#include "../prots.h"
#include "../global-var.h"

#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>

#include <deque>
#include <map>
#include <string>
#include <vector>

#define FASTLOGIN_CFG_FILE "fast-login.txt"
#define FASTLOGIN_MODULE "fast-login"

struct QRcode
{
	int version;
	int width;
	unsigned char *data;
};

typedef QRcode *(*QRcodeEncodeString8bit)(const char *, int, int);
typedef void (*QRcodeFree)(QRcode *);

struct QrApi
{
	void *lib;
	QRcodeEncodeString8bit encode;
	QRcodeFree free_code;
};

struct FastLoginConfig
{
	bool enabled;
	std::string issuer;
	std::string notification_type;
	int digits;
	int period;
	int setup_ttl;
	int setup_cooldown;
	int max_attempts;
	int lockout_time;
	int qr_line_delay;
	std::string qr_output;

	FastLoginConfig() :
		enabled(false),
		issuer("Evangeline FastLogin"),
		notification_type("text"),
		digits(6),
		period(30),
		setup_ttl(300),
		setup_cooldown(60),
		max_attempts(3),
		lockout_time(300),
		qr_line_delay(2),
		qr_output("compact")
	{
	}
};

struct FastLoginUser
{
	bool allowed;
	bool enabled;
	std::string secret;

	FastLoginUser() : allowed(false), enabled(false) { }
};

struct SetupSession
{
	std::string handle;
	std::string hostmask;
	std::string nick;
	std::string secret;
	time_t expires_at;
	unsigned int attempts;
};

struct OutMsg
{
	std::string nick;
	std::string text;
	bool notice;
};

static module *module_info = NULL;
static FastLoginConfig cfg;
static QrApi qrapi;
static std::map<std::string, FastLoginUser> users;
static std::map<std::string, SetupSession> setup_sessions;
static std::map<std::string, time_t> setup_request_times;
static std::map<std::string, time_t> setup_lockouts;
static std::map<std::string, time_t> ip_lockouts;
static std::map<std::string, unsigned int> ip_failures;
static std::map<std::string, std::string> peer_errors;
static std::map<std::string, unsigned long long> last_totp_counters;
static std::deque<OutMsg> outbox;
static time_t last_outbox_send = 0;
static const size_t MAX_OUTBOX_MESSAGES = 120;
static const size_t TOTP_SECRET_BYTES = 20;
static const size_t MIN_TOTP_SECRET_BYTES = 16;

static void fastlogin_save();
static void fastlogin_load();

static std::string nick_from_mask(const char *mask)
{
	const char *bang = strchr(mask, '!');
	if(!bang)
		return std::string(mask);
	return std::string(mask, bang - mask);
}

static std::string canonical_host_from_mask(const char *mask)
{
	const char *bang = strchr(mask, '!');
	if(!bang)
		return std::string(mask);
	return std::string(bang + 1);
}

static bool parse_bool_value(const char *value, bool &out)
{
	if(!strcasecmp(value, "on") || !strcasecmp(value, "yes") || !strcasecmp(value, "true") || !strcmp(value, "1"))
	{
		out = true;
		return true;
	}
	if(!strcasecmp(value, "off") || !strcasecmp(value, "no") || !strcasecmp(value, "false") || !strcmp(value, "0"))
	{
		out = false;
		return true;
	}
	return false;
}

static bool valid_partyline_handle(HANDLE *h)
{
	return h && !userlist.isBot(h) && (h->flags[GLOBAL] & HAS_P);
}

static void irc_reply(const std::string &nick, const char *message)
{
	if(cfg.notification_type == "notice")
		ME.notice(nick.c_str(), message, NULL);
	else
		ME.privmsg(nick.c_str(), message, NULL);
}

static void queue_reply(const std::string &nick, const std::string &message)
{
	OutMsg msg;
	msg.nick = nick;
	msg.text = message;
	msg.notice = cfg.notification_type == "notice";
	if(outbox.size() >= MAX_OUTBOX_MESSAGES)
		outbox.pop_front();
	outbox.push_back(msg);
}

static void remove_queued_replies(const std::string &nick)
{
	for(std::deque<OutMsg>::iterator it = outbox.begin(); it != outbox.end(); )
	{
		if(it->nick == nick)
			it = outbox.erase(it++);
		else
			++it;
	}
}

static void clear_runtime_for_handle(const std::string &handle)
{
	std::string prefix = handle + "|";
	setup_sessions.erase(handle);
	setup_request_times.erase(handle);
	for(std::map<std::string, time_t>::iterator it = setup_lockouts.begin(); it != setup_lockouts.end(); )
	{
		if(!strncmp(it->first.c_str(), prefix.c_str(), prefix.size()))
			setup_lockouts.erase(it++);
		else
			++it;
	}
	for(std::map<std::string, unsigned long long>::iterator cit = last_totp_counters.begin(); cit != last_totp_counters.end(); )
	{
		if(!strncmp(cit->first.c_str(), prefix.c_str(), prefix.size()))
			last_totp_counters.erase(cit++);
		else
			++cit;
	}
}

static void flush_outbox()
{
	if(outbox.empty())
		return;
	if(last_outbox_send && last_outbox_send + cfg.qr_line_delay > NOW)
		return;

	OutMsg msg = outbox.front();
	outbox.pop_front();
	if(msg.notice)
		ME.notice(msg.nick.c_str(), msg.text.c_str(), NULL);
	else
		ME.privmsg(msg.nick.c_str(), msg.text.c_str(), NULL);
	last_outbox_send = NOW;
}

static bool secure_random_bytes(unsigned char *buf, size_t len)
{
	size_t off = 0;
#ifdef SYS_getrandom
	while(off < len)
	{
		ssize_t n = syscall(SYS_getrandom, buf + off, len - off, 0);
		if(n < 0)
		{
			if(errno == EINTR)
				continue;
			break;
		}
		if(n == 0)
			break;
		off += (size_t)n;
	}
	if(off == len)
		return true;
#endif

	int fd = open("/dev/urandom", O_RDONLY);
	if(fd < 0)
		return false;
	off = 0;
	while(off < len)
	{
		ssize_t n = read(fd, buf + off, len - off);
		if(n < 0)
		{
			if(errno == EINTR)
				continue;
			close(fd);
			return false;
		}
		if(n == 0)
		{
			close(fd);
			return false;
		}
		off += (size_t)n;
	}
	close(fd);
	return true;
}

static std::string base32_encode(const unsigned char *data, size_t len)
{
	static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
	std::string out;
	unsigned int buffer = 0;
	int bits = 0;
	for(size_t i = 0; i < len; ++i)
	{
		buffer = (buffer << 8) | data[i];
		bits += 8;
		while(bits >= 5)
		{
			out += alphabet[(buffer >> (bits - 5)) & 31];
			bits -= 5;
		}
	}
	if(bits)
		out += alphabet[(buffer << (5 - bits)) & 31];
	return out;
}

static int base32_value(char c)
{
	if(c >= 'A' && c <= 'Z') return c - 'A';
	if(c >= 'a' && c <= 'z') return c - 'a';
	if(c >= '2' && c <= '7') return c - '2' + 26;
	return -1;
}

static bool base32_decode(const std::string &text, std::vector<unsigned char> &out)
{
	unsigned int buffer = 0;
	int bits = 0;
	out.clear();
	for(size_t i = 0; i < text.size(); ++i)
	{
		if(text[i] == '=' || text[i] == ' ' || text[i] == '-')
			continue;
		int v = base32_value(text[i]);
		if(v < 0)
			return false;
		buffer = (buffer << 5) | (unsigned int)v;
		bits += 5;
		if(bits >= 8)
		{
			out.push_back((unsigned char)((buffer >> (bits - 8)) & 0xff));
			bits -= 8;
		}
	}
	return !out.empty();
}

static bool generate_secret(std::string &secret)
{
	unsigned char raw[TOTP_SECRET_BYTES];
	if(!secure_random_bytes(raw, sizeof(raw)))
		return false;
	secret = base32_encode(raw, sizeof(raw));
	return true;
}

static std::string url_encode(const std::string &in)
{
	static const char hex[] = "0123456789ABCDEF";
	std::string out;
	for(size_t i = 0; i < in.size(); ++i)
	{
		unsigned char c = (unsigned char)in[i];
		if((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~')
			out += c;
		else
		{
			out += '%';
			out += hex[c >> 4];
			out += hex[c & 15];
		}
	}
	return out;
}

static std::string otpauth_uri(const std::string &handle, const std::string &secret)
{
	std::string label = cfg.issuer + ":" + handle;
	char digits[16], period[16];
	snprintf(digits, sizeof(digits), "%d", cfg.digits);
	snprintf(period, sizeof(period), "%d", cfg.period);
	std::string uri = "otpauth://totp/" + url_encode(label) + "?secret=" + secret;
	if(cfg.digits != 6)
		uri += std::string("&digits=") + digits;
	if(cfg.period != 30)
		uri += std::string("&period=") + period;
	return uri;
}

static bool parse_code(const char *text, std::string &code)
{
	if((int)strlen(text) != cfg.digits)
		return false;
	for(size_t i = 0; text[i]; ++i)
		if(!isdigit((unsigned char)text[i]))
			return false;
	code = text;
	return true;
}

static bool totp_for_counter(const std::vector<unsigned char> &secret, unsigned long long counter, std::string &out)
{
	unsigned char msg[8];
	for(int i = 7; i >= 0; --i)
	{
		msg[i] = counter & 0xff;
		counter >>= 8;
	}

	unsigned int len = 0;
	unsigned char digest[EVP_MAX_MD_SIZE];
	if(!HMAC(EVP_sha1(), &secret[0], secret.size(), msg, sizeof(msg), digest, &len) || len < 20)
		return false;

	int offset = digest[19] & 0x0f;
	unsigned int binary = ((digest[offset] & 0x7f) << 24) |
		((digest[offset + 1] & 0xff) << 16) |
		((digest[offset + 2] & 0xff) << 8) |
		(digest[offset + 3] & 0xff);
	unsigned int mod = 1;
	for(int i = 0; i < cfg.digits; ++i)
		mod *= 10;

	char fmt[16], buf[32];
	snprintf(fmt, sizeof(fmt), "%%0%du", cfg.digits);
	snprintf(buf, sizeof(buf), fmt, binary % mod);
	out = buf;
	return true;
}

static bool verify_totp(const std::string &secret_text, const std::string &code, unsigned long long *matched_counter = NULL)
{
	std::vector<unsigned char> secret;
	if(!base32_decode(secret_text, secret))
		return false;
	unsigned long long counter = (unsigned long long)(NOW / cfg.period);
	for(int skew = -1; skew <= 1; ++skew)
	{
		if(skew < 0 && counter == 0)
			continue;
		std::string expected;
		if(totp_for_counter(secret, counter + skew, expected) && expected == code)
		{
			if(matched_counter)
				*matched_counter = counter + skew;
			return true;
		}
	}
	return false;
}

static bool load_qr_api()
{
	if(qrapi.lib)
		return true;
	qrapi.lib = dlopen("libqrencode.so.4", RTLD_NOW);
	if(!qrapi.lib)
		qrapi.lib = dlopen("libqrencode.so", RTLD_NOW);
	if(!qrapi.lib)
		return false;

	qrapi.encode = (QRcodeEncodeString8bit)dlsym(qrapi.lib, "QRcode_encodeString8bit");
	qrapi.free_code = (QRcodeFree)dlsym(qrapi.lib, "QRcode_free");
	if(!qrapi.encode || !qrapi.free_code)
	{
		dlclose(qrapi.lib);
		memset(&qrapi, 0, sizeof(qrapi));
		return false;
	}
	return true;
}

static void send_qr_text(const std::string &nick, const std::string &uri)
{
	if(cfg.qr_output == "manual")
	{
		queue_reply(nick, "QR text output is disabled; use the manual key or otpauth URI");
		return;
	}
	if(!load_qr_api())
	{
		queue_reply(nick, "QR library is not available; use the manual key or otpauth URI");
		return;
	}

	QRcode *qr = qrapi.encode(uri.c_str(), 0, 0);
	if(!qr)
	{
		queue_reply(nick, "QR generation failed; use the manual key or otpauth URI");
		return;
	}

	const int border = cfg.qr_output == "compact" ? 1 : 2;
	for(int y = -border; y < qr->width + border; y += 2)
	{
		std::string line = "\00301,00";
		for(int x = -border; x < qr->width + border; ++x)
		{
			bool top = false, bottom = false;
			if(x >= 0 && y >= 0 && x < qr->width && y < qr->width)
				top = (qr->data[y * qr->width + x] & 1) != 0;
			if(x >= 0 && y + 1 >= 0 && x < qr->width && y + 1 < qr->width)
				bottom = (qr->data[(y + 1) * qr->width + x] & 1) != 0;

			if(top && bottom)
				line += "\342\226\210";
			else if(top)
				line += "\342\226\200";
			else if(bottom)
				line += "\342\226\204";
			else
				line += " ";
		}
		line += "\017";
		queue_reply(nick, line);
	}
	qrapi.free_code(qr);
}

static bool user_available(const char *from, HANDLE **hout, std::string &handle, std::string &nick)
{
	nick = nick_from_mask(from);
	HANDLE *h = userlist.findHandleByHost(from);
	if(!valid_partyline_handle(h))
		return false;
	handle = h->name;
	*hout = h;
	return true;
}

static void handle_setup_request(const char *from)
{
	std::string handle, nick;
	HANDLE *h = NULL;
	if(!cfg.enabled)
	{
		irc_reply(nick_from_mask(from), "FastLogin setup unavailable: module is disabled. Ask an owner to run .fastlogin enable");
		return;
	}
	if(!user_available(from, &h, handle, nick))
	{
		irc_reply(nick_from_mask(from), "FastLogin setup unavailable: your IRC hostmask does not match a partyline handle with +p");
		return;
	}

	FastLoginUser &u = users[handle];
	if(!u.allowed)
	{
		irc_reply(nick, "FastLogin setup unavailable: your handle is not enabled. Ask an owner to run .fastlogin <handle> enable");
		return;
	}
	if(!u.secret.empty())
	{
		irc_reply(nick, "FastLogin is already configured for your account");
		irc_reply(nick, "Ask an owner to remove the existing secret if you need to set it up again");
		return;
	}

	std::map<std::string, SetupSession>::iterator existing = setup_sessions.find(handle);
	if(existing != setup_sessions.end() && existing->second.expires_at > NOW)
	{
		irc_reply(nick, "FastLogin setup is already in progress");
		return;
	}
	if(setup_request_times.find(handle) != setup_request_times.end() && setup_request_times[handle] + cfg.setup_cooldown > NOW)
	{
		irc_reply(nick, "Please wait before requesting another FastLogin setup");
		return;
	}

	std::string lkey = handle + "|" + canonical_host_from_mask(from);
	if(setup_lockouts.find(lkey) != setup_lockouts.end() && setup_lockouts[lkey] > NOW)
	{
		irc_reply(nick, "FastLogin setup is temporarily locked");
		return;
	}

	SetupSession session;
	session.handle = handle;
	session.hostmask = from;
	session.nick = nick;
	session.expires_at = NOW + cfg.setup_ttl;
	session.attempts = 0;
	if(!generate_secret(session.secret))
	{
		irc_reply(nick, "Unable to create FastLogin setup. Please try again later");
		net.send(HAS_N, "[fast-login] secure random generation failed", NULL);
		return;
	}

	setup_sessions[handle] = session;
	setup_request_times[handle] = NOW;
	remove_queued_replies(nick);
	std::string uri = otpauth_uri(handle, session.secret);
	irc_reply(nick, "Scan this QR code with your authenticator app, or enter the manual key");
	queue_reply(nick, "Manual key: " + session.secret);
	queue_reply(nick, "URI: " + uri);
	send_qr_text(nick, uri);
	queue_reply(nick, "Reply here with the current 6-digit code to finish setup");
	net.send(HAS_N, "[fast-login] setup started for ", handle.c_str(), " (", nick.c_str(), ")", NULL);
}

static void handle_setup_submit(const char *from, const char *msg)
{
	std::string handle, nick;
	HANDLE *h = NULL;
	if(!user_available(from, &h, handle, nick))
		return;

	std::map<std::string, SetupSession>::iterator sit = setup_sessions.find(handle);
	if(sit == setup_sessions.end())
		return;

	SetupSession &session = sit->second;
	std::string lkey = handle + "|" + canonical_host_from_mask(session.hostmask.c_str());
	if(session.expires_at <= NOW || session.hostmask != from || session.nick != nick)
	{
		setup_sessions.erase(sit);
		irc_reply(nick, "FastLogin setup expired. Request a new setup with owner-setup");
		return;
	}

	std::string code;
	if(!parse_code(msg, code) || !verify_totp(session.secret, code))
	{
		session.attempts++;
		if((int)session.attempts >= cfg.max_attempts)
		{
			setup_lockouts[lkey] = NOW + cfg.lockout_time;
			setup_sessions.erase(sit);
			irc_reply(nick, "Too many failed attempts. FastLogin setup is locked for 5 minutes");
			net.send(HAS_N, "[fast-login] setup locked for ", handle.c_str(), NULL);
		}
		else
		{
			char buf[128];
			snprintf(buf, sizeof(buf), "Invalid verification code. %d attempts remaining", cfg.max_attempts - (int)session.attempts);
			irc_reply(nick, buf);
		}
		return;
	}

	FastLoginUser &u = users[handle];
	u.secret = session.secret;
	u.allowed = true;
	u.enabled = true;
	setup_sessions.erase(sit);
	fastlogin_save();
	irc_reply(nick, "FastLogin setup verified and enabled");
	irc_reply(nick, "To use telnet fast login, enter: <handle> <6-digit code>");
	net.send(HAS_N, "[fast-login] setup verified for ", handle.c_str(), NULL);
}

static void record_fastlogin_failure(const std::string &peer, const char *handle)
{
	if(peer.empty())
		return;
	if(ip_lockouts.find(peer) != ip_lockouts.end() && ip_lockouts[peer] > NOW)
		return;

	unsigned int n = ++ip_failures[peer];
	net.send(HAS_N, "[fast-login] failed login from ", peer.c_str(), handle && *handle ? " for " : "", handle && *handle ? handle : "", NULL);
	if((int)n >= cfg.max_attempts)
	{
		ip_failures.erase(peer);
		ip_lockouts[peer] = NOW + cfg.lockout_time;
		net.send(HAS_N, "[fast-login] IP locked for 5 minutes: ", peer.c_str(), NULL);
	}
}

static void set_peer_error(const std::string &peer, const std::string &error)
{
	if(!peer.empty())
		peer_errors[peer] = error;
}

extern "C" HANDLE *fastLogin(const char *handle, const char *code, const char *peer)
{
	std::string peer_key = peer ? peer : "";
	if(!cfg.enabled || !handle || !*handle || !code)
	{
		set_peer_error(peer_key, "FastLogin failed: module is disabled or request is incomplete");
		return NULL;
	}
	if(ip_lockouts.find(peer_key) != ip_lockouts.end() && ip_lockouts[peer_key] > NOW)
	{
		set_peer_error(peer_key, "FastLogin failed: this IP is temporarily locked");
		return NULL;
	}

	std::string parsed_code;
	if(!parse_code(code, parsed_code))
	{
		set_peer_error(peer_key, "FastLogin failed: code must be exactly 6 digits");
		record_fastlogin_failure(peer_key, handle);
		return NULL;
	}

	HANDLE *h = userlist.findHandle(handle);
	if(!valid_partyline_handle(h))
	{
		set_peer_error(peer_key, "FastLogin failed: invalid handle or missing partyline +p flag");
		record_fastlogin_failure(peer_key, handle);
		return NULL;
	}

	std::map<std::string, FastLoginUser>::iterator uit = users.find(h->name);
	if(uit == users.end() || !uit->second.allowed || !uit->second.enabled || uit->second.secret.empty())
	{
		set_peer_error(peer_key, "FastLogin failed: handle is not enabled or setup is incomplete");
		record_fastlogin_failure(peer_key, h->name);
		return NULL;
	}

	unsigned long long matched_counter = 0;
	if(!verify_totp(uit->second.secret, parsed_code, &matched_counter))
	{
		set_peer_error(peer_key, "FastLogin failed: invalid or expired authenticator code");
		record_fastlogin_failure(peer_key, h->name);
		return NULL;
	}

	std::string counter_key = std::string(h->name) + "|" + peer_key;
	if(last_totp_counters.find(counter_key) != last_totp_counters.end() && matched_counter <= last_totp_counters[counter_key])
	{
		set_peer_error(peer_key, "FastLogin failed: authenticator code was already used");
		record_fastlogin_failure(peer_key, h->name);
		net.send(HAS_N, "[fast-login] OTP replay rejected for ", h->name, " from ", peer_key.c_str(), NULL);
		return NULL;
	}

	peer_errors.erase(peer_key);
	ip_failures.erase(peer_key);
	last_totp_counters[counter_key] = matched_counter;
	net.send(HAS_N, "[fast-login] login accepted for ", h->name, " from ", peer_key.c_str(), NULL);
	return h;
}

extern "C" const char *fastLoginError(const char *peer)
{
	std::string peer_key = peer ? peer : "";
	std::map<std::string, std::string>::iterator it = peer_errors.find(peer_key);
	if(it == peer_errors.end())
		return "FastLogin failed: module not loaded or no detailed error is available";
	return it->second.c_str();
}

void hook_privmsg(const char *from, const char *to, const char *msg)
{
	if(strcmp(to, ME.nick))
		return;

	if(!strcmp(msg, "owner-setup"))
	{
		handle_setup_request(from);
		stopParsing = true;
		return;
	}

	HANDLE *h = userlist.findHandleByHost(from);
	if(h && setup_sessions.find(h->name) != setup_sessions.end())
	{
		handle_setup_submit(from, msg);
		stopParsing = true;
	}
}

static void status_to_owner(const char *from)
{
	net.sendOwner(from, "FastLogin Status:", NULL);
	net.sendOwner(from, "Module Enabled: ", cfg.enabled ? "ON" : "OFF", NULL);
	net.sendOwner(from, "Issuer: ", cfg.issuer.c_str(), NULL);
	net.sendOwner(from, "Digits: ", itoa(cfg.digits), NULL);
	net.sendOwner(from, "Period: ", itoa(cfg.period), NULL);
	net.sendOwner(from, "Max Attempts: ", itoa(cfg.max_attempts), NULL);
	net.sendOwner(from, "IP Lockout Time: ", itoa(cfg.lockout_time), NULL);
	net.sendOwner(from, "QR Library: ", load_qr_api() ? "AVAILABLE" : "MISSING", NULL);
}

static void help_to_owner(const char *from)
{
	net.sendOwner(from, ".fastlogin status|enable|disable|help", NULL);
	net.sendOwner(from, ".fastlogin <handle> show|enable|disable|remove-secret|unlock", NULL);
}

static void user_show(const char *from, const char *handle)
{
	HANDLE *h = userlist.findHandle(handle);
	if(!valid_partyline_handle(h))
	{
		net.sendOwner(from, "Invalid partyline handle", NULL);
		return;
	}
	FastLoginUser &u = users[h->name];
	net.sendOwner(from, "FastLogin User: ", h->name, NULL);
	net.sendOwner(from, "Allowed: ", u.allowed ? "YES" : "NO", NULL);
	net.sendOwner(from, "Status: ", u.enabled ? "ENABLED" : "DISABLED", NULL);
	net.sendOwner(from, "Secret: ", u.secret.empty() ? "(not set)" : "********", NULL);
}

static void user_enable(const char *from, const char *handle)
{
	HANDLE *h = userlist.findHandle(handle);
	if(!valid_partyline_handle(h))
	{
		net.sendOwner(from, "Invalid partyline handle", NULL);
		return;
	}
	FastLoginUser &u = users[h->name];
	u.allowed = true;
	if(!u.secret.empty())
		u.enabled = true;
	fastlogin_save();
	net.sendOwner(from, u.secret.empty() ? "FastLogin setup allowed for " : "FastLogin enabled for ", h->name, NULL);
}

static void user_disable(const char *from, const char *handle)
{
	HANDLE *h = userlist.findHandle(handle);
	if(!valid_partyline_handle(h))
	{
		net.sendOwner(from, "Invalid partyline handle", NULL);
		return;
	}
	FastLoginUser &u = users[h->name];
	u.enabled = false;
	clear_runtime_for_handle(h->name);
	fastlogin_save();
	net.sendOwner(from, "FastLogin disabled for ", h->name, "; secret kept", NULL);
}

static void user_remove_secret(const char *from, const char *handle)
{
	HANDLE *h = userlist.findHandle(handle);
	if(!valid_partyline_handle(h))
	{
		net.sendOwner(from, "Invalid partyline handle", NULL);
		return;
	}
	FastLoginUser &u = users[h->name];
	u.secret.clear();
	u.enabled = false;
	clear_runtime_for_handle(h->name);
	fastlogin_save();
	net.sendOwner(from, "FastLogin secret removed for ", h->name, NULL);
}

void hook_partylineCmd(const char *from, int flags, const char *cmd, const char *args)
{
	if(strcmp(cmd, ".fastlogin"))
		return;
	stopParsing = true;

	if(!(flags & HAS_N) || !(flags & (HAS_S | HAS_X)))
	{
		net.sendOwner(from, "No permission", NULL);
		return;
	}

	char arg[5][MAX_LEN];
	str2words(arg[0], args ? args : "", 5, MAX_LEN, 0);

	if(!strlen(arg[0]) || !strcmp(arg[0], "help"))
	{
		help_to_owner(from);
		return;
	}
	if(!strcmp(arg[0], "status"))
	{
		status_to_owner(from);
		return;
	}
	if(!strcmp(arg[0], "enable"))
	{
		cfg.enabled = true;
		fastlogin_save();
		net.sendOwner(from, "FastLogin module enabled", NULL);
		return;
	}
	if(!strcmp(arg[0], "disable"))
	{
		cfg.enabled = false;
		setup_sessions.clear();
		setup_request_times.clear();
		setup_lockouts.clear();
		ip_failures.clear();
		ip_lockouts.clear();
		last_totp_counters.clear();
		outbox.clear();
		fastlogin_save();
		net.sendOwner(from, "FastLogin module disabled", NULL);
		return;
	}

	if(strlen(arg[1]))
	{
		if(!strcmp(arg[1], "show"))
			user_show(from, arg[0]);
		else if(!strcmp(arg[1], "enable"))
			user_enable(from, arg[0]);
		else if(!strcmp(arg[1], "disable"))
			user_disable(from, arg[0]);
		else if(!strcmp(arg[1], "remove-secret"))
			user_remove_secret(from, arg[0]);
		else if(!strcmp(arg[1], "unlock"))
		{
			clear_runtime_for_handle(arg[0]);
			net.sendOwner(from, "FastLogin runtime state cleared for ", arg[0], NULL);
		}
		else
			net.sendOwner(from, "Unknown FastLogin user command", NULL);
		return;
	}

	net.sendOwner(from, "Unknown FastLogin command", NULL);
}

static bool set_config_value(const char *key, const char *value)
{
	int n = atoi(value);
	if(!strcmp(key, "issuer"))
		cfg.issuer = value;
	else if(!strcmp(key, "notification-type"))
	{
		if(strcmp(value, "text") && strcmp(value, "notice"))
			return false;
		cfg.notification_type = value;
	}
	else if(!strcmp(key, "digits"))
	{
		if(n != 6)
			return false;
		cfg.digits = n;
	}
	else if(!strcmp(key, "period"))
	{
		if(n < 15 || n > 300)
			return false;
		cfg.period = n;
	}
	else if(!strcmp(key, "setup-ttl"))
	{
		if(n < 30 || n > 3600)
			return false;
		cfg.setup_ttl = n;
	}
	else if(!strcmp(key, "setup-cooldown"))
	{
		if(n < 10 || n > 3600)
			return false;
		cfg.setup_cooldown = n;
	}
	else if(!strcmp(key, "max-attempts"))
	{
		if(n < 1 || n > 10)
			return false;
		cfg.max_attempts = n;
	}
	else if(!strcmp(key, "lockout-time"))
	{
		if(n < 60 || n > 3600)
			return false;
		cfg.lockout_time = n;
	}
	else if(!strcmp(key, "qr-line-delay"))
	{
		if(n < 1 || n > 10)
			return false;
		cfg.qr_line_delay = n;
	}
	else if(!strcmp(key, "qr-output"))
	{
		if(strcmp(value, "manual") && strcmp(value, "compact"))
			return false;
		cfg.qr_output = value;
	}
	else
		return false;
	return true;
}

static void fastlogin_load()
{
	FILE *fh = fopen(FASTLOGIN_CFG_FILE, "r");
	if(!fh)
		return;

	char buffer[MAX_LEN];
	char arg[8][MAX_LEN];
	while(fgets(buffer, sizeof(buffer), fh))
	{
		buffer[strcspn(buffer, "\r\n")] = '\0';
		str2words(arg[0], buffer, 8, MAX_LEN, 0);
		if(!strlen(arg[0]) || arg[0][0] == '#')
			continue;
		if(!strcmp(arg[0], "set"))
		{
			char *value = srewind(buffer, 2);
			if(!strcmp(arg[1], "module-enabled"))
			{
				bool b;
				if(parse_bool_value(value ? value : "", b))
					cfg.enabled = b;
			}
			else if(value)
				set_config_value(arg[1], value);
		}
		else if(!strcmp(arg[0], "user") && strlen(arg[1]) && strlen(arg[2]))
		{
			FastLoginUser &u = users[arg[1]];
			char *value = srewind(buffer, 3);
			if(!strcmp(arg[2], "allowed") && value)
			{
				bool b;
				if(parse_bool_value(value, b))
					u.allowed = b;
			}
			else if(!strcmp(arg[2], "enabled") && value)
			{
				bool b;
				if(parse_bool_value(value, b))
					u.enabled = b;
			}
			else if(!strcmp(arg[2], "secret") && value)
			{
				std::vector<unsigned char> decoded;
				if(base32_decode(value, decoded) && decoded.size() >= MIN_TOTP_SECRET_BYTES)
					u.secret = value;
			}
		}
	}
	fclose(fh);
}

static void fastlogin_save()
{
	FILE *fh = fopen(FASTLOGIN_CFG_FILE, "w");
	if(!fh)
	{
		net.send(HAS_N, "[fast-login] cannot open ", FASTLOGIN_CFG_FILE, " for writing: ", strerror(errno), NULL);
		return;
	}
	chmod(FASTLOGIN_CFG_FILE, S_IRUSR | S_IWUSR);

	fprintf(fh, "set module-enabled %s\n", cfg.enabled ? "ON" : "OFF");
	fprintf(fh, "set issuer %s\n", cfg.issuer.c_str());
	fprintf(fh, "set notification-type %s\n", cfg.notification_type.c_str());
	fprintf(fh, "set digits %d\n", cfg.digits);
	fprintf(fh, "set period %d\n", cfg.period);
	fprintf(fh, "set setup-ttl %d\n", cfg.setup_ttl);
	fprintf(fh, "set setup-cooldown %d\n", cfg.setup_cooldown);
	fprintf(fh, "set max-attempts %d\n", cfg.max_attempts);
	fprintf(fh, "set lockout-time %d\n", cfg.lockout_time);
	fprintf(fh, "set qr-line-delay %d\n", cfg.qr_line_delay);
	fprintf(fh, "set qr-output %s\n", cfg.qr_output.c_str());

	for(std::map<std::string, FastLoginUser>::iterator it = users.begin(); it != users.end(); ++it)
	{
		fprintf(fh, "user %s allowed %s\n", it->first.c_str(), it->second.allowed ? "ON" : "OFF");
		fprintf(fh, "user %s enabled %s\n", it->first.c_str(), it->second.enabled ? "ON" : "OFF");
		if(!it->second.secret.empty())
			fprintf(fh, "user %s secret %s\n", it->first.c_str(), it->second.secret.c_str());
	}
	fclose(fh);
}

static void expire_runtime()
{
	for(std::map<std::string, SetupSession>::iterator it = setup_sessions.begin(); it != setup_sessions.end(); )
	{
		if(it->second.expires_at <= NOW)
			setup_sessions.erase(it++);
		else
			++it;
	}
	for(std::map<std::string, time_t>::iterator it = setup_lockouts.begin(); it != setup_lockouts.end(); )
	{
		if(it->second <= NOW)
			setup_lockouts.erase(it++);
		else
			++it;
	}
	for(std::map<std::string, time_t>::iterator it = ip_lockouts.begin(); it != ip_lockouts.end(); )
	{
		if(it->second <= NOW)
			ip_lockouts.erase(it++);
		else
			++it;
	}
	for(std::map<std::string, time_t>::iterator it = setup_request_times.begin(); it != setup_request_times.end(); )
	{
		if(it->second + cfg.setup_cooldown <= NOW)
			setup_request_times.erase(it++);
		else
			++it;
	}
}

void hook_timer()
{
	expire_runtime();
	flush_outbox();
}

void hook_userlistLoaded()
{
	users.clear();
	fastlogin_load();
}

extern "C" module *init()
{
	module_info = new module(FASTLOGIN_MODULE, "OpenAI Codex", "0.1");
	module_info->hooks->privmsg = hook_privmsg;
	module_info->hooks->partylineCmd = hook_partylineCmd;
	module_info->hooks->timer = hook_timer;
	module_info->hooks->userlistLoaded = hook_userlistLoaded;
	if(userlist.SN)
		hook_userlistLoaded();
	return module_info;
}

extern "C" void destroy()
{
	if(qrapi.lib)
	{
		dlclose(qrapi.lib);
		memset(&qrapi, 0, sizeof(qrapi));
	}
}
