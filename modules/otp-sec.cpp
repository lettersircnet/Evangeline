#include "../prots.h"
#include "../global-var.h"

#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>

#include <algorithm>
#include <deque>
#include <map>
#include <queue>
#include <string>
#include <vector>

/*
 * otp-sec bundles the two operator second-factor flows in one loadable module:
 *
 *   - email OTP: one-time code delivered through SMTP
 *   - authenticator OTP: TOTP setup and qr-op codes
 *
 * Both flows replace only the password-verification step. On success they call
 * grantOpForAuthenticatedUser(), so Evangeline keeps using the historical OP
 * authorization and MODE queue path.
 */

namespace email_otp {

#define EMAIL_OTP_CFG_FILE "email-otp.txt"
#define EMAIL_OTP_MODULE "email-otp"

struct EmailOtpConfig
{
	bool enabled;
	std::string smtp_host;
	int smtp_port;
	std::string smtp_security;
	std::string smtp_user;
	std::string smtp_password;
	std::string smtp_from;
	std::string smtp_from_name;
	bool verify_tls;
	int otp_length;
	int otp_ttl;
	int max_attempts;
	int lockout_time;
	int resend_cooldown;
	int hourly_limit;
	std::string notification_type;

	EmailOtpConfig() :
		enabled(false),
		smtp_port(587),
		smtp_security("starttls"),
		verify_tls(true),
		otp_length(6),
		otp_ttl(300),
		max_attempts(3),
		lockout_time(18000),
		resend_cooldown(60),
		hourly_limit(5),
		notification_type("text")
	{
	}
};

struct EmailOtpUser
{
	std::string email;
	bool enabled;

	EmailOtpUser() : enabled(false) { }
};

struct OtpSession
{
	std::string handle;
	std::string hostmask;
	std::string nick;
	unsigned char nonce[16];
	unsigned char hash[SHA256_DIGEST_LENGTH];
	time_t created_at;
	time_t expires_at;
	unsigned int attempts;
};

struct PendingRequest
{
	std::string handle;
	std::string hostmask;
	std::string nick;
	unsigned char nonce[16];
	unsigned char hash[SHA256_DIGEST_LENGTH];
	time_t created_at;
	time_t expires_at;
};

struct SmtpJob
{
	std::string handle;
	std::string nick;
	time_t created_at;
	std::string to;
	std::string otp;
	std::string url;
	std::string user;
	std::string password;
	std::string from;
	std::string from_name;
	std::string botnick;
	std::string security;
	bool verify_tls;
	int timeout;
};

struct SmtpResult
{
	std::string handle;
	time_t created_at;
	bool ok;
	std::string error;
};

struct UploadPayload
{
	const char *data;
	size_t pos;
	size_t len;
};

typedef void CURL;
typedef int CURLcode;
struct curl_slist
{
	char *data;
	curl_slist *next;
};

#define CURLE_OK 0
#define CURL_GLOBAL_DEFAULT 3
#define CURLUSESSL_ALL 3
#define CURLOPTTYPE_LONG 0
#define CURLOPTTYPE_OBJECTPOINT 10000
#define CURLOPTTYPE_FUNCTIONPOINT 20000
#define CURLOPTTYPE_OFF_T 30000
#define CURLOPT_URL (CURLOPTTYPE_OBJECTPOINT + 2)
#define CURLOPT_READFUNCTION (CURLOPTTYPE_FUNCTIONPOINT + 12)
#define CURLOPT_READDATA (CURLOPTTYPE_OBJECTPOINT + 9)
#define CURLOPT_UPLOAD (CURLOPTTYPE_LONG + 46)
#define CURLOPT_TIMEOUT (CURLOPTTYPE_LONG + 13)
#define CURLOPT_CONNECTTIMEOUT (CURLOPTTYPE_LONG + 78)
#define CURLOPT_SSL_VERIFYPEER (CURLOPTTYPE_LONG + 64)
#define CURLOPT_SSL_VERIFYHOST (CURLOPTTYPE_LONG + 81)
#define CURLOPT_USE_SSL (CURLOPTTYPE_LONG + 119)
#define CURLOPT_USERNAME (CURLOPTTYPE_OBJECTPOINT + 173)
#define CURLOPT_PASSWORD (CURLOPTTYPE_OBJECTPOINT + 174)
#define CURLOPT_MAIL_FROM (CURLOPTTYPE_OBJECTPOINT + 186)
#define CURLOPT_MAIL_RCPT (CURLOPTTYPE_OBJECTPOINT + 187)
#define CURLINFO_LONG 0x200000
#define CURLINFO_RESPONSE_CODE (CURLINFO_LONG + 2)

struct CurlApi
{
	void *lib;
	CURLcode (*global_init)(long);
	void (*global_cleanup)();
	CURL *(*easy_init)();
	CURLcode (*easy_setopt)(CURL *, int, ...);
	CURLcode (*easy_perform)(CURL *);
	CURLcode (*easy_getinfo)(CURL *, int, ...);
	void (*easy_cleanup)(CURL *);
	const char *(*easy_strerror)(CURLcode);
	curl_slist *(*slist_append)(curl_slist *, const char *);
	void (*slist_free_all)(curl_slist *);
};

static CurlApi curlapi;

static module *module_info = NULL;
static EmailOtpConfig cfg;
static std::map<std::string, EmailOtpUser> users;
static std::map<std::string, OtpSession> sessions;
static std::map<std::string, PendingRequest> pending;
static std::map<std::string, time_t> lockouts;
static std::map<std::string, std::deque<time_t> > request_times;

static pthread_t smtp_thread;
static pthread_mutex_t smtp_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t smtp_cond = PTHREAD_COND_INITIALIZER;
static bool smtp_started = false;
static bool smtp_shutdown = false;
static std::deque<SmtpJob> smtp_jobs;
static std::deque<SmtpResult> smtp_results;

static void emailotp_save();
static void emailotp_load();

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

static std::string lock_key(const std::string &handle, const char *hostmask)
{
	return handle + "|" + canonical_host_from_mask(hostmask);
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

static bool valid_email(const std::string &email)
{
	if(email.empty() || email.size() > 254)
		return false;
	if(email.find('\r') != std::string::npos || email.find('\n') != std::string::npos)
		return false;
	if(email.find(' ') != std::string::npos || email.find('\t') != std::string::npos)
		return false;
	size_t at = email.find('@');
	if(at == std::string::npos || at == 0 || at == email.size() - 1)
		return false;
	if(email.find('@', at + 1) != std::string::npos)
		return false;
	return true;
}

static bool safe_header_value(const std::string &value)
{
	return value.size() <= 255 && value.find('\r') == std::string::npos && value.find('\n') == std::string::npos;
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

static bool secure_uniform(unsigned int limit, unsigned int &out)
{
	if(limit == 0)
		return false;

	unsigned int x;
	unsigned int threshold = 0xffffffffu - (0xffffffffu % limit);
	do
	{
		if(!secure_random_bytes((unsigned char *)&x, sizeof(x)))
			return false;
	} while(x >= threshold);

	out = x % limit;
	return true;
}

static bool generate_otp(std::string &otp)
{
	unsigned int max = 1;
	for(int i = 0; i < cfg.otp_length; ++i)
		max *= 10;

	unsigned int value;
	if(!secure_uniform(max, value))
		return false;

	char fmt[16], buf[32];
	snprintf(fmt, sizeof(fmt), "%%0%du", cfg.otp_length);
	snprintf(buf, sizeof(buf), fmt, value);
	otp = buf;
	return true;
}

static void hash_otp(const unsigned char nonce[16], const std::string &otp, unsigned char out[SHA256_DIGEST_LENGTH])
{
	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, nonce, 16);
	SHA256_Update(&ctx, otp.data(), otp.size());
	SHA256_Final(out, &ctx);
}

static bool hashes_equal(const unsigned char *a, const unsigned char *b)
{
	unsigned char diff = 0;
	for(int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
		diff |= a[i] ^ b[i];
	return diff == 0;
}

static void irc_reply(const std::string &nick, const char *message)
{
	if(cfg.notification_type == "notice")
		ME.notice(nick.c_str(), message, NULL);
	else
		ME.privmsg(nick.c_str(), message, NULL);
}

static size_t smtp_read_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
	UploadPayload *payload = (UploadPayload *)userdata;
	size_t max = size * nmemb;
	size_t left = payload->len - payload->pos;
	size_t n = left < max ? left : max;
	if(n)
	{
		memcpy(ptr, payload->data + payload->pos, n);
		payload->pos += n;
	}
	return n;
}

static bool load_curl_api()
{
	if(curlapi.lib)
		return true;

	curlapi.lib = dlopen("libcurl.so.4", RTLD_NOW);
	if(!curlapi.lib)
		curlapi.lib = dlopen("libcurl.so", RTLD_NOW);
	if(!curlapi.lib)
		return false;

	curlapi.global_init = (CURLcode (*)(long))dlsym(curlapi.lib, "curl_global_init");
	curlapi.global_cleanup = (void (*)())dlsym(curlapi.lib, "curl_global_cleanup");
	curlapi.easy_init = (CURL *(*)())dlsym(curlapi.lib, "curl_easy_init");
	curlapi.easy_setopt = (CURLcode (*)(CURL *, int, ...))dlsym(curlapi.lib, "curl_easy_setopt");
	curlapi.easy_perform = (CURLcode (*)(CURL *))dlsym(curlapi.lib, "curl_easy_perform");
	curlapi.easy_getinfo = (CURLcode (*)(CURL *, int, ...))dlsym(curlapi.lib, "curl_easy_getinfo");
	curlapi.easy_cleanup = (void (*)(CURL *))dlsym(curlapi.lib, "curl_easy_cleanup");
	curlapi.easy_strerror = (const char *(*)(CURLcode))dlsym(curlapi.lib, "curl_easy_strerror");
	curlapi.slist_append = (curl_slist *(*)(curl_slist *, const char *))dlsym(curlapi.lib, "curl_slist_append");
	curlapi.slist_free_all = (void (*)(curl_slist *))dlsym(curlapi.lib, "curl_slist_free_all");

	if(!curlapi.global_init || !curlapi.global_cleanup || !curlapi.easy_init ||
		!curlapi.easy_setopt || !curlapi.easy_perform || !curlapi.easy_getinfo ||
		!curlapi.easy_cleanup || !curlapi.easy_strerror || !curlapi.slist_append ||
		!curlapi.slist_free_all)
	{
		dlclose(curlapi.lib);
		memset(&curlapi, 0, sizeof(curlapi));
		return false;
	}

	return true;
}

static bool smtp_send_job(const SmtpJob &job, std::string &error)
{
	CURL *curl = curlapi.easy_init();
	if(!curl)
	{
		error = "curl_easy_init failed";
		return false;
	}

	std::string from_header = job.from_name.empty() ? job.from : job.from_name + " <" + job.from + ">";
	std::string payload =
		"To: " + job.to + "\r\n" +
		"From: " + from_header + "\r\n" +
		"Subject: Your IRC operator verification code\r\n" +
		"\r\n" +
		"Your verification code is: " + job.otp + "\r\n\r\n" +
		"This code expires in 5 minutes.\r\n\r\n" +
		"If you did not request this code, you can ignore this message.\r\n" +
		"Bot: " + job.botnick + "\r\n";

	UploadPayload upload;
	upload.data = payload.c_str();
	upload.pos = 0;
	upload.len = payload.size();

	struct curl_slist *recipients = NULL;
	std::string mail_from = "<" + job.from + ">";
	std::string rcpt = "<" + job.to + ">";
	recipients = curlapi.slist_append(recipients, rcpt.c_str());

	curlapi.easy_setopt(curl, CURLOPT_URL, job.url.c_str());
	curlapi.easy_setopt(curl, CURLOPT_MAIL_FROM, mail_from.c_str());
	curlapi.easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);
	curlapi.easy_setopt(curl, CURLOPT_READFUNCTION, smtp_read_cb);
	curlapi.easy_setopt(curl, CURLOPT_READDATA, &upload);
	curlapi.easy_setopt(curl, CURLOPT_UPLOAD, 1L);
	curlapi.easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
	curlapi.easy_setopt(curl, CURLOPT_TIMEOUT, (long)job.timeout);
	curlapi.easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, job.verify_tls ? 1L : 0L);
	curlapi.easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, job.verify_tls ? 2L : 0L);

	if(job.security == "starttls")
		curlapi.easy_setopt(curl, CURLOPT_USE_SSL, (long)CURLUSESSL_ALL);

	if(!job.user.empty())
		curlapi.easy_setopt(curl, CURLOPT_USERNAME, job.user.c_str());
	if(!job.password.empty())
		curlapi.easy_setopt(curl, CURLOPT_PASSWORD, job.password.c_str());

	CURLcode rc = curlapi.easy_perform(curl);
	long response = 0;
	curlapi.easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response);
	curlapi.slist_free_all(recipients);
	curlapi.easy_cleanup(curl);

	if(rc != CURLE_OK)
	{
		error = curlapi.easy_strerror(rc);
		return false;
	}
	if(response >= 400)
	{
		char buf[80];
		snprintf(buf, sizeof(buf), "SMTP response code %ld", response);
		error = buf;
		return false;
	}
	return true;
}

static void *smtp_worker(void *)
{
	while(true)
	{
		pthread_mutex_lock(&smtp_mutex);
		while(smtp_jobs.empty() && !smtp_shutdown)
			pthread_cond_wait(&smtp_cond, &smtp_mutex);
		if(smtp_shutdown && smtp_jobs.empty())
		{
			pthread_mutex_unlock(&smtp_mutex);
			break;
		}
		SmtpJob job = smtp_jobs.front();
		smtp_jobs.pop_front();
		pthread_mutex_unlock(&smtp_mutex);

		SmtpResult result;
		result.handle = job.handle;
		result.created_at = job.created_at;
		result.ok = smtp_send_job(job, result.error);

		pthread_mutex_lock(&smtp_mutex);
		smtp_results.push_back(result);
		pthread_mutex_unlock(&smtp_mutex);
	}
	return NULL;
}

static bool ensure_worker()
{
	if(smtp_started)
		return true;
	if(!load_curl_api())
		return false;
	if(curlapi.global_init(CURL_GLOBAL_DEFAULT) != 0)
		return false;
	smtp_shutdown = false;
	if(pthread_create(&smtp_thread, NULL, smtp_worker, NULL) != 0)
		return false;
	smtp_started = true;
	return true;
}

static std::string smtp_url()
{
	char port[24];
	snprintf(port, sizeof(port), "%d", cfg.smtp_port);
	std::string scheme = cfg.smtp_security == "smtps" ? "smtps://" : "smtp://";
	return scheme + cfg.smtp_host + ":" + port;
}

static void queue_smtp(const PendingRequest &req, const std::string &email, const std::string &otp)
{
	SmtpJob job;
	job.handle = req.handle;
	job.nick = req.nick;
	job.created_at = req.created_at;
	job.to = email;
	job.otp = otp;
	job.url = smtp_url();
	job.user = cfg.smtp_user;
	job.password = cfg.smtp_password;
	job.from = cfg.smtp_from;
	job.from_name = cfg.smtp_from_name;
	job.botnick = (const char *)ME.nick;
	job.security = cfg.smtp_security;
	job.verify_tls = cfg.verify_tls;
	job.timeout = 20;

	pthread_mutex_lock(&smtp_mutex);
	smtp_jobs.push_back(job);
	pthread_cond_signal(&smtp_cond);
	pthread_mutex_unlock(&smtp_mutex);
}

static bool valid_smtp_config()
{
	return !cfg.smtp_host.empty() && valid_email(cfg.smtp_from) &&
		(cfg.smtp_security == "plain" || cfg.smtp_security == "starttls" || cfg.smtp_security == "smtps") &&
		safe_header_value(cfg.smtp_from_name);
}

static void expire_runtime()
{
	std::map<std::string, OtpSession>::iterator it = sessions.begin();
	while(it != sessions.end())
	{
		if(it->second.expires_at <= NOW)
			sessions.erase(it++);
		else
			++it;
	}

	std::map<std::string, PendingRequest>::iterator pit = pending.begin();
	while(pit != pending.end())
	{
		if(pit->second.expires_at <= NOW)
			pending.erase(pit++);
		else
			++pit;
	}

	std::map<std::string, time_t>::iterator lit = lockouts.begin();
	while(lit != lockouts.end())
	{
		if(lit->second <= NOW)
			lockouts.erase(lit++);
		else
			++lit;
	}

	std::map<std::string, std::deque<time_t> >::iterator rit = request_times.begin();
	while(rit != request_times.end())
	{
		while(!rit->second.empty() && rit->second.front() <= NOW - 3600)
			rit->second.pop_front();
		++rit;
	}
}

static bool rate_limited(const std::string &handle)
{
	std::deque<time_t> &times = request_times[handle];
	while(!times.empty() && times.front() <= NOW - 3600)
		times.pop_front();
	if(!times.empty() && times.back() + cfg.resend_cooldown > NOW)
		return true;
	if((int)times.size() >= cfg.hourly_limit)
		return true;
	return false;
}

static void note_request(const std::string &handle)
{
	request_times[handle].push_back(NOW);
}

static void handle_request(const char *from)
{
	std::string nick = nick_from_mask(from);
	if(!cfg.enabled)
	{
		irc_reply(nick, "Email OTP authentication is not available for your account");
		return;
	}

	HANDLE *h = userlist.findHandleByHost(from);
	if(!h || userlist.isBot(h))
	{
		irc_reply(nick, "Email OTP authentication is not available for your account");
		return;
	}

	std::string handle = h->name;
	std::map<std::string, EmailOtpUser>::iterator uit = users.find(handle);
	if(uit == users.end() || !uit->second.enabled || !valid_email(uit->second.email))
	{
		irc_reply(nick, "Email OTP authentication is not available for your account");
		return;
	}

	std::string lkey = lock_key(handle, from);
	if(lockouts.find(lkey) != lockouts.end() && lockouts[lkey] > NOW)
	{
		irc_reply(nick, "Please wait before requesting another verification code");
		return;
	}

	if(rate_limited(handle))
	{
		irc_reply(nick, "Please wait before requesting another verification code");
		return;
	}

	if(!valid_smtp_config() || !ensure_worker())
	{
		irc_reply(nick, "Unable to send the verification code. Please try again later");
		net.send(HAS_N, "[email-otp] SMTP is not configured or worker could not start", NULL);
		return;
	}

	std::string otp;
	PendingRequest req;
	req.handle = handle;
	req.hostmask = from;
	req.nick = nick;
	req.created_at = NOW;
	req.expires_at = NOW + cfg.otp_ttl;

	if(!secure_random_bytes(req.nonce, sizeof(req.nonce)) || !generate_otp(otp))
	{
		irc_reply(nick, "Unable to send the verification code. Please try again later");
		net.send(HAS_N, "[email-otp] secure random generation failed", NULL);
		return;
	}

	hash_otp(req.nonce, otp, req.hash);
	sessions.erase(handle);
	pending[handle] = req;
	note_request(handle);
	queue_smtp(req, uit->second.email, otp);

	net.send(HAS_N, "[email-otp] OTP requested by ", handle.c_str(), " (", nick.c_str(), ")", NULL);
	net.send(HAS_N, "[email-otp] OTP email queued for ", handle.c_str(), NULL);
}

static bool parse_otp_message(const char *msg, std::string &otp)
{
	char arg[2][MAX_LEN];
	str2words(arg[0], msg, 2, MAX_LEN, 0);

	if(!strcmp(arg[0], "op-email") && strlen(arg[1]))
		otp = arg[1];
	else
		return false;

	if((int)otp.size() != cfg.otp_length)
		return false;
	for(size_t i = 0; i < otp.size(); ++i)
		if(!isdigit((unsigned char)otp[i]))
			return false;
	return true;
}

static void handle_otp_submit(const char *from, const char *msg)
{
	HANDLE *h = userlist.findHandleByHost(from);
	if(!h || userlist.isBot(h))
		return;

	std::string handle = h->name;
	std::map<std::string, OtpSession>::iterator sit = sessions.find(handle);
	if(sit == sessions.end())
		return;

	OtpSession &session = sit->second;
	std::string nick = nick_from_mask(from);
	std::string lkey = lock_key(handle, session.hostmask.c_str());

	if(lockouts.find(lkey) != lockouts.end() && lockouts[lkey] > NOW)
	{
		sessions.erase(sit);
		irc_reply(nick, "Please wait before requesting another verification code");
		return;
	}

	if(session.expires_at <= NOW)
	{
		sessions.erase(sit);
		irc_reply(nick, "Verification code expired. Request a new code with email-otp");
		return;
	}

	if(session.hostmask != from || session.nick != nick || strcmp(h->name, session.handle.c_str()))
	{
		sessions.erase(sit);
		irc_reply(nick, "Verification code expired. Request a new code with email-otp");
		return;
	}

	std::string otp;
	if(!parse_otp_message(msg, otp))
	{
		session.attempts++;
		net.send(HAS_N, "[email-otp] OTP verification failed for ", handle.c_str(), " (", itoa(session.attempts), "/", itoa(cfg.max_attempts), ")", NULL);
		if((int)session.attempts >= cfg.max_attempts)
		{
			lockouts[lkey] = NOW + cfg.lockout_time;
			sessions.erase(sit);
			irc_reply(nick, "Too many failed attempts. OTP authentication has been locked for 5 hours");
			net.send(HAS_N, "[email-otp] OTP authentication locked for ", handle.c_str(), " for ", itoa(cfg.lockout_time), " seconds", NULL);
		}
		else
		{
			char buf[128];
			snprintf(buf, sizeof(buf), "Invalid verification code. %d attempts remaining", cfg.max_attempts - (int)session.attempts);
			irc_reply(nick, buf);
		}
		return;
	}

	unsigned char digest[SHA256_DIGEST_LENGTH];
	hash_otp(session.nonce, otp, digest);
	if(hashes_equal(digest, session.hash))
	{
		sessions.erase(sit);
		HANDLE *reh = userlist.findHandleByHost(from);
		if(reh && !strcmp(reh->name, handle.c_str()))
		{
			irc_reply(nick, "Verification successful");
			grantOpForAuthenticatedUser(from, NULL);
			net.send(HAS_N, "[email-otp] OTP verification successful for ", handle.c_str(), NULL);
		}
		return;
	}

	session.attempts++;
	net.send(HAS_N, "[email-otp] OTP verification failed for ", handle.c_str(), " (", itoa(session.attempts), "/", itoa(cfg.max_attempts), ")", NULL);
	if((int)session.attempts >= cfg.max_attempts)
	{
		lockouts[lkey] = NOW + cfg.lockout_time;
		sessions.erase(sit);
		irc_reply(nick, "Too many failed attempts. OTP authentication has been locked for 5 hours");
		net.send(HAS_N, "[email-otp] OTP authentication locked for ", handle.c_str(), " for ", itoa(cfg.lockout_time), " seconds", NULL);
	}
	else
	{
		char buf[128];
		snprintf(buf, sizeof(buf), "Invalid verification code. %d attempts remaining", cfg.max_attempts - (int)session.attempts);
		irc_reply(nick, buf);
	}
}

void hook_privmsg(const char *from, const char *to, const char *msg)
{
	if(strcmp(to, ME.nick))
		return;

	if(!strcmp(msg, "email-otp"))
	{
		handle_request(from);
		stopParsing = true;
		return;
	}

	HANDLE *h = userlist.findHandleByHost(from);
	if(h && sessions.find(h->name) != sessions.end())
	{
		char arg[2][MAX_LEN];
		str2words(arg[0], msg, 2, MAX_LEN, 0);
		if(!strcmp(arg[0], "op-email"))
		{
			handle_otp_submit(from, msg);
			stopParsing = true;
		}
	}
}

static void handle_smtp_results()
{
	std::deque<SmtpResult> results;
	pthread_mutex_lock(&smtp_mutex);
	results.swap(smtp_results);
	pthread_mutex_unlock(&smtp_mutex);

	for(size_t i = 0; i < results.size(); ++i)
	{
		SmtpResult &res = results[i];
		std::map<std::string, PendingRequest>::iterator pit = pending.find(res.handle);
		if(pit == pending.end())
			continue;
		if(pit->second.created_at != res.created_at)
			continue;

		PendingRequest req = pit->second;
		pending.erase(pit);

		if(!res.ok)
		{
			irc_reply(req.nick, "Unable to send the verification code. Please try again later");
			net.send(HAS_N, "[email-otp] SMTP delivery failed for ", res.handle.c_str(), ": ", res.error.c_str(), NULL);
			continue;
		}

		OtpSession session;
		session.handle = req.handle;
		session.hostmask = req.hostmask;
		session.nick = req.nick;
		memcpy(session.nonce, req.nonce, sizeof(session.nonce));
		memcpy(session.hash, req.hash, sizeof(session.hash));
		session.created_at = req.created_at;
		session.expires_at = req.expires_at;
		session.attempts = 0;
		sessions[session.handle] = session;
		irc_reply(req.nick, "Verification code sent. Check your email and reply here with: op-email <6-digit code>");
	}
}

void hook_timer()
{
	expire_runtime();
	handle_smtp_results();
}

static void status_to_owner(const char *from)
{
	net.sendOwner(from, "Email OTP Status:", NULL);
	net.sendOwner(from, "Module Enabled: ", cfg.enabled ? "ON" : "OFF", NULL);
	net.sendOwner(from, "SMTP Host: ", cfg.smtp_host.c_str(), NULL);
	net.sendOwner(from, "SMTP Port: ", itoa(cfg.smtp_port), NULL);
	net.sendOwner(from, "SMTP Security: ", cfg.smtp_security.c_str(), NULL);
	net.sendOwner(from, "SMTP User: ", cfg.smtp_user.c_str(), NULL);
	net.sendOwner(from, "SMTP Password: ", cfg.smtp_password.empty() ? "(not set)" : "********", NULL);
	net.sendOwner(from, "SMTP From: ", cfg.smtp_from.c_str(), NULL);
	net.sendOwner(from, "SMTP From Name: ", cfg.smtp_from_name.c_str(), NULL);
	net.sendOwner(from, "Verify TLS: ", cfg.verify_tls ? "ON" : "OFF", NULL);
	net.sendOwner(from, "OTP Length: ", itoa(cfg.otp_length), NULL);
	net.sendOwner(from, "OTP TTL: ", itoa(cfg.otp_ttl), NULL);
	net.sendOwner(from, "Max Attempts: ", itoa(cfg.max_attempts), NULL);
	net.sendOwner(from, "Lockout Time: ", itoa(cfg.lockout_time), NULL);
	net.sendOwner(from, "Resend Cooldown: ", itoa(cfg.resend_cooldown), NULL);
	net.sendOwner(from, "Hourly Limit: ", itoa(cfg.hourly_limit), NULL);
	net.sendOwner(from, "Notification Type: ", cfg.notification_type.c_str(), NULL);
}

static void help_to_owner(const char *from)
{
	net.sendOwner(from, ".email-otp status|enable|disable|smtp|help", NULL);
	net.sendOwner(from, ".email-otp set <smtp-host|smtp-port|smtp-security|smtp-user|smtp-password|smtp-from|smtp-from-name|verify-tls|notification-type> <value>", NULL);
	net.sendOwner(from, ".email-otp set <otp-length|otp-ttl|max-attempts|lockout-time|resend-cooldown|hourly-limit> <value>", NULL);
	net.sendOwner(from, ".email-otp user <handle> show|set-email <email>|enable|disable|remove-email|unlock", NULL);
}

static void smtp_status_to_owner(const char *from)
{
	net.sendOwner(from, "SMTP Host: ", cfg.smtp_host.c_str(), NULL);
	net.sendOwner(from, "SMTP Port: ", itoa(cfg.smtp_port), NULL);
	net.sendOwner(from, "SMTP Security: ", cfg.smtp_security.c_str(), NULL);
	net.sendOwner(from, "SMTP From: ", cfg.smtp_from.c_str(), NULL);
	net.sendOwner(from, "SMTP User: ", cfg.smtp_user.empty() ? "(not set)" : cfg.smtp_user.c_str(), NULL);
	net.sendOwner(from, "SMTP Password: ", cfg.smtp_password.empty() ? "(not set)" : "********", NULL);
	net.sendOwner(from, "Verify TLS: ", cfg.verify_tls ? "ON" : "OFF", NULL);
}

static bool set_config_value(const char *key, const char *value, std::string &err)
{
	bool b;
	int n = atoi(value);
	if(!strcmp(key, "smtp-host")) cfg.smtp_host = value;
	else if(!strcmp(key, "smtp-port"))
	{
		if(n <= 0 || n > 65535) { err = "invalid port"; return false; }
		cfg.smtp_port = n;
	}
	else if(!strcmp(key, "smtp-security"))
	{
		if(strcmp(value, "plain") && strcmp(value, "starttls") && strcmp(value, "smtps")) { err = "invalid smtp-security"; return false; }
		cfg.smtp_security = value;
	}
	else if(!strcmp(key, "smtp-user")) cfg.smtp_user = value;
	else if(!strcmp(key, "smtp-password")) cfg.smtp_password = value;
	else if(!strcmp(key, "smtp-from"))
	{
		if(!valid_email(value)) { err = "invalid email address"; return false; }
		cfg.smtp_from = value;
	}
	else if(!strcmp(key, "smtp-from-name"))
	{
		if(!safe_header_value(value)) { err = "invalid header value"; return false; }
		cfg.smtp_from_name = value;
	}
	else if(!strcmp(key, "verify-tls"))
	{
		if(!parse_bool_value(value, b)) { err = "invalid boolean"; return false; }
		cfg.verify_tls = b;
	}
	else if(!strcmp(key, "otp-length"))
	{
		if(n < 6 || n > 9) { err = "otp-length must be 6..9"; return false; }
		cfg.otp_length = n;
	}
	else if(!strcmp(key, "otp-ttl"))
	{
		if(n < 30 || n > 3600) { err = "otp-ttl must be 30..3600"; return false; }
		cfg.otp_ttl = n;
	}
	else if(!strcmp(key, "max-attempts"))
	{
		if(n < 1 || n > 10) { err = "max-attempts must be 1..10"; return false; }
		cfg.max_attempts = n;
	}
	else if(!strcmp(key, "lockout-time"))
	{
		if(n < 60 || n > 86400) { err = "lockout-time must be 60..86400"; return false; }
		cfg.lockout_time = n;
	}
	else if(!strcmp(key, "resend-cooldown"))
	{
		if(n < 1 || n > 3600) { err = "resend-cooldown must be 1..3600"; return false; }
		cfg.resend_cooldown = n;
	}
	else if(!strcmp(key, "hourly-limit"))
	{
		if(n < 1 || n > 100) { err = "hourly-limit must be 1..100"; return false; }
		cfg.hourly_limit = n;
	}
	else if(!strcmp(key, "notification-type"))
	{
		if(strcmp(value, "text") && strcmp(value, "notice")) { err = "notification-type must be text or notice"; return false; }
		cfg.notification_type = value;
	}
	else
	{
		err = "unknown setting";
		return false;
	}
	return true;
}

static void user_show(const char *from, const char *handle)
{
	HANDLE *h = userlist.findHandle(handle);
	if(!h)
	{
		net.sendOwner(from, "Unknown handle", NULL);
		return;
	}

	EmailOtpUser &u = users[handle];
	bool locked = false;
	std::string prefix = std::string(handle) + "|";
	for(std::map<std::string, time_t>::iterator it = lockouts.begin(); it != lockouts.end(); ++it)
		if(!strncmp(it->first.c_str(), prefix.c_str(), prefix.size()) && it->second > NOW)
			locked = true;

	net.sendOwner(from, "Email OTP User: ", handle, NULL);
	net.sendOwner(from, "Status: ", u.enabled ? "ENABLED" : "DISABLED", NULL);
	net.sendOwner(from, "Email: ", u.email.empty() ? "(not set)" : u.email.c_str(), NULL);
	net.sendOwner(from, "Locked: ", locked ? "YES" : "NO", NULL);
}

static void user_command(const char *from, char arg[10][MAX_LEN], const char *args)
{
	const char *handle = arg[1];
	const char *action = arg[2];
	HANDLE *h = userlist.findHandle(handle);
	if(!strlen(handle) || !strlen(action))
	{
		net.sendOwner(from, "Syntax: .email-otp user <handle> show|set-email|enable|disable|remove-email|unlock", NULL);
		return;
	}
	if(!h)
	{
		net.sendOwner(from, "Unknown handle", NULL);
		return;
	}

	EmailOtpUser &u = users[handle];
	if(!strcmp(action, "show"))
		user_show(from, handle);
	else if(!strcmp(action, "set-email"))
	{
		char *email = srewind(args, 3);
		if(!email || !valid_email(email))
		{
			net.sendOwner(from, "Invalid email address", NULL);
			return;
		}
			u.email = email;
			u.enabled = false;
			emailotp_save();
			net.sendOwner(from, "Email OTP email set for ", handle, "; account remains disabled", NULL);
		}
		else if(!strcmp(action, "enable"))
		{
			if(!valid_email(u.email))
			{
				net.sendOwner(from, handle, " has no valid email configured", NULL);
				return;
			}
			u.enabled = true;
			emailotp_save();
			net.sendOwner(from, "Email OTP enabled for ", handle, NULL);
		}
		else if(!strcmp(action, "disable"))
		{
			u.enabled = false;
			sessions.erase(handle);
			pending.erase(handle);
			emailotp_save();
			net.sendOwner(from, "Email OTP disabled for ", handle, NULL);
		}
		else if(!strcmp(action, "remove-email"))
		{
			u.email.clear();
			u.enabled = false;
			sessions.erase(handle);
			pending.erase(handle);
			emailotp_save();
			net.sendOwner(from, "Email OTP email removed for ", handle, "; account disabled", NULL);
		}
	else if(!strcmp(action, "unlock"))
	{
		std::string prefix = std::string(handle) + "|";
		for(std::map<std::string, time_t>::iterator it = lockouts.begin(); it != lockouts.end(); )
		{
				if(!strncmp(it->first.c_str(), prefix.c_str(), prefix.size()))
					lockouts.erase(it++);
				else
					++it;
			}
			net.send(HAS_N, "[email-otp] OTP manually unlocked for ", handle, NULL);
			net.sendOwner(from, "Email OTP unlocked for ", handle, NULL);
		}
	else
		net.sendOwner(from, "Unknown user command", NULL);
}

void hook_partylineCmd(const char *from, int flags, const char *cmd, const char *args)
{
	if(strcmp(cmd, ".email-otp"))
		return;
	stopParsing = true;

	if(!(flags & HAS_N))
	{
		net.sendOwner(from, "No permission", NULL);
		return;
	}

	char arg[10][MAX_LEN];
	str2words(arg[0], args ? args : "", 10, MAX_LEN, 0);

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
	if(!strcmp(arg[0], "smtp"))
	{
		smtp_status_to_owner(from);
		return;
	}
	if(!strcmp(arg[0], "enable"))
	{
		cfg.enabled = true;
		emailotp_save();
		net.sendOwner(from, "Email OTP module enabled", NULL);
		return;
	}
	if(!strcmp(arg[0], "disable"))
	{
		cfg.enabled = false;
		sessions.clear();
		pending.clear();
		emailotp_save();
		net.sendOwner(from, "Email OTP module disabled", NULL);
		return;
	}
	if(!strcmp(arg[0], "set"))
	{
		char *value = srewind(args, 2);
		if(!strlen(arg[1]) || !value || !*value)
		{
			net.sendOwner(from, "Syntax: .email-otp set <key> <value>", NULL);
			return;
		}
		std::string err;
		if(!set_config_value(arg[1], value, err))
		{
			net.sendOwner(from, err.c_str(), NULL);
			return;
		}
		emailotp_save();
		net.sendOwner(from, !strcmp(arg[1], "smtp-password") ? "smtp-password has been set to ********" : "Setting updated", NULL);
		return;
	}
	if(!strcmp(arg[0], "user"))
	{
		user_command(from, arg, args ? args : "");
		return;
	}

	net.sendOwner(from, "Unknown email-otp command", NULL);
}

static void emailotp_load()
{
	FILE *fh = fopen(EMAIL_OTP_CFG_FILE, "r");
	if(!fh)
		return;

	char buffer[MAX_LEN];
	char arg[10][MAX_LEN];
	int line = 0;
	while(fgets(buffer, sizeof(buffer), fh))
	{
		line++;
		buffer[strcspn(buffer, "\r\n")] = '\0';
		str2words(arg[0], buffer, 10, MAX_LEN, 0);
		if(!strlen(arg[0]) || arg[0][0] == '#')
			continue;
		if(!strcmp(arg[0], "set"))
		{
			char *value = srewind(buffer, 2);
			std::string err;
			if(!strcmp(arg[1], "module-enabled"))
			{
				bool b;
				if(parse_bool_value(value ? value : "", b))
					cfg.enabled = b;
			}
			else if(value && !set_config_value(arg[1], value, err))
				printf("[-] %s:%d: %s\n", EMAIL_OTP_CFG_FILE, line, err.c_str());
		}
		else if(!strcmp(arg[0], "user"))
		{
			if(!strlen(arg[1]) || !strlen(arg[2]))
				continue;
			EmailOtpUser &u = users[arg[1]];
			char *value = srewind(buffer, 3);
			if(!strcmp(arg[2], "email") && value && valid_email(value))
				u.email = value;
			else if(!strcmp(arg[2], "enabled") && value)
			{
				bool b;
				if(parse_bool_value(value, b))
					u.enabled = b;
			}
		}
	}
	fclose(fh);
}

static void emailotp_save()
{
	FILE *fh = fopen(EMAIL_OTP_CFG_FILE, "w");
	if(!fh)
	{
		net.send(HAS_N, "[email-otp] cannot open ", EMAIL_OTP_CFG_FILE, " for writing: ", strerror(errno), NULL);
		return;
	}
	chmod(EMAIL_OTP_CFG_FILE, S_IRUSR | S_IWUSR);

	fprintf(fh, "set module-enabled %s\n", cfg.enabled ? "ON" : "OFF");
	fprintf(fh, "set smtp-host %s\n", cfg.smtp_host.c_str());
	fprintf(fh, "set smtp-port %d\n", cfg.smtp_port);
	fprintf(fh, "set smtp-security %s\n", cfg.smtp_security.c_str());
	fprintf(fh, "set smtp-user %s\n", cfg.smtp_user.c_str());
	fprintf(fh, "set smtp-password %s\n", cfg.smtp_password.c_str());
	fprintf(fh, "set smtp-from %s\n", cfg.smtp_from.c_str());
	fprintf(fh, "set smtp-from-name %s\n", cfg.smtp_from_name.c_str());
	fprintf(fh, "set verify-tls %s\n", cfg.verify_tls ? "ON" : "OFF");
	fprintf(fh, "set otp-length %d\n", cfg.otp_length);
	fprintf(fh, "set otp-ttl %d\n", cfg.otp_ttl);
	fprintf(fh, "set max-attempts %d\n", cfg.max_attempts);
	fprintf(fh, "set lockout-time %d\n", cfg.lockout_time);
	fprintf(fh, "set resend-cooldown %d\n", cfg.resend_cooldown);
	fprintf(fh, "set hourly-limit %d\n", cfg.hourly_limit);
	fprintf(fh, "set notification-type %s\n", cfg.notification_type.c_str());

	for(std::map<std::string, EmailOtpUser>::iterator it = users.begin(); it != users.end(); ++it)
	{
		if(!it->second.email.empty())
			fprintf(fh, "user %s email %s\n", it->first.c_str(), it->second.email.c_str());
		fprintf(fh, "user %s enabled %s\n", it->first.c_str(), it->second.enabled ? "ON" : "OFF");
	}

	fclose(fh);
}

void hook_userlistLoaded()
{
	users.clear();
	emailotp_load();
}

module *init()
{
	module_info = new module(EMAIL_OTP_MODULE, "OpenAI Codex", "0.1");
	module_info->hooks->privmsg = hook_privmsg;
	module_info->hooks->partylineCmd = hook_partylineCmd;
	module_info->hooks->timer = hook_timer;
	module_info->hooks->userlistLoaded = hook_userlistLoaded;

	if(userlist.SN)
		hook_userlistLoaded();

	return module_info;
}

void destroy()
{
	if(smtp_started)
	{
		pthread_mutex_lock(&smtp_mutex);
		smtp_shutdown = true;
		pthread_cond_signal(&smtp_cond);
		pthread_mutex_unlock(&smtp_mutex);
		pthread_join(smtp_thread, NULL);
		curlapi.global_cleanup();
		if(curlapi.lib)
			dlclose(curlapi.lib);
		memset(&curlapi, 0, sizeof(curlapi));
		smtp_started = false;
	}
}

} // namespace email_otp

namespace qrcode_otp {

#define QRCODE_OTP_CFG_FILE "qrcode-otp.txt"
#define QRCODE_OTP_MODULE "qrcode-otp"

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

struct QrOtpConfig
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

		QrOtpConfig() :
			enabled(false),
			issuer("Evangeline OTP"),
			notification_type("text"),
			digits(6),
			period(30),
			setup_ttl(300),
			setup_cooldown(60),
			max_attempts(3),
			lockout_time(18000),
			qr_line_delay(2),
			qr_output("compact")
	{
	}
};

struct QrOtpUser
{
	bool allowed;
	bool enabled;
	std::string secret;

	QrOtpUser() : allowed(false), enabled(false) { }
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
static QrOtpConfig cfg;
static QrApi qrapi;
static std::map<std::string, QrOtpUser> users;
static std::map<std::string, SetupSession> setup_sessions;
static std::map<std::string, time_t> setup_request_times;
static std::map<std::string, time_t> lockouts;
static std::map<std::string, unsigned int> failures;
static std::map<std::string, unsigned long long> last_totp_counters;
static std::deque<OutMsg> outbox;
static time_t last_outbox_send = 0;
static const size_t MAX_OUTBOX_MESSAGES = 120;
static const size_t TOTP_SECRET_BYTES = 20;
static const size_t MIN_TOTP_SECRET_BYTES = 16;

static void qrcode_save();
static void qrcode_load();

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

static std::string lock_key(const std::string &handle, const char *hostmask)
{
	return handle + "|" + canonical_host_from_mask(hostmask);
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
			it = outbox.erase(it);
		else
			++it;
	}
}

static void clear_runtime_for_handle(const std::string &handle)
{
	std::string prefix = handle + "|";
	setup_sessions.erase(handle);
	setup_request_times.erase(handle);
	for(std::map<std::string, unsigned int>::iterator fit = failures.begin(); fit != failures.end(); )
	{
		if(!strncmp(fit->first.c_str(), prefix.c_str(), prefix.size()))
			failures.erase(fit++);
		else
			++fit;
	}
	for(std::map<std::string, time_t>::iterator it = lockouts.begin(); it != lockouts.end(); )
	{
		if(!strncmp(it->first.c_str(), prefix.c_str(), prefix.size()))
			lockouts.erase(it++);
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
	std::string uri = "otpauth://totp/" + url_encode(label) +
		"?secret=" + secret;
	if(cfg.digits != 6)
		uri += std::string("&digits=") + digits;
	if(cfg.period != 30)
		uri += std::string("&period=") + period;
	return uri;
}

static bool parse_code(const char *text, std::string &code)
{
	char arg[3][MAX_LEN];
	str2words(arg[0], text, 3, MAX_LEN, 0);
	if(!strcmp(arg[0], "qr-op") && strlen(arg[1]))
		code = arg[1];
	else
		code = arg[0];
	if((int)code.size() != cfg.digits)
		return false;
	for(size_t i = 0; i < code.size(); ++i)
		if(!isdigit((unsigned char)code[i]))
			return false;
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
	if(cfg.qr_output == "compact")
	{
		for(int y = -border; y < qr->width + border; y += 2)
		{
			std::string line = "\00301,00";
			for(int x = -border; x < qr->width + border; ++x)
			{
				bool top = false;
				bool bottom = false;
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
		return;
	}

	for(int y = -border; y < qr->width + border; ++y)
	{
		std::string line;
		for(int x = -border; x < qr->width + border; ++x)
		{
			bool dark = false;
			if(x >= 0 && y >= 0 && x < qr->width && y < qr->width)
				dark = (qr->data[y * qr->width + x] & 1) != 0;
			line += dark ? "\342\226\210\342\226\210" : "  ";
		}
		queue_reply(nick, line);
	}
	qrapi.free_code(qr);
}

static bool user_available(const char *from, HANDLE **hout, std::string &handle, std::string &nick)
{
	nick = nick_from_mask(from);
	HANDLE *h = userlist.findHandleByHost(from);
	if(!h || userlist.isBot(h))
		return false;
	handle = h->name;
	*hout = h;
	return true;
}

static void handle_setup_request(const char *from)
{
	std::string handle, nick;
	HANDLE *h = NULL;
	if(!cfg.enabled || !user_available(from, &h, handle, nick))
	{
		irc_reply(nick_from_mask(from), "QR authentication is not available for your account");
		return;
	}

	QrOtpUser &u = users[handle];
	if(!u.allowed)
	{
		irc_reply(nick, "QR authentication is not available for your account");
		return;
	}
	if(!u.secret.empty())
	{
		irc_reply(nick, "QR authentication is already configured for your account");
		irc_reply(nick, "To set it up again, contact an owner to remove the existing QR secret");
		return;
	}

	std::map<std::string, SetupSession>::iterator existing = setup_sessions.find(handle);
	if(existing != setup_sessions.end() && existing->second.expires_at > NOW)
	{
		irc_reply(nick, "QR setup is already in progress. Check your previous messages or wait before requesting another setup");
		return;
	}

	if(setup_request_times.find(handle) != setup_request_times.end() && setup_request_times[handle] + cfg.setup_cooldown > NOW)
	{
		irc_reply(nick, "Please wait before requesting another QR setup");
		return;
	}

	std::string lkey = lock_key(handle, from);
	if(lockouts.find(lkey) != lockouts.end() && lockouts[lkey] > NOW)
	{
		irc_reply(nick, "QR authentication is temporarily locked");
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
		irc_reply(nick, "Unable to create QR setup. Please try again later");
		net.send(HAS_N, "[qrcode-otp] secure random generation failed", NULL);
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
	net.send(HAS_N, "[qrcode-otp] setup started for ", handle.c_str(), " (", nick.c_str(), ")", NULL);
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
	std::string lkey = lock_key(handle, session.hostmask.c_str());
	if(session.expires_at <= NOW || session.hostmask != from || session.nick != nick)
	{
		setup_sessions.erase(sit);
		irc_reply(nick, "QR setup expired. Request a new setup with qr-setup");
		return;
	}

	std::string code;
	if(!parse_code(msg, code) || !verify_totp(session.secret, code))
	{
		session.attempts++;
		if((int)session.attempts >= cfg.max_attempts)
		{
			lockouts[lkey] = NOW + cfg.lockout_time;
			setup_sessions.erase(sit);
			irc_reply(nick, "Too many failed attempts. QR authentication has been locked for 5 hours");
			net.send(HAS_N, "[qrcode-otp] setup locked for ", handle.c_str(), " for ", itoa(cfg.lockout_time), " seconds", NULL);
		}
		else
		{
			char buf[128];
			snprintf(buf, sizeof(buf), "Invalid verification code. %d attempts remaining", cfg.max_attempts - (int)session.attempts);
			irc_reply(nick, buf);
		}
		return;
	}

	QrOtpUser &u = users[handle];
	u.secret = session.secret;
	u.allowed = true;
	u.enabled = true;
	setup_sessions.erase(sit);
	qrcode_save();
	irc_reply(nick, "QR setup verified and enabled");
	irc_reply(nick, "To request op, send: qr-op <6-digit code>");
	net.send(HAS_N, "[qrcode-otp] setup verified for ", handle.c_str(), NULL);
}

static void handle_qr_op(const char *from, const char *msg)
{
	std::string handle, nick;
	HANDLE *h = NULL;
	if(!cfg.enabled || !user_available(from, &h, handle, nick))
	{
		irc_reply(nick_from_mask(from), "QR authentication is not available for your account");
		return;
	}

	QrOtpUser &u = users[handle];
	if(!u.enabled || u.secret.empty())
	{
		irc_reply(nick, "QR authentication is not available for your account");
		return;
	}

	std::string lkey = lock_key(handle, from);
	if(lockouts.find(lkey) != lockouts.end() && lockouts[lkey] > NOW)
	{
		irc_reply(nick, "QR authentication is temporarily locked");
		return;
	}

	std::string code;
	unsigned long long matched_counter = 0;
	if(!parse_code(msg, code) || !verify_totp(u.secret, code, &matched_counter))
	{
		unsigned int n = ++failures[lkey];
		if((int)n >= cfg.max_attempts)
		{
			failures.erase(lkey);
			lockouts[lkey] = NOW + cfg.lockout_time;
			irc_reply(nick, "Too many failed attempts. QR authentication has been locked for 5 hours");
			net.send(HAS_N, "[qrcode-otp] authentication locked for ", handle.c_str(), " for ", itoa(cfg.lockout_time), " seconds", NULL);
		}
		else
		{
			char buf[128];
			snprintf(buf, sizeof(buf), "Invalid verification code. %d attempts remaining", cfg.max_attempts - (int)n);
			irc_reply(nick, buf);
		}
		return;
	}

	if(last_totp_counters.find(lkey) != last_totp_counters.end() && matched_counter <= last_totp_counters[lkey])
	{
		irc_reply(nick, "Verification code already used. Wait for a new code and try again");
		net.send(HAS_N, "[qrcode-otp] OTP replay rejected for ", handle.c_str(), NULL);
		return;
	}

	failures.erase(lkey);
	HANDLE *reh = userlist.findHandleByHost(from);
	if(reh && !strcmp(reh->name, handle.c_str()))
	{
		last_totp_counters[lkey] = matched_counter;
		irc_reply(nick, "Verification successful");
		grantOpForAuthenticatedUser(from, NULL);
		net.send(HAS_N, "[qrcode-otp] OTP verification successful for ", handle.c_str(), NULL);
	}
}

void hook_privmsg(const char *from, const char *to, const char *msg)
{
	if(strcmp(to, ME.nick))
		return;

	if(!strcmp(msg, "qr-setup"))
	{
		handle_setup_request(from);
		stopParsing = true;
		return;
	}

	char arg[3][MAX_LEN];
	str2words(arg[0], msg, 3, MAX_LEN, 0);
	if(!strcmp(arg[0], "qr-op"))
	{
		handle_qr_op(from, msg);
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

static void expire_runtime()
{
	for(std::map<std::string, SetupSession>::iterator it = setup_sessions.begin(); it != setup_sessions.end(); )
	{
		if(it->second.expires_at <= NOW)
			setup_sessions.erase(it++);
		else
			++it;
	}
	for(std::map<std::string, time_t>::iterator lit = lockouts.begin(); lit != lockouts.end(); )
	{
		if(lit->second <= NOW)
			lockouts.erase(lit++);
		else
			++lit;
	}
	for(std::map<std::string, time_t>::iterator rit = setup_request_times.begin(); rit != setup_request_times.end(); )
	{
		if(rit->second + cfg.setup_cooldown <= NOW)
			setup_request_times.erase(rit++);
		else
			++rit;
	}
}

void hook_timer()
{
	expire_runtime();
	flush_outbox();
}

static void status_to_owner(const char *from)
{
	net.sendOwner(from, "QR OTP Status:", NULL);
	net.sendOwner(from, "Module Enabled: ", cfg.enabled ? "ON" : "OFF", NULL);
	net.sendOwner(from, "Issuer: ", cfg.issuer.c_str(), NULL);
	net.sendOwner(from, "Notification Type: ", cfg.notification_type.c_str(), NULL);
	net.sendOwner(from, "Digits: ", itoa(cfg.digits), NULL);
	net.sendOwner(from, "Period: ", itoa(cfg.period), NULL);
	net.sendOwner(from, "Setup TTL: ", itoa(cfg.setup_ttl), NULL);
	net.sendOwner(from, "Setup Cooldown: ", itoa(cfg.setup_cooldown), NULL);
	net.sendOwner(from, "Max Attempts: ", itoa(cfg.max_attempts), NULL);
	net.sendOwner(from, "Lockout Time: ", itoa(cfg.lockout_time), NULL);
	net.sendOwner(from, "QR Line Delay: ", itoa(cfg.qr_line_delay), NULL);
	net.sendOwner(from, "QR Output: ", cfg.qr_output.c_str(), NULL);
	net.sendOwner(from, "QR Library: ", load_qr_api() ? "AVAILABLE" : "MISSING", NULL);
}

static void help_to_owner(const char *from)
{
	net.sendOwner(from, ".qrcode status|enable|disable|help", NULL);
	net.sendOwner(from, ".qrcode set <issuer|notification-type|digits|period|setup-ttl|setup-cooldown|max-attempts|lockout-time|qr-line-delay|qr-output> <value>", NULL);
	net.sendOwner(from, ".qrcode set <handle> enable|disable", NULL);
	net.sendOwner(from, ".qrcode user <handle> show|enable|disable|remove-secret|unlock", NULL);
}

static bool set_config_value(const char *key, const char *value, std::string &err)
{
	int n = atoi(value);
	if(!strcmp(key, "issuer"))
	{
		if(!*value || strlen(value) > 64 || strchr(value, '\r') || strchr(value, '\n')) { err = "invalid issuer"; return false; }
		cfg.issuer = value;
	}
	else if(!strcmp(key, "qr-label"))
		return true;
	else if(!strcmp(key, "notification-type"))
	{
		if(strcmp(value, "text") && strcmp(value, "notice")) { err = "notification-type must be text or notice"; return false; }
		cfg.notification_type = value;
	}
	else if(!strcmp(key, "digits"))
	{
		if(n != 6 && n != 8) { err = "digits must be 6 or 8"; return false; }
		cfg.digits = n;
	}
	else if(!strcmp(key, "period"))
	{
		if(n < 15 || n > 300) { err = "period must be 15..300"; return false; }
		cfg.period = n;
	}
	else if(!strcmp(key, "setup-ttl"))
	{
		if(n < 30 || n > 3600) { err = "setup-ttl must be 30..3600"; return false; }
		cfg.setup_ttl = n;
	}
	else if(!strcmp(key, "setup-cooldown"))
	{
		if(n < 10 || n > 3600) { err = "setup-cooldown must be 10..3600"; return false; }
		cfg.setup_cooldown = n;
	}
	else if(!strcmp(key, "max-attempts"))
	{
		if(n < 1 || n > 10) { err = "max-attempts must be 1..10"; return false; }
		cfg.max_attempts = n;
	}
	else if(!strcmp(key, "lockout-time"))
	{
		if(n < 60 || n > 86400) { err = "lockout-time must be 60..86400"; return false; }
		cfg.lockout_time = n;
	}
	else if(!strcmp(key, "qr-line-delay"))
	{
		if(n < 1 || n > 10) { err = "qr-line-delay must be 1..10"; return false; }
		cfg.qr_line_delay = n;
	}
	else if(!strcmp(key, "qr-output"))
	{
		if(strcmp(value, "manual") && strcmp(value, "compact") && strcmp(value, "full")) { err = "qr-output must be manual, compact or full"; return false; }
		cfg.qr_output = value;
	}
	else
	{
		err = "unknown setting";
		return false;
	}
	return true;
}

static void user_show(const char *from, const char *handle)
{
	HANDLE *h = userlist.findHandle(handle);
	if(!h)
	{
		net.sendOwner(from, "Unknown handle", NULL);
		return;
	}
	QrOtpUser &u = users[handle];
	bool locked = false;
	std::string prefix = std::string(handle) + "|";
	for(std::map<std::string, time_t>::iterator it = lockouts.begin(); it != lockouts.end(); ++it)
		if(!strncmp(it->first.c_str(), prefix.c_str(), prefix.size()) && it->second > NOW)
			locked = true;

	net.sendOwner(from, "QR OTP User: ", handle, NULL);
	net.sendOwner(from, "Allowed: ", u.allowed ? "YES" : "NO", NULL);
	net.sendOwner(from, "Status: ", u.enabled ? "ENABLED" : "DISABLED", NULL);
	net.sendOwner(from, "Secret: ", u.secret.empty() ? "(not set)" : "********", NULL);
	net.sendOwner(from, "Locked: ", locked ? "YES" : "NO", NULL);
}

static void user_enable(const char *from, const char *handle)
{
	HANDLE *h = userlist.findHandle(handle);
	if(!h)
	{
		net.sendOwner(from, "Unknown handle", NULL);
		return;
	}
	QrOtpUser &u = users[handle];
	u.allowed = true;
	if(!u.secret.empty())
		u.enabled = true;
	qrcode_save();
	net.sendOwner(from, u.secret.empty() ? "QR setup allowed for " : "QR OTP enabled for ", handle, NULL);
}

static void user_disable(const char *from, const char *handle)
{
	HANDLE *h = userlist.findHandle(handle);
	if(!h)
	{
		net.sendOwner(from, "Unknown handle", NULL);
		return;
	}
	QrOtpUser &u = users[handle];
	u.enabled = false;
	clear_runtime_for_handle(handle);
	qrcode_save();
	net.sendOwner(from, "QR OTP disabled for ", handle, "; secret kept", NULL);
}

static void user_command(const char *from, char arg[10][MAX_LEN])
{
	const char *handle = arg[1];
	const char *action = arg[2];
	if(!strlen(handle) || !strlen(action))
	{
		net.sendOwner(from, "Syntax: .qrcode user <handle> show|enable|disable|remove-secret|unlock", NULL);
		return;
	}
	if(!strcmp(action, "show"))
		user_show(from, handle);
	else if(!strcmp(action, "enable"))
		user_enable(from, handle);
	else if(!strcmp(action, "disable"))
		user_disable(from, handle);
	else if(!strcmp(action, "remove-secret"))
	{
		HANDLE *h = userlist.findHandle(handle);
		if(!h)
		{
			net.sendOwner(from, "Unknown handle", NULL);
			return;
		}
			QrOtpUser &u = users[handle];
			u.secret.clear();
			u.enabled = false;
			clear_runtime_for_handle(handle);
			qrcode_save();
			net.sendOwner(from, "QR OTP secret removed for ", handle, "; account disabled", NULL);
		}
		else if(!strcmp(action, "unlock"))
		{
			clear_runtime_for_handle(handle);
			net.send(HAS_N, "[qrcode-otp] OTP manually unlocked for ", handle, NULL);
			net.sendOwner(from, "QR OTP unlocked for ", handle, NULL);
		}
	else
		net.sendOwner(from, "Unknown user command", NULL);
}

void hook_partylineCmd(const char *from, int flags, const char *cmd, const char *args)
{
	if(strcmp(cmd, ".qrcode"))
		return;
	stopParsing = true;

	if(!(flags & HAS_N))
	{
		net.sendOwner(from, "No permission", NULL);
		return;
	}

	char arg[10][MAX_LEN];
	str2words(arg[0], args ? args : "", 10, MAX_LEN, 0);

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
		qrcode_save();
		net.sendOwner(from, "QR OTP module enabled", NULL);
		return;
	}
		if(!strcmp(arg[0], "disable"))
		{
			cfg.enabled = false;
			setup_sessions.clear();
			setup_request_times.clear();
			failures.clear();
			lockouts.clear();
			last_totp_counters.clear();
			outbox.clear();
			qrcode_save();
			net.sendOwner(from, "QR OTP module disabled", NULL);
			return;
	}
	if(!strcmp(arg[0], "set"))
	{
		if(strlen(arg[1]) && strlen(arg[2]) && (!strcmp(arg[2], "enable") || !strcmp(arg[2], "disable")) && userlist.findHandle(arg[1]))
		{
			if(!strcmp(arg[2], "enable"))
				user_enable(from, arg[1]);
			else
				user_disable(from, arg[1]);
			return;
		}

		char *value = srewind(args, 2);
		if(!strlen(arg[1]) || !value || !*value)
		{
			net.sendOwner(from, "Syntax: .qrcode set <key> <value>", NULL);
			return;
		}
		std::string err;
		if(!set_config_value(arg[1], value, err))
		{
			net.sendOwner(from, err.c_str(), NULL);
			return;
		}
		qrcode_save();
		net.sendOwner(from, "Setting updated", NULL);
		return;
	}
	if(!strcmp(arg[0], "user"))
	{
		user_command(from, arg);
		return;
	}

	net.sendOwner(from, "Unknown qrcode command", NULL);
}

static void qrcode_load()
{
	FILE *fh = fopen(QRCODE_OTP_CFG_FILE, "r");
	if(!fh)
		return;

	char buffer[MAX_LEN];
	char arg[10][MAX_LEN];
	int line = 0;
	while(fgets(buffer, sizeof(buffer), fh))
	{
		line++;
		buffer[strcspn(buffer, "\r\n")] = '\0';
		str2words(arg[0], buffer, 10, MAX_LEN, 0);
		if(!strlen(arg[0]) || arg[0][0] == '#')
			continue;
		if(!strcmp(arg[0], "set"))
		{
			char *value = srewind(buffer, 2);
			std::string err;
			if(!strcmp(arg[1], "module-enabled"))
			{
				bool b;
				if(parse_bool_value(value ? value : "", b))
					cfg.enabled = b;
			}
			else if(value && !set_config_value(arg[1], value, err))
				printf("[-] %s:%d: %s\n", QRCODE_OTP_CFG_FILE, line, err.c_str());
		}
		else if(!strcmp(arg[0], "user"))
		{
			if(!strlen(arg[1]) || !strlen(arg[2]))
				continue;
			QrOtpUser &u = users[arg[1]];
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
					else
					{
						u.secret.clear();
						u.enabled = false;
						printf("[-] %s:%d: ignored weak or invalid TOTP secret for %s\n", QRCODE_OTP_CFG_FILE, line, arg[1]);
					}
				}
		}
	}
	fclose(fh);
}

static void qrcode_save()
{
	FILE *fh = fopen(QRCODE_OTP_CFG_FILE, "w");
	if(!fh)
	{
		net.send(HAS_N, "[qrcode-otp] cannot open ", QRCODE_OTP_CFG_FILE, " for writing: ", strerror(errno), NULL);
		return;
	}
	chmod(QRCODE_OTP_CFG_FILE, S_IRUSR | S_IWUSR);

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

	for(std::map<std::string, QrOtpUser>::iterator it = users.begin(); it != users.end(); ++it)
	{
		fprintf(fh, "user %s allowed %s\n", it->first.c_str(), it->second.allowed ? "ON" : "OFF");
		fprintf(fh, "user %s enabled %s\n", it->first.c_str(), it->second.enabled ? "ON" : "OFF");
		if(!it->second.secret.empty())
			fprintf(fh, "user %s secret %s\n", it->first.c_str(), it->second.secret.c_str());
	}

	fclose(fh);
}

void hook_userlistLoaded()
{
	users.clear();
	qrcode_load();
}

module *init()
{
	module_info = new module(QRCODE_OTP_MODULE, "OpenAI Codex", "0.1");
	module_info->hooks->privmsg = hook_privmsg;
	module_info->hooks->partylineCmd = hook_partylineCmd;
	module_info->hooks->timer = hook_timer;
	module_info->hooks->userlistLoaded = hook_userlistLoaded;

	if(userlist.SN)
		hook_userlistLoaded();

	return module_info;
}

void destroy()
{
	if(qrapi.lib)
	{
		dlclose(qrapi.lib);
		memset(&qrapi, 0, sizeof(qrapi));
	}
}

} // namespace qrcode_otp

static module *otpsec_info = NULL;
static module *emailotp_mod = NULL;
static module *qrcodeotp_mod = NULL;

static void otpsec_help(const char *from)
{
	net.sendOwner(from, "Welcome to OTP Security for Evangeline", NULL);
	net.sendOwner(from, "Email OTP and Authenticator OTP Support for OP mode users", NULL);
	net.sendOwner(from, "OTP Security module commands:", NULL);
	net.sendOwner(from, ".otp help", NULL);
	net.sendOwner(from, ".otp status", NULL);
	net.sendOwner(from, ".otp email <email-otp command args>", NULL);
	net.sendOwner(from, ".otp qr <qrcode command args>", NULL);
	net.sendOwner(from, "Direct commands", NULL);
	if(emailotp_mod && emailotp_mod->hooks->partylineCmd)
		emailotp_mod->hooks->partylineCmd(from, HAS_N, ".email-otp", "help");
	stopParsing = false;
	if(qrcodeotp_mod && qrcodeotp_mod->hooks->partylineCmd)
		qrcodeotp_mod->hooks->partylineCmd(from, HAS_N, ".qrcode", "help");
	stopParsing = true;
}

static void otpsec_status(const char *from)
{
	net.sendOwner(from, "OTP Security Status:", NULL);
	if(emailotp_mod && emailotp_mod->hooks->partylineCmd)
		emailotp_mod->hooks->partylineCmd(from, HAS_N, ".email-otp", "status");
	stopParsing = false;
	if(qrcodeotp_mod && qrcodeotp_mod->hooks->partylineCmd)
		qrcodeotp_mod->hooks->partylineCmd(from, HAS_N, ".qrcode", "status");
	stopParsing = true;
}

static void otpsec_privmsg(const char *from, const char *to, const char *msg)
{
	if(emailotp_mod && emailotp_mod->hooks->privmsg)
		emailotp_mod->hooks->privmsg(from, to, msg);
	if(stopParsing)
		return;
	if(qrcodeotp_mod && qrcodeotp_mod->hooks->privmsg)
		qrcodeotp_mod->hooks->privmsg(from, to, msg);
}

static void otpsec_partylineCmd(const char *from, int flags, const char *cmd, const char *args)
{
	if(!strcmp(cmd, ".otp"))
	{
		stopParsing = true;
		if(!(flags & HAS_N))
		{
			net.sendOwner(from, "No permission", NULL);
			return;
		}

		char arg[4][MAX_LEN];
		str2words(arg[0], args ? args : "", 4, MAX_LEN, 0);
		if(!strlen(arg[0]) || !strcmp(arg[0], "help"))
		{
			otpsec_help(from);
			return;
		}
		if(!strcmp(arg[0], "status"))
		{
			otpsec_status(from);
			return;
		}
		if(!strcmp(arg[0], "email"))
		{
			const char *subargs = srewind(args ? args : "", 1);
			if(emailotp_mod && emailotp_mod->hooks->partylineCmd)
				emailotp_mod->hooks->partylineCmd(from, flags, ".email-otp", subargs ? subargs : "");
			stopParsing = true;
			return;
		}
		if(!strcmp(arg[0], "qr") || !strcmp(arg[0], "qrcode"))
		{
			const char *subargs = srewind(args ? args : "", 1);
			if(qrcodeotp_mod && qrcodeotp_mod->hooks->partylineCmd)
				qrcodeotp_mod->hooks->partylineCmd(from, flags, ".qrcode", subargs ? subargs : "");
			stopParsing = true;
			return;
		}
		net.sendOwner(from, "Unknown .otp command. Try .otp help", NULL);
		return;
	}

	if(emailotp_mod && emailotp_mod->hooks->partylineCmd)
		emailotp_mod->hooks->partylineCmd(from, flags, cmd, args);
	if(stopParsing)
		return;
	if(qrcodeotp_mod && qrcodeotp_mod->hooks->partylineCmd)
		qrcodeotp_mod->hooks->partylineCmd(from, flags, cmd, args);
}

static void otpsec_timer()
{
	if(emailotp_mod && emailotp_mod->hooks->timer)
		emailotp_mod->hooks->timer();
	if(qrcodeotp_mod && qrcodeotp_mod->hooks->timer)
		qrcodeotp_mod->hooks->timer();
}

static void otpsec_userlistLoaded()
{
	if(emailotp_mod && emailotp_mod->hooks->userlistLoaded)
		emailotp_mod->hooks->userlistLoaded();
	if(qrcodeotp_mod && qrcodeotp_mod->hooks->userlistLoaded)
		qrcodeotp_mod->hooks->userlistLoaded();
}

extern "C" module *init()
{
	emailotp_mod = email_otp::init();
	qrcodeotp_mod = qrcode_otp::init();

	otpsec_info = new module("otp-sec", "OpenAI Codex", "0.1");
	otpsec_info->hooks->privmsg = otpsec_privmsg;
	otpsec_info->hooks->partylineCmd = otpsec_partylineCmd;
	otpsec_info->hooks->timer = otpsec_timer;
	otpsec_info->hooks->userlistLoaded = otpsec_userlistLoaded;
	return otpsec_info;
}

extern "C" void destroy()
{
	qrcode_otp::destroy();
	email_otp::destroy();
}
