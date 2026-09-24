#include "../prots.h"
#include "../global-var.h"

#include <sys/stat.h>
#include <dlfcn.h>
#include <pthread.h>

#include <deque>
#include <map>
#include <string>
#include <vector>

#define METEO_CFG_FILE "meteo.txt"

typedef void CURL;
typedef int CURLcode;

#define CURLE_OK 0
#define CURL_GLOBAL_DEFAULT 3
#define CURLOPTTYPE_LONG 0
#define CURLOPTTYPE_OBJECTPOINT 10000
#define CURLOPTTYPE_FUNCTIONPOINT 20000
#define CURLOPT_URL (CURLOPTTYPE_OBJECTPOINT + 2)
#define CURLOPT_WRITEDATA (CURLOPTTYPE_OBJECTPOINT + 1)
#define CURLOPT_WRITEFUNCTION (CURLOPTTYPE_FUNCTIONPOINT + 11)
#define CURLOPT_TIMEOUT (CURLOPTTYPE_LONG + 13)
#define CURLOPT_CONNECTTIMEOUT (CURLOPTTYPE_LONG + 78)
#define CURLOPT_FOLLOWLOCATION (CURLOPTTYPE_LONG + 52)
#define CURLOPT_USERAGENT (CURLOPTTYPE_OBJECTPOINT + 18)
#define CURLOPT_NOSIGNAL (CURLOPTTYPE_LONG + 99)
#define CURLINFO_LONG 0x200000
#define CURLINFO_RESPONSE_CODE (CURLINFO_LONG + 2)

struct MeteoConfig
{
	bool enabled;
	std::string language;
	int timeout;
	int cooldown;
	int max_queue;

	MeteoConfig() : enabled(true), language("it"), timeout(10), cooldown(10), max_queue(20) { }
};

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

	CurlApi() : lib(NULL), global_init(NULL), global_cleanup(NULL), easy_init(NULL),
		easy_setopt(NULL), easy_perform(NULL), easy_getinfo(NULL), easy_cleanup(NULL),
		easy_strerror(NULL) { }
};

struct HttpResponse
{
	std::string body;
};

struct MeteoJob
{
	std::string nick;
	std::string target;
	std::string city;
	bool channel;
};

struct MeteoResult
{
	std::string nick;
	std::string target;
	bool channel;
	bool ok;
	std::string text;
};

static module *module_info = NULL;
static MeteoConfig cfg;
static CurlApi curlapi;
static pthread_t worker_thread;
static pthread_mutex_t meteo_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t meteo_cond = PTHREAD_COND_INITIALIZER;
static bool worker_started = false;
static bool worker_shutdown = false;
static std::deque<MeteoJob> jobs;
static std::deque<MeteoResult> results;
static std::map<std::string, time_t> cooldowns;

static void meteo_save();
static void meteo_load();

static std::string nick_from_mask(const char *mask)
{
	const char *bang = strchr(mask, '!');
	if(!bang)
		return std::string(mask);
	return std::string(mask, bang - mask);
}

static std::string trim(const std::string &s)
{
	size_t b = 0;
	while(b < s.size() && isspace((unsigned char)s[b]))
		++b;
	size_t e = s.size();
	while(e > b && isspace((unsigned char)s[e - 1]))
		--e;
	return s.substr(b, e - b);
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

	if(!curlapi.global_init || !curlapi.global_cleanup || !curlapi.easy_init ||
		!curlapi.easy_setopt || !curlapi.easy_perform || !curlapi.easy_getinfo ||
		!curlapi.easy_cleanup || !curlapi.easy_strerror)
	{
		dlclose(curlapi.lib);
		memset(&curlapi, 0, sizeof(curlapi));
		return false;
	}
	return true;
}

static size_t http_write_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
	size_t total = size * nmemb;
	HttpResponse *resp = (HttpResponse *)userdata;
	if(resp->body.size() + total > 1024 * 1024)
		return 0;
	resp->body.append(ptr, total);
	return total;
}

static bool http_get(const std::string &url, std::string &body, std::string &error)
{
	CURL *curl = curlapi.easy_init();
	if(!curl)
	{
		error = "curl init failed";
		return false;
	}

	HttpResponse resp;
	curlapi.easy_setopt(curl, CURLOPT_URL, url.c_str());
	curlapi.easy_setopt(curl, CURLOPT_WRITEFUNCTION, http_write_cb);
	curlapi.easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
	curlapi.easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
	curlapi.easy_setopt(curl, CURLOPT_TIMEOUT, (long)cfg.timeout);
	curlapi.easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
	curlapi.easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
	curlapi.easy_setopt(curl, CURLOPT_USERAGENT, "evangeline-meteo/1.0");

	CURLcode rc = curlapi.easy_perform(curl);
	long response = 0;
	curlapi.easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response);
	curlapi.easy_cleanup(curl);

	if(rc != CURLE_OK)
	{
		error = curlapi.easy_strerror(rc);
		return false;
	}
	if(response >= 400 || response == 0)
	{
		char buf[80];
		snprintf(buf, sizeof(buf), "HTTP response code %ld", response);
		error = buf;
		return false;
	}
	body = resp.body;
	return !body.empty();
}

static std::string url_encode(const std::string &in, bool plus_space)
{
	static const char hex[] = "0123456789ABCDEF";
	std::string out;
	for(size_t i = 0; i < in.size(); ++i)
	{
		unsigned char c = (unsigned char)in[i];
		if((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~')
			out += c;
		else if(c == ' ' && plus_space)
			out += '+';
		else
		{
			out += '%';
			out += hex[c >> 4];
			out += hex[c & 15];
		}
	}
	return out;
}

static bool json_string_after(const std::string &json, size_t start, const char *key, std::string &out)
{
	std::string needle = std::string("\"") + key + "\"";
	size_t p = json.find(needle, start);
	if(p == std::string::npos)
		return false;
	p = json.find(':', p + needle.size());
	if(p == std::string::npos)
		return false;
	p = json.find('"', p + 1);
	if(p == std::string::npos)
		return false;
	size_t e = p + 1;
	out.clear();
	bool esc = false;
	for(; e < json.size(); ++e)
	{
		char c = json[e];
		if(esc)
		{
			out += c;
			esc = false;
			continue;
		}
		if(c == '\\')
		{
			esc = true;
			continue;
		}
		if(c == '"')
			return true;
		out += c;
	}
	return false;
}

static bool json_number_after(const std::string &json, size_t start, const char *key, std::string &out)
{
	std::string needle = std::string("\"") + key + "\"";
	size_t search = start;
	while(true)
	{
		size_t p = json.find(needle, search);
		if(p == std::string::npos)
			return false;
		search = p + needle.size();
		p = json.find(':', search);
		if(p == std::string::npos)
			return false;
		++p;
		while(p < json.size() && isspace((unsigned char)json[p]))
			++p;
		bool quoted = false;
		if(p < json.size() && json[p] == '"')
		{
			quoted = true;
			++p;
		}
		if(p >= json.size() || (!isdigit((unsigned char)json[p]) && json[p] != '-' && json[p] != '.'))
			continue;
		size_t e = p;
		while(e < json.size() && (isdigit((unsigned char)json[e]) || json[e] == '-' || json[e] == '.'))
			++e;
		if(e == p)
			continue;
		if(quoted && (e >= json.size() || json[e] != '"'))
			continue;
		out = json.substr(p, e - p);
		return true;
	}
}

static bool json_value_in_array(const std::string &json, const char *key, std::string &out)
{
	std::string needle = std::string("\"") + key + "\"";
	size_t p = json.find(needle);
	if(p == std::string::npos)
		return false;
	size_t end = json.find(']', p);
	if(end == std::string::npos)
		end = json.size();
	std::string segment = json.substr(p, end - p);
	return json_string_after(segment, 0, "value", out);
}

static bool json_int_after(const std::string &json, size_t start, const char *key, int &out)
{
	std::string s;
	if(!json_number_after(json, start, key, s))
		return false;
	out = atoi(s.c_str());
	return true;
}

static std::string weather_code_it(int code)
{
	switch(code)
	{
		case 0: return "sereno";
		case 1: return "prevalentemente sereno";
		case 2: return "parzialmente nuvoloso";
		case 3: return "nuvoloso";
		case 45: return "nebbia";
		case 48: return "nebbia con brina";
		case 51: return "pioviggine leggera";
		case 53: return "pioviggine";
		case 55: return "pioviggine intensa";
		case 61: return "pioggia leggera";
		case 63: return "pioggia";
		case 65: return "pioggia intensa";
		case 71: return "neve leggera";
		case 73: return "neve";
		case 75: return "neve intensa";
		case 80: return "rovesci leggeri";
		case 81: return "rovesci";
		case 82: return "rovesci intensi";
		case 95: return "temporale";
		case 96: return "temporale con grandine";
		case 99: return "temporale con grandine intensa";
	}
	return "n/a";
}

static bool parse_wttr(const std::string &json, const std::string &fallback_city, std::string &reply)
{
	std::string city = fallback_city, country = "??", desc = "n/a";
	std::string temp = "n/a", feels = "n/a", humidity = "n/a", wind_kmph = "n/a";

	json_value_in_array(json, "areaName", city);
	json_value_in_array(json, "country", country);
	json_value_in_array(json, "lang_it", desc);
	if(desc == "n/a")
		json_value_in_array(json, "weatherDesc", desc);
	json_number_after(json, 0, "temp_C", temp);
	json_number_after(json, 0, "FeelsLikeC", feels);
	json_number_after(json, 0, "humidity", humidity);
	json_number_after(json, 0, "windspeedKmph", wind_kmph);

	double wind_ms = atof(wind_kmph.c_str()) / 3.6;
	char wind[32];
	if(wind_kmph != "n/a")
		snprintf(wind, sizeof(wind), "%.1f", wind_ms);
	else
		snprintf(wind, sizeof(wind), "n/a");

	reply = "Meteo " + city + ", " + country + ": " + desc +
		" | Temp: " + temp + " C (percepiti " + feels + " C)" +
		" | Umidita: " + humidity + "% | Vento: " + wind + " m/s";
	return temp != "n/a";
}

static bool fetch_wttr(const std::string &city, std::string &reply, std::string &error)
{
	std::string body;
	std::string url = "https://wttr.in/" + url_encode(city, false) + "?format=j1&lang=" + url_encode(cfg.language, false);
	if(!http_get(url, body, error))
		return false;
	return parse_wttr(body, city, reply);
}

static bool fetch_openmeteo(const std::string &city, std::string &reply, std::string &error)
{
	std::string geo;
	std::string gurl = "https://geocoding-api.open-meteo.com/v1/search?name=" +
		url_encode(city, false) + "&count=1&language=" + url_encode(cfg.language, false) + "&format=json";
	if(!http_get(gurl, geo, error))
		return false;

	std::string lat, lon, name = city, country = "??";
	if(!json_number_after(geo, 0, "latitude", lat) || !json_number_after(geo, 0, "longitude", lon))
	{
		error = "city not found";
		return false;
	}
	json_string_after(geo, 0, "name", name);
	json_string_after(geo, 0, "country_code", country);

	std::string weather;
	std::string wurl = "https://api.open-meteo.com/v1/forecast?latitude=" + lat +
		"&longitude=" + lon +
		"&current=temperature_2m,apparent_temperature,relative_humidity_2m,wind_speed_10m,weather_code&timezone=auto";
	if(!http_get(wurl, weather, error))
		return false;

	std::string temp = "n/a", feels = "n/a", humidity = "n/a", wind_kmh = "n/a";
	int code = -1;
	json_number_after(weather, 0, "temperature_2m", temp);
	json_number_after(weather, 0, "apparent_temperature", feels);
	json_number_after(weather, 0, "relative_humidity_2m", humidity);
	json_number_after(weather, 0, "wind_speed_10m", wind_kmh);
	json_int_after(weather, 0, "weather_code", code);

	double wind_ms = atof(wind_kmh.c_str()) / 3.6;
	char wind[32];
	if(wind_kmh != "n/a")
		snprintf(wind, sizeof(wind), "%.1f", wind_ms);
	else
		snprintf(wind, sizeof(wind), "n/a");

	reply = "Meteo " + name + ", " + country + ": " + weather_code_it(code) +
		" | Temp: " + temp + " C (percepiti " + feels + " C)" +
		" | Umidita: " + humidity + "% | Vento: " + wind + " m/s";
	return temp != "n/a";
}

static std::string fetch_meteo(const std::string &city)
{
	std::string reply, error1, error2;
	if(fetch_wttr(city, reply, error1))
		return reply;
	if(fetch_openmeteo(city, reply, error2))
		return reply;
	net.send(HAS_N, "[meteo] wttr failed for ", city.c_str(), ": ", error1.c_str(), "; open-meteo: ", error2.c_str(), NULL);
	return "Impossibile contattare il servizio meteo.";
}

static void *meteo_worker(void *)
{
	while(true)
	{
		pthread_mutex_lock(&meteo_mutex);
		while(jobs.empty() && !worker_shutdown)
			pthread_cond_wait(&meteo_cond, &meteo_mutex);
		if(worker_shutdown && jobs.empty())
		{
			pthread_mutex_unlock(&meteo_mutex);
			break;
		}
		MeteoJob job = jobs.front();
		jobs.pop_front();
		pthread_mutex_unlock(&meteo_mutex);

		MeteoResult res;
		res.nick = job.nick;
		res.target = job.target;
		res.channel = job.channel;
		res.ok = true;
		res.text = fetch_meteo(job.city);

		pthread_mutex_lock(&meteo_mutex);
		results.push_back(res);
		pthread_mutex_unlock(&meteo_mutex);
	}
	return NULL;
}

static bool ensure_worker()
{
	if(worker_started)
		return true;
	if(!load_curl_api())
		return false;
	if(curlapi.global_init(CURL_GLOBAL_DEFAULT) != 0)
		return false;
	worker_shutdown = false;
	if(pthread_create(&worker_thread, NULL, meteo_worker, NULL) != 0)
		return false;
	worker_started = true;
	return true;
}

static void send_reply(const MeteoResult &res)
{
	if(res.channel)
		ME.privmsg(res.target.c_str(), res.text.c_str(), NULL);
	else
		ME.privmsg(res.nick.c_str(), res.text.c_str(), NULL);
}

static void flush_results()
{
	std::deque<MeteoResult> local;
	pthread_mutex_lock(&meteo_mutex);
	local.swap(results);
	pthread_mutex_unlock(&meteo_mutex);

	for(size_t i = 0; i < local.size(); ++i)
		send_reply(local[i]);
}

static bool queue_job(const std::string &nick, const std::string &target, bool channel, const std::string &city)
{
	if(!ensure_worker())
		return false;

	MeteoJob job;
	job.nick = nick;
	job.target = target;
	job.channel = channel;
	job.city = city;

	pthread_mutex_lock(&meteo_mutex);
	if((int)jobs.size() >= cfg.max_queue)
	{
		pthread_mutex_unlock(&meteo_mutex);
		return false;
	}
	jobs.push_back(job);
	pthread_cond_signal(&meteo_cond);
	pthread_mutex_unlock(&meteo_mutex);
	return true;
}

static void hook_meteo_request(const char *from, const char *to, const char *msg)
{
	if(strncmp(msg, "!meteo", 6))
		return;
	if(msg[6] && !isspace((unsigned char)msg[6]))
		return;

	std::string nick = nick_from_mask(from);
	bool channel = chan::isChannel(to);
	if(channel)
	{
		chan *ch = ME.findChannel(to);
		if(!ch || !ch->getUser(from))
			return;
	}
	else if(strcmp(to, ME.nick))
		return;

	std::string city = trim(msg + 6);
	if(city.empty())
	{
		if(channel)
			ME.privmsg(to, nick.c_str(), ": uso: !meteo <citta>", NULL);
		else
			ME.privmsg(nick.c_str(), "Uso: !meteo <citta>", NULL);
		stopParsing = true;
		return;
	}
	if(city.size() > 96 || city.find('\r') != std::string::npos || city.find('\n') != std::string::npos)
	{
		ME.privmsg(channel ? to : nick.c_str(), "Citta non valida.", NULL);
		stopParsing = true;
		return;
	}
	if(!cfg.enabled)
	{
		ME.privmsg(channel ? to : nick.c_str(), "Modulo meteo disabilitato.", NULL);
		stopParsing = true;
		return;
	}

	std::string ckey = std::string(from) + "|" + city;
	if(cooldowns.find(ckey) != cooldowns.end() && cooldowns[ckey] + cfg.cooldown > NOW)
	{
		ME.privmsg(channel ? to : nick.c_str(), "Aspetta prima di richiedere di nuovo il meteo.", NULL);
		stopParsing = true;
		return;
	}
	cooldowns[ckey] = NOW;

	if(!queue_job(nick, channel ? std::string(to) : nick, channel, city))
		ME.privmsg(channel ? to : nick.c_str(), "Servizio meteo momentaneamente occupato.", NULL);
	stopParsing = true;
}

void hook_privmsg(const char *from, const char *to, const char *msg)
{
	hook_meteo_request(from, to, msg);
}

static void expire_runtime()
{
	for(std::map<std::string, time_t>::iterator it = cooldowns.begin(); it != cooldowns.end(); )
	{
		if(it->second + cfg.cooldown <= NOW)
			cooldowns.erase(it++);
		else
			++it;
	}
}

void hook_timer()
{
	expire_runtime();
	flush_results();
}

static void status_to_owner(const char *from)
{
	net.sendOwner(from, "Meteo Status:", NULL);
	net.sendOwner(from, "Module Enabled: ", cfg.enabled ? "ON" : "OFF", NULL);
	net.sendOwner(from, "Language: ", cfg.language.c_str(), NULL);
	net.sendOwner(from, "Timeout: ", itoa(cfg.timeout), NULL);
	net.sendOwner(from, "Cooldown: ", itoa(cfg.cooldown), NULL);
	net.sendOwner(from, "Max Queue: ", itoa(cfg.max_queue), NULL);
	net.sendOwner(from, "libcurl: ", load_curl_api() ? "AVAILABLE" : "MISSING", NULL);
}

static void help_to_owner(const char *from)
{
	net.sendOwner(from, ".meteo status|enable|disable|help", NULL);
	net.sendOwner(from, ".meteo set <language|timeout|cooldown|max-queue> <value>", NULL);
	net.sendOwner(from, "IRC command: !meteo <citta>", NULL);
	net.sendOwner(from, "Services: wttr.in with Open-Meteo fallback, no API key required", NULL);
}

static bool set_config_value(const char *key, const char *value, std::string &err)
{
	int n = atoi(value);
	if(!strcmp(key, "language"))
	{
		if(!*value || strlen(value) > 8 || strchr(value, '\r') || strchr(value, '\n')) { err = "invalid language"; return false; }
		cfg.language = value;
	}
	else if(!strcmp(key, "timeout"))
	{
		if(n < 3 || n > 30) { err = "timeout must be 3..30"; return false; }
		cfg.timeout = n;
	}
	else if(!strcmp(key, "cooldown"))
	{
		if(n < 0 || n > 300) { err = "cooldown must be 0..300"; return false; }
		cfg.cooldown = n;
	}
	else if(!strcmp(key, "max-queue"))
	{
		if(n < 1 || n > 100) { err = "max-queue must be 1..100"; return false; }
		cfg.max_queue = n;
	}
	else
	{
		err = "unknown setting";
		return false;
	}
	return true;
}

void hook_partylineCmd(const char *from, int flags, const char *cmd, const char *args)
{
	if(strcmp(cmd, ".meteo"))
		return;
	stopParsing = true;

	if(!(flags & HAS_N))
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
		meteo_save();
		net.sendOwner(from, "Meteo module enabled", NULL);
		return;
	}
	if(!strcmp(arg[0], "disable"))
	{
		cfg.enabled = false;
		meteo_save();
		net.sendOwner(from, "Meteo module disabled", NULL);
		return;
	}
	if(!strcmp(arg[0], "set"))
	{
		char *value = srewind(args ? args : "", 2);
		if(!strlen(arg[1]) || !value || !*value)
		{
			net.sendOwner(from, "Syntax: .meteo set <key> <value>", NULL);
			return;
		}
		std::string err;
		if(!set_config_value(arg[1], value, err))
		{
			net.sendOwner(from, err.c_str(), NULL);
			return;
		}
		meteo_save();
		net.sendOwner(from, "Meteo setting updated", NULL);
		return;
	}
	net.sendOwner(from, "Unknown meteo command", NULL);
}

static void meteo_load()
{
	FILE *fh = fopen(METEO_CFG_FILE, "r");
	if(!fh)
		return;

	char buffer[MAX_LEN];
	char arg[8][MAX_LEN];
	int line = 0;
	while(fgets(buffer, sizeof(buffer), fh))
	{
		line++;
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
			else
			{
				std::string err;
				if(value && !set_config_value(arg[1], value, err))
					printf("[-] %s:%d: %s\n", METEO_CFG_FILE, line, err.c_str());
			}
		}
	}
	fclose(fh);
}

static void meteo_save()
{
	FILE *fh = fopen(METEO_CFG_FILE, "w");
	if(!fh)
	{
		net.send(HAS_N, "[meteo] cannot open ", METEO_CFG_FILE, " for writing: ", strerror(errno), NULL);
		return;
	}
	chmod(METEO_CFG_FILE, S_IRUSR | S_IWUSR);
	fprintf(fh, "set module-enabled %s\n", cfg.enabled ? "ON" : "OFF");
	fprintf(fh, "set language %s\n", cfg.language.c_str());
	fprintf(fh, "set timeout %d\n", cfg.timeout);
	fprintf(fh, "set cooldown %d\n", cfg.cooldown);
	fprintf(fh, "set max-queue %d\n", cfg.max_queue);
	fclose(fh);
}

extern "C" module *init()
{
	module_info = new module("meteo", "OpenAI Codex", "1.0");
	module_info->hooks->privmsg = hook_privmsg;
	module_info->hooks->partylineCmd = hook_partylineCmd;
	module_info->hooks->timer = hook_timer;
	meteo_load();
	return module_info;
}

extern "C" void destroy()
{
	if(worker_started)
	{
		pthread_mutex_lock(&meteo_mutex);
		worker_shutdown = true;
		pthread_cond_signal(&meteo_cond);
		pthread_mutex_unlock(&meteo_mutex);
		pthread_join(worker_thread, NULL);
		if(curlapi.global_cleanup)
			curlapi.global_cleanup();
		if(curlapi.lib)
			dlclose(curlapi.lib);
		memset(&curlapi, 0, sizeof(curlapi));
		worker_started = false;
	}
}
