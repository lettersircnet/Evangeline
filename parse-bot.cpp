/***************************************************************************
 *   Copyright (C) 2003-2005 by Grzegorz Rusin                             *
 *   grusin@gmail.com                                                      *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
 ***************************************************************************/

#include "prots.h"
#include "global-var.h"
#include <dlfcn.h>

static char arg[10][MAX_LEN];
static char *reason;

static void normalize_fastlogin_code(const char *in, char out[MAX_LEN])
{
	size_t i = 0;
	while(in[i] && in[i] != '\r' && in[i] != '\n' && !isspace((unsigned char)in[i]) && i < MAX_LEN - 1)
	{
		out[i] = in[i];
		++i;
	}
	out[i] = '\0';
}

static HANDLE *try_fastlogin_modules(const char *handle, const char *code, const char *peer)
{
#ifdef HAVE_MODULES
	typedef HANDLE *(*FastLoginFn)(const char *, const char *, const char *);
	ptrlist<module>::iterator mi = modules.begin();
	while(mi)
	{
		if(mi->handle)
		{
			FastLoginFn fastLogin = (FastLoginFn)dlsym(mi->handle, "fastLogin");
			if(fastLogin)
			{
				HANDLE *h = fastLogin(handle, code, peer);
				if(h)
					return h;
			}
		}
		mi++;
	}
#endif
	return NULL;
}

static const char *fastlogin_error_from_modules(const char *peer)
{
#ifdef HAVE_MODULES
	typedef const char *(*FastLoginErrorFn)(const char *);
	ptrlist<module>::iterator mi = modules.begin();
	while(mi)
	{
		if(mi->handle)
		{
			FastLoginErrorFn fastLoginError = (FastLoginErrorFn)dlsym(mi->handle, "fastLoginError");
			if(fastLoginError)
			{
				const char *error = fastLoginError(peer);
				if(error && *error)
					return error;
			}
		}
		mi++;
	}
#endif
	return "FastLogin failed: module is not loaded";
}

static void send_fastlogin_error_now(inetconn *c, const char *error)
{
	if(!c || c->fd < 1 || !error)
		return;

	char buf[MAX_LEN];
	snprintf(buf, sizeof(buf), "%s\n", error);
#ifdef HAVE_SSL
	if(c->isSSL())
		SSL_write(c->ssl, buf, strlen(buf));
	else
#endif
		write(c->fd, buf, strlen(buf));
}

static bool finish_fastlogin(inetconn *c, HANDLE *h)
{
	if(!h || !(h->flags[GLOBAL] & HAS_P) || userlist.isBot(h))
		return false;

	if(set.TELNET_OWNERS == 2)
	{
		char buf[MAX_LEN];
		snprintf(buf, MAX_LEN, "*!*@%s", c->getPeerIpName());
		if(userlist.wildFindHostExt(h, buf) == -1)
			return false;
	}

	c->status |= STATUS_CONNECTED | STATUS_PARTY | STATUS_REGISTERED | STATUS_TELNET;
	c->status &= ~STATUS_BOT;
	c->tmpint = 0;
	c->killTime = 0;
	c->handle = h;
	mem_strcpy(c->name, h->name);
	if(c->tmpstr)
	{
		free(c->tmpstr);
		c->tmpstr = NULL;
	}
	sendLogo(c);
	ignore.removeHit(c->getPeerIp4());
	return true;
}

void parse_bot(inetconn *c, char *data)
{
	reason = NULL;

	if(!strlen(data)) return;
	str2words(arg[0], data, 10, MAX_LEN);

	/* REGISTER CONNECTION */
	if(!(c->status & STATUS_REGISTERED))
	{
		switch(c->tmpint)
		{
				case 1:
				{
					if(config.bottype == BOT_MAIN && set.TELNET_OWNERS && !strcasecmp(arg[0], "PASS") && strlen(arg[1]))
					{
						if(MD5Validate(config.ownerpass, arg[1], strlen(arg[1])))
						{
							c->status |= STATUS_CONNECTED | STATUS_PARTY | STATUS_TELNET;
							c->status &= ~STATUS_BOT;
							c->tmpint = 1;
							c->killTime = NOW + set.AUTH_TIME;
							c->send("Welcome to Evangeline (", (const char *) config.nick, ") - ", S_DISPLAY_VERSION, NULL);
#ifdef HAVE_SSL
							if(c->isSSL())
								SSL_write(c->ssl, "login: ", strlen("login: "));
							else
#endif
								write(c->fd, "login: ", strlen("login: "));
							return;
						}
						reason = push(NULL, "bad ownerpass", NULL);
						break;
					}

					if(config.bottype == BOT_MAIN && set.TELNET_OWNERS && strlen(arg[0]) && strlen(arg[1]))
					{
						char fast_code[MAX_LEN];
					normalize_fastlogin_code(arg[1], fast_code);
					const char *peer = c->getPeerIpName();
					HANDLE *h = try_fastlogin_modules(arg[0], fast_code, peer);
					if(finish_fastlogin(c, h))
						return;

					send_fastlogin_error_now(c, fastlogin_error_from_modules(peer));
					c->close("fastlogin failed");
					return;
				}

				if(!strcmp(arg[0], config.botnetword))
				{
					c->enableCrypt((const char *) config.botnetword, strlen(config.botnetword));
					c->tmpstr = (char *) malloc(AUTHSTR_LEN + 1);
					++c->tmpint;
					MD5CreateAuthString(c->tmpstr, AUTHSTR_LEN);
					c->tmpstr[32] = '\0';
					c->send(c->tmpstr, NULL);
					return;
				}
				
				/* maybe that's owner */
				if(config.bottype == BOT_MAIN && set.TELNET_OWNERS && MD5Validate(config.ownerpass, arg[0], strlen(arg[0])))
				{
					c->status |= STATUS_CONNECTED | STATUS_PARTY | STATUS_TELNET;
					c->status &= ~STATUS_BOT;
					c->tmpint = 1;
					c->killTime = NOW + set.AUTH_TIME;
					if(creation)
					{
						c->send("Welcome ", c->getPeerIpName(), " to the constructor", NULL);
						//c->echo(1);
#ifdef HAVE_SSL
						if(c->isSSL())
							SSL_write(c->ssl, "new login: ", strlen("new login: "));
						else
#endif
							write(c->fd, "new login: ", strlen("new login: "));
					}
					else
					{
						//c->echo(1);
						c->send("Welcome ", c->getPeerIpName(), NULL);
#ifdef HAVE_SSL
						if(c->isSSL())
							SSL_write(c->ssl, "login: ", strlen("login: "));
						else
#endif
							write(c->fd, "login: ", strlen("login: "));

					}
					return;
				}
				DEBUG(printf("[D] telnet creep: %s [%d]\n", arg[0], strlen(arg[0])));
				reason = push(NULL, "telnet creep", NULL);
				break;
			}
			case 2:
			{
				if(strlen(arg[1]))
				{
						struct sockaddr_storage peer;
					HANDLE *h = userlist.findHandle(arg[0]);

					if(h && net.findConn(h))
					{
						net.send(HAS_N, "[!] ", arg[0], ": duplicate connection, already linked", NULL);
						reason = push(NULL,  arg[0], ": duplicate connection",NULL);
						break;
					}
					if(h && config.bottype == BOT_MAIN && !userlist.isSlave(h))
					{
						net.send(HAS_N, "[!] ", arg[0], ": is not a slave (use .link-slave)", NULL);
						reason = push(NULL, arg[0], ": not a slave", NULL);
						break;
					}

					if(h && config.bottype == BOT_SLAVE && !userlist.isLeaf(h))
					{
						net.send(HAS_N, "[!] ", arg[0], ": is not a leaf (use .link-leaf)", NULL);
						reason = push(NULL, arg[0], ": not a leaf", NULL);
						break;
					}

						socklen_t peersize = sizeof(peer);
						memset(&peer, 0, sizeof(peer));
						getpeername(c->fd, (sockaddr *) &peer, &peersize);

					if(!h)
					{
						if(isRealStr(arg[0]) && strlen(arg[0]) <= MAX_HANDLE_LEN)
							reason = push(NULL, arg[0], ": not a bot", NULL);
						else
							reason = push(NULL, "(crap here): not a bot", NULL);

						net.send(HAS_N, "[!] incoming bot `", arg[0], "' is not in the botnet (run .link-slave/.link-leaf first)", NULL);
						break;
					}
					if(!h->pass)
					{
						net.send(HAS_N, "[!] ", arg[0], ": no password set (run .link-slave/.link-leaf <handle> <pass>)", NULL);
						reason = push(NULL, arg[0], ": no password set", NULL);

						break;
					}
						if(!h->ip || (peer.ss_family == AF_INET && ((struct sockaddr_in *) &peer)->sin_addr.s_addr == h->ip))
					{
   						if(MD5HexValidate(arg[1], c->tmpstr, strlen(c->tmpstr), h->pass, 16))
						{
							net.send(HAS_N, "[*] ", arg[0], ": password OK", NULL);
							++c->tmpint;
							c->handle = h;
							free(c->tmpstr);
							c->tmpstr = NULL;
							return;
						}
						else
						{
							net.send(HAS_N, "[!] ", arg[0], ": wrong password, link refused", NULL);
							reason = push(NULL, arg[0], ": wrong botpass", NULL);
							break;
						}
					}
					else
					{
						reason = push(NULL, arg[0], ": invalid botip", NULL);
						break;
					}
				}
				reason = push(NULL, "This should not happen (1)", NULL);
				break;
			}
			case 3:
			{
				if(strlen(arg[0]))
				{
					char hash[33];

					++c->tmpint;
					MD5HexHash(hash, arg[0], AUTHSTR_LEN, c->handle->pass, 16);
					c->send(config.handle, " ", userlist.first->next->creation->print(), " ", hash, NULL);
					return;
				}
				reason = push(NULL, "This should not happen (2)", NULL);
				break;
			}
			case 4:
			{
				/* S_REGISTER <S_VERSION> <userlist.SN> [ircnick [irc server] ] */
				if(!strcmp(arg[0], S_REGISTER) && strlen(arg[2]))
				{
					if(strcmp(arg[1], S_VERSION))
					{
						net.send(HAS_N, "[!] ", c->handle->name, " has different version: ", arg[1], NULL);
					}

					mem_strcpy(c->name, arg[3]);
					mem_strcpy(c->origin, arg[4]);
					c->status |= STATUS_CONNECTED | STATUS_REGISTERED | STATUS_BOT;
					c->tmpint = 0;
					c->killTime = NOW + set.CONN_TIMEOUT;
					c->lastPing = NOW;

					if(config.bottype == BOT_SLAVE)
					{
						char portbuf[16];
						snprintf(portbuf, sizeof(portbuf), "%d", (int) config.hub.getPort());
						c->send(S_REGISTER, " ", (const char *) ME.nick, " ", (const char *) config.hub.getHost(), " ", portbuf, NULL);
					}
					else
						c->send(S_REGISTER, " ", (const char *) ME.nick, NULL);

					c->enableCrypt(c->handle->pass, 16);

					/* update ul */
					if(userlist.SN != strtoull(arg[2], NULL, 10))
					{
						net.send(HAS_N, "[*] ", c->handle->name, " is linked (sending userlist)", NULL);
						userlist.send(c);
					}
					else net.send(HAS_N, "\002[ ", c->handle->name, " ]\002 - Established", NULL);


						/* send list of bots */
						net.sendBotListTo(c);
						if(config.bottype != BOT_LEAF)
						{
							char host[MAX_LEN], portbuf[16];
							snprintf(host, sizeof(host), "%s", !config.myipv6.isDefault() ? (const char *) config.myipv6 : (const char *) config.myipv4);
							snprintf(portbuf, sizeof(portbuf), "%d", (int) (config.listenport ? config.listenport : config.ssl_listenport));
							c->send(S_LINKINFO, " ", (const char *) config.handle, " ", host, " ", portbuf, NULL);
							net.propagate(NULL, S_LINKINFO, " ", (const char *) config.handle, " ", host, " ", portbuf, NULL);
						}
						net.propagate(c, S_BJOIN, " ", c->name, " ", c->origin, NULL);

					/* check bot host */
					if(config.bottype == BOT_MAIN)
						c->send(S_CHKHOST, " *", NULL);

					ignore.removeHit(c->getPeerIp4());
					return;
				}

				if(!strcmp(arg[0], S_IUSEMODULES))
					return;

				reason = push(NULL, "This should not happen (3)", NULL);
				break;
			}
			default:
			break;
		}
		/* HUH */
		if(!reason)
			reason = push(NULL, "Unknown error", NULL);
		c->close(reason);
		free(reason);
		return;
	}

	/* PARSE DATA FROM REGISTERED BOT */
	c->killTime = NOW + set.CONN_TIMEOUT;

	if(!strcmp(arg[0], S_UL_UPLOAD_START))
	{
		c->close("Go fuck yourself");
		return;
	}
	if(!strcmp(arg[0], S_ULOK))
	{
		net.send(HAS_N, "\002[ ", c->handle->name, " ]\002 - Established", NULL);
		return;
	}
	parse_botnet(c, data);
}
