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

int requestShit(const char *channel, const char *mask, const char *from, int delay, const char *reason, const char *bot);

static char arg[10][MAX_LEN];
static chan *ch;
static chanuser *p;

static void learnLinkEndpoint(const char *handle, const char *host, const char *port)
{
	if(config.bottype != BOT_LEAF || !handle || !*handle || !host || !*host || !port || !*port)
		return;
	if(!strcasecmp(handle, config.handle) || !strcasecmp(handle, config.hub.getHandle()))
		return;

	HANDLE *h = userlist.findHandle(handle);
	if(!h || !userlist.isBot(h) || (!userlist.isSlave(h) && !userlist.isMain(h)))
		return;

	int start = userlist.isMain(h) ? MAX_ALTS - 1 : 0;
	int end = userlist.isMain(h) ? MAX_ALTS : MAX_ALTS - 1;
	for(int i=start; i<end; ++i)
	{
		if(config.alt[i].isDefault() ||
			(!strcmp(config.alt[i].getHost().connectionString, host) && atoi(port) == (int) config.alt[i].getPort()))
		{
			options::event *e = config.alt[i].setValue("alt", host, port);
			if(e && e->ok)
				config.alt[i].failures = 0;
			return;
		}
	}
}

void autoRehostBotOnNotify(const char *payload, inetconn *c)
{
	if(!payload || !*payload) return;

	const char *np = strstr(payload, " is not added");
	if(!np) return;

	const char *bt = strchr(payload, '`');
	const char *start = bt ? strchr(bt + 1, '\002') : NULL;
	const char *end = start ? strchr(start + 1, '\002') : NULL;
	if(!start || !end || end <= start + 1) return;

	char mask[MAX_LEN], mh[MAX_LEN], nick[MAX_HANDLE_LEN + 1];
	size_t ml = (size_t)(end - start - 1);
	if(ml >= MAX_LEN) ml = MAX_LEN - 1;
	memcpy(mask, start + 1, ml);
	mask[ml] = '\0';

	const char *bang = strchr(mask, '!');
	if(!bang) return;
	size_t nl = (size_t)(bang - mask);
	if(nl > MAX_HANDLE_LEN) nl = MAX_HANDLE_LEN;
	memcpy(nick, mask, nl);
	nick[nl] = '\0';

	if(!isRealStr(nick)) return;
	HANDLE *h = userlist.findHandle(nick);
	if(!h || !userlist.isBot(h)) return;
	if(userlist.wildFindHost(h, mask) != -1) return;

	if(!extendhost(bang + 1, mh, MAX_LEN)) return;

	if(userlist.addHost(h, mh, c && c->handle ? c->handle->name : "link", NOW) == -1)
		return;

	net.send(HAS_B, S_ADDHOST, " ", h->name, " ", mh, NULL);
	++userlist.SN;
	userlist.nextSave = NOW + SAVEDELAY;
	net.send(HAS_N, "[*] ", h->name, ": IRC host changed, re-added host ", mh, NULL);
}

int parse_botnet(inetconn *c, char *data)
{
	if(!strlen(data)) return 0;
	str2words(arg[0], data, 10, MAX_LEN);

	/* CHNICK [nick [irc server] ] */
	if(!strcmp(arg[0], S_CHNICK))
	{
		if(*arg[2] || !*arg[1])
		{
			free(c->origin);
			free(c->name);
			mem_strcpy(c->origin, arg[2]);
			mem_strcpy(c->name, arg[1]);
		}

		//nick change
		else if(*arg[1])
		{
			free(c->name);
			mem_strcpy(c->name, arg[1]);
		}
		return 1;
	}

	if(!strcmp(arg[0], S_LINKINFO) && strlen(arg[3]))
	{
		learnLinkEndpoint(arg[1], arg[2], arg[3]);
		net.propagate(c, data, NULL);
		return 1;
	}

	/* BJOIN [ircnick [irc server] ] */
	/*
	if(!strcmp(arg[0], S_BJOIN))
	{
		if(h && userlist.isBot(h) && strcmp(ME.nick, arg[1]) && !net.findConn(h))
		{
			bot = net.addConn(c->fd);
			if(bot)
			{
				mem_strcpy(bot->name, arg[2]);
				mem_strcpy(bot->origin, arg[3]);
                bot->status = STATUS_CONNECTED + STATUS_REGISTERED + STATUS_BOT + STATUS_REDIR;
				bot->handle = h;
    			net.propagate(c, data, NULL);

				if(config.bottype == BOT_LEAF && config.currentHub != &config.hub &&
					!strcmp(arg[1], config.hub.handle))
				{
					config.hub.failures = 0;
					net.hub.close("Jumping to hub");
				}
			}
		}
		return 1;
	}
	*/
	/* BQUIT [reason] */
	if(!strcmp(arg[0], S_BQUIT))
	{
		c->close(srewind(data, 1));
		return 1;
	}

	/* FORWARD <from> <to|*> <data> */
	if(!strcmp(arg[0], S_FORWARD) && strlen(arg[3]))
	{
		inetconn *from = net.findConn(userlist.findHandle(arg[1]));

		if(from)
		{
			if(from->fd != c->fd)
			{
				net.send(HAS_N, "[!] Hacked packet from ", c->handle->name, "@", from->name, ": ", data, NULL);
				c->close("Hacked packed -- internal error or smb is doing sth nasty");
				return 1;
			}
		}
		//bot joined ?
		else
		{
			/* FORWARD <from> "*" BJOIN [nick [ircserver]] */
			if(!strcmp(arg[3], S_BJOIN) && !strcmp(arg[2], "*"))
			{
				HANDLE *h = userlist.findHandle(arg[1]);
				if(!h)
				{
					net.send(HAS_N, "[-] Invalid bot join (dsynced ul?) from ", c->name, ": ", arg[1], NULL);
					net.send(HAS_N, "[*] This should not happnen, please do .restart `\002", c->name, "\002'", NULL);
					return 1;
				}

				if(h->flags[GLOBAL] & HAS_B)
				{
					//maybe thats my slave ?
					if(config.bottype == BOT_LEAF && config.currentHub != &config.hub &&
							!strcmp(arg[1], config.hub.getHandle()))
					{
						config.hub.failures = 0;
						ME.nextConnToHub = NOW + set.HUB_CONN_DELAY + rand() % set.HUB_CONN_DELAY;
						net.hub.close("Jumping to main slave");
						//no point of doing anything else
						//cos we disconnect from other bots in the botnet
						return 1;
					}

					from = net.addConn(c->fd);

					mem_strcpy(from->name, arg[4]);
					mem_strcpy(from->origin, arg[5]);
					from->status = STATUS_CONNECTED + STATUS_REGISTERED + STATUS_BOT + STATUS_REDIR;
					from->handle = h;

					if(from->isMain())
						ME.checkMyHost("*");
				}
			}
			else
			{
				net.send(HAS_N, "[!] Invalid packet from ", c->name, ": ", data, NULL);
				c->close("Invalid packet -- internal error or smb is doing sth nasty");
				return 1;
			}
		}

		if(!strcmp(arg[2], config.handle))
		{
			if(from->isMain())
				parse_hub(srewind(data, 3));
			else
				parse_botnet(from, srewind(data, 3));
		}
		else if(!strcmp(arg[2], "*"))
		{
			net.propagate(from, srewind(data, 3), NULL);
			if(from->isMain())
				parse_hub(srewind(data, 3));
			else
				parse_botnet(from, srewind(data, 3));
		}
		else
		{
			inetconn *to = net.findConn(userlist.findHandle(arg[2]));

			if(to)
			{
				inetconn *slave = net.findRedirConn(to);
				if(slave)
					slave->send(data, NULL);
			}
		}
		return 1;
	}
	/* BOP <channel> */
	if(!strcmp(arg[0], S_BOP) && strlen(arg[1]))
	{
		ch = ME.findChannel(arg[1]);
		if(ch)
		{
			p = ch->getUser(c->name);
			if(p && (p->flags & HAS_B) && (set.GETOP_OP_CHECK ? !(p->flags & IS_OP) : 1))
				ch->op(p);
		}
		return 1;
	}
	/* S_INVITE <seed> <channel> */
	if(!strcmp(arg[0], S_INVITE) && strlen(arg[2]))
	{
		ch = ME.findChannel(arg[2]);
		if(ch)
		{
			if(ch->me->flags & IS_OP && ch->myTurn(ch->chset->INVITE_BOTS, atoi(arg[1])))
			{
				if(!ch->getUser(c->name))
					ch->invite(c->name);
			}
		}
		return 1;
	}

	/* S_UNBANME <seed> <nick!ident@host> <channel> [IP] [UID]*/
	if(!strcmp(arg[0], S_UNBANME) && strlen(arg[3]))
	{
		if(penalty >= 10) return 1;
		ch = ME.findChannel(arg[3]);
		if(ch)
		{
			if(ch->me->flags & IS_OP && ch->myTurn(ch->chset->GUARDIAN_BOTS, atoi(arg[1])))
			{
				if(!ch->getUser(c->name))
				{
					if(ch->chset->INVITE_ON_UNBAN_REQUEST)
						ch->invite(c->name);
					else
					{
						masklist_ent *m = ch->list[BAN].matchBan(arg[2], arg[4], arg[5]);
						if(m)
						{
							if(protmodelist::isSticky(m->mask, BAN, ch))
								ch->invite(c->name);
							else
							{
								ch->modeQ[PRIO_HIGH].add(NOW, "-b", m->mask);
								ch->modeQ[PRIO_HIGH].flush(PRIO_HIGH);

								c->send(S_COMEON, " ", arg[3], NULL);
							}
						}
					}
				}
			}
		}
		return 1;
	}

	/* S_BIDLIMIT <seed> <channel> */
	if(!strcmp(arg[0], S_BIDLIMIT) && strlen(arg[2]))
	{
		net.propagate(c, data, NULL);
		if(penalty >= 10) return 1;

		ch = ME.findChannel(arg[2]);
		if(ch && ch->me->flags & IS_OP && ch->myTurn(ch->chset->LIMIT_BOTS, atoi(arg[1])))
		{
			if(ch->nextlimit != -1)
			{
				if(ch->limit <= ch->users.entries())
				{
					ch->modeQ[PRIO_HIGH].add(NOW, "+l", itoa(ch->users.entries() + ch->chset->LIMIT_OFFSET));
					if(ch->modeQ[PRIO_HIGH].flush(PRIO_HIGH))
						c->send(S_COMEON, " ", arg[2], NULL);
				}
			}
			else ch->invite(c->name);
		}
		return 1;
	}

	/* S_KEY <seed> <channel> */
	if(!strcmp(arg[0], S_KEY) && strlen(arg[2]))
	{
		ch = ME.findChannel(arg[2]);
		if(ch && ch->key && *ch->key && ch->myTurn(ch->chset->INVITE_BOTS, atoi(arg[1])))
			c->send(S_KEYRPL, " ", arg[2], " ", (const char *) ch->key, NULL);

		return 1;
	}

	/* S_KEYRPL <channel> <key> */
	if(!strcmp(arg[0], S_KEYRPL) && strlen(arg[2]))
	{
		int i;
		if(!ME.findChannel(arg[1]) && (i = userlist.findChannel(arg[1])) != -1)
		{
			userlist.chanlist[i].pass = arg[2];
			if(userlist.chanlist[i].nextjoin + 2 >= NOW)
				ME.rejoin(arg[1], 2);
		}
		return 1;
	}

	/* S_COMEON <channel> */
	if(!strcmp(arg[0], S_COMEON) && strlen(arg[1]))
	{
		int i;
		if(!ME.findChannel(arg[1]) && (i = userlist.findChannel(arg[1])) != -1 && userlist.isRjoined(i))
		{
			if(userlist.chanlist[i].nextjoin + 2 >= NOW)
				ME.rejoin(arg[1], 2);
		}
		return 1;
	}
	/* S_LIST ? <owner> arg1 arg2 */
	if(!strcmp(arg[0], S_LIST) && strlen(arg[2]))
	{
		listcmd(arg[1][0], arg[2], arg[3], arg[4], c);
			//net.propagate(c, data, NULL);
		return 1;
	}

	/* S_BOTCMD <cmd> */
	if(!strcmp(arg[0], S_BOTCMD) && strlen(arg[1]))
	{
		botnetcmd(c->name, srewind(data, 1));
		return 1;
	}

	/* S_BKICK <chan> <nick> ... - an oped bot is overloaded and handed off its
	   enemies; enqueue and kick them for it */
	if(!strcmp(arg[0], S_BKICK) && strlen(arg[1]))
	{
		chan *ch = ME.findChannel(arg[1]);
		if(ch && ch->me->flags & IS_OP)
		{
			char targetBuf[MAX_LEN], *nick, *saveptr = NULL;
			const char *targets = srewind(data, 2);
			if(!targets || !*targets)
				return 1;
			snprintf(targetBuf, sizeof(targetBuf), "%s", targets);
			for(nick = strtok_r(targetBuf, " ", &saveptr); nick; nick = strtok_r(NULL, " ", &saveptr))
			{
				chanuser *u = ch->getUser(nick);
				if(u && !(u->flags & HAS_F))
					ch->toKick.sortAdd(u);
			}
			if((int) penalty < 15)
				ch->flushKickQueue();
		}
		return 1;
	}

	if(config.bottype == BOT_MAIN)
	{
		if(!strcmp(arg[0], S_PROXYHOST) && strlen(arg[1]))
		{
			HANDLE *h = userlist.findHandle(arg[1]);
			if(h && userlist.isBot(h) && h->flags[GLOBAL] & HAS_P)
			{
				userlist.addHost(h, arg[2], NULL, 0, MAX_HOSTS-1);
				++userlist.SN;
				net.send(HAS_B, data, NULL);
			}
			return 1;
		}

		/* S_OREDIR <from> <to|*> <[?]> <data> */
		if(!strcmp(arg[0], S_OREDIR) && strlen(arg[4]))
		{
			char *a = srewind(data, 3);
			if(a)
			{
				autoRehostBotOnNotify(a, c);
				net.sendOwner(arg[2], "(", arg[1], ") ", a, NULL);
			}
			return 1;
		}

		/* S_REQSHIT <chan> <mask> <from> <delay> <reason> */
		if(!strcmp(arg[0], S_REQSHIT) && strlen(arg[5]))
		{
			if(set.BOTS_CAN_ADD_SHIT)
				protmodelist::addShit(arg[1], arg[2], arg[3], atol(arg[4]), srewind(data, 5), c->handle->name);
			else
				net.send(HAS_N, "[?] ", c->handle->name, " requested shit but bots-can-add-shit is OFF", NULL);

			return 1;
		}
		/* S_ADDIDIOT <mask> <chan> <number> <reason> */
		if(!strcmp(arg[0], S_ADDIDIOT) && strlen(arg[4]))
		{
		    char *a = srewind(data, 4);
		    if(a)
			userlist.addIdiot(arg[1], arg[2], a, arg[3]);
		    return 1;
		}

		/* S_SHITOBSERVED <#channel> <ban_mask> <nick!user@host> */
		if(!strcmp(arg[0], S_SHITOBSERVED) && strlen(arg[3]))
		{
			protmodelist::updateLastUsedTime(arg[1], arg[2], BAN);
		}
	}
	return 0;
}
