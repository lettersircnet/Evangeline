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
#include "scram.h"

static char arg[11][MAX_LEN], *a, buf[MAX_LEN];
static chan *ch;
static chanuser *p;
static int i;
#ifdef HAVE_SSL
static Scram* scram;
#endif

int grantOpForAuthenticatedUser(const char *from, const char *channel)
{
	int delay = 0, granted = 0;
	chan *opch;
	chanuser *opuser;

	if(channel && *channel)
	{
		opch = ME.findChannel(channel);
		if(opch)
		{
			opuser = opch->getUser(from);
			if(opuser && opuser->flags & HAS_O && !(opuser->flags & IS_OP))
			{
				opch->modeQ[PRIO_LOW].add(NOW, "+o", opuser->nick);
				++granted;
			}
		}
	}
	else
	{
		foreachSyncedChannel(opch)
		{
			opuser = opch->getUser(from);
			if(opuser && opuser->flags & HAS_O && !(opuser->flags & IS_OP))
			{
				opch->modeQ[PRIO_LOW].add(NOW + delay, "+o", opuser->nick);
				delay += 4;
				++granted;
			}
		}
	}

	return granted;
}

void parse_irc(char *data)
{
	if(!strlen(data))
		return;

	net.irc.killTime = NOW + set.CONN_TIMEOUT;

	str2words(arg[0], data, 11, MAX_LEN, 1);

	/* debug */
#ifdef HAVE_DEBUG

	if(debug)
	{
		if(!strcmp(arg[1], "PRIVMSG"))
		{
			ch = ME.findChannel(arg[2]);

			if(ch)
			{
				if(!strcasecmp(arg[3], "!debug"))
				{
					printf("### DEBUG ###\n");
					printf("CHANNELS: %d\n", ME.channels);
					ME.display();
					ch->display();
					return;
				}
			}

			if(!strcmp(arg[3], "!re"))
			{
				ME.recheckFlags();
				return;
			}
			
			/*if(!strcmp(arg[3], "!crash"))
			{
				char *buf = NULL;
				*buf = 9;
			}*/
		}
	}
#endif

	/* a raw server ERROR: capture the reason (e.g. "Excess Flood", "Bad
	   password", "K-lined") before the link dies so that _close() can react.
	   this is the IRCnet flood-signature path. */
	if(!strcmp(arg[0], "ERROR") || !strcmp(arg[1], "ERROR"))
	{
		char *er = (!strcmp(arg[0], "ERROR")) ? srewind(data, 1) : srewind(data, 2);
		if(er && *er == ':') ++er;
		net.irc.close(er && *er ? er : (char *)"server ERROR");
		return;
	}

	/* reaction */
	if(!strcmp(arg[1], "JOIN"))
	{
		chanuser u(arg[0], NULL, 0, false);
		int netjoin = arg[2][0] != ':';
		if(netjoin)
			a = arg[2];
		else
			a = arg[2] + 1;

		if(!strcasecmp(ME.nick, u.nick))
		{
			if(!ME.findNotSyncedChannel(a))
			{
				// FIXME: WHO flood if bot receives many JOIN's

				if((i = userlist.findChannel(a)) != -1)
				{
					ME.createNewChannel(a);
					if(!(userlist.chanlist[i].status & WHO_SENT))
					{
						net.irc.send("WHO ", a, NULL);
						penalty+=2;
					}
				}
				//if thats !channel maybe we have to change its name
				//to !0WN3Dchannel
				//FIXME: is that necessary?
				else if(*a == '!' && strlen(a) > 6)
				{
					buf[0] = '!';
					strcpy(buf+1, a + 6);
					if((i = userlist.findChannel(buf)) != -1)
					{
						userlist.chanlist[i].name = a;
						ME.createNewChannel(a);
						if(!(userlist.chanlist[i].status & WHO_SENT))
						{
							net.irc.send("WHO ", a, NULL);
							penalty+=2;
						}
					}
				}
				else
				{
					net.irc.send("PART ", a, " :wtf?", NULL);
					penalty += 3;
				}
			}
			else
			{
				net.send(HAS_N, "\0039 >> Double join to ", a, " <<\003", NULL);
			}
		}
		else
		{
			ch = ME.findChannel(a);
			if(ch)
				ch->gotJoin(arg[0], netjoin ? NET_JOINED : 0);
#ifdef HAVE_DEBUG
			else if(!ME.findNotSyncedChannel(a))
				net.send(HAS_N, "\0039 >>> Join observed to non exitsing channel ", a, "<<\003", NULL);
#endif
		}
		return;
	}
	if(!strcmp(arg[1], "MODE"))
	{
		ch = ME.findChannel(arg[2]);
		if(ch)
		{
			char *tmp=srewind(data, 4); // args

                        if(tmp)
				a=strdup(tmp);

			ch->gotMode(arg[3], tmp ? a : "", arg[0]);

			if(tmp)
				free(a);
		}
		return;
	}
	if(!strcmp(arg[1], "KICK"))
	{
		if(!strcasecmp(ME.nick, arg[3]))
		{
			ch = ME.findChannel(arg[2]);
			if(ch)
				ch->buildAllowedOpsList(arg[0]);
			ME.removeChannel(arg[2]);
			ME.rejoin(arg[2], set.REJOIN_DELAY);
		}
		else
		{
			ch = ME.findChannel(arg[2]);
			if(ch)
			{
				char *r = srewind(data, 4);
				if(r && *r == ':') ++r;
				if(!r) r = (char *) "";
				ch->gotKick(arg[3], arg[0], r);
			}
		}
		return;
	}
	if(!strcmp(arg[1], "PART"))
	{
		HOOK(pre_part, pre_part(arg[0], arg[2], srewind(data,3), false));
		stopParsing=false;

		if(!strcasecmp(ME.mask, arg[0]))
		{
			ME.removeChannel(arg[2]);
			penalty += 4;
		}
		else
		{
			ch = ME.findChannel(arg[2]);
			if(ch)
			{
				char *ex = strchr(arg[0], '!');
				if(ex)
				{
					mem_strncpy(a, arg[0], abs(arg[0] - ex) + 1);
					ch->gotPart(a, 0);
					free(a);
				}
				else
					ch->gotPart(arg[0], 0);
			}

		}
		HOOK(post_part, post_part(arg[0], arg[2], srewind(data,3), false));
		stopParsing=false;
		return;
	}
	if(!strcmp(arg[1], "NICK"))
	{
		ME.gotNickChange(arg[0], arg[2]);
		return;
	}
	if(!strcasecmp(arg[1], "352"))
	{
		ch = ME.findNotSyncedChannel(arg[3]);
		if(ch && !ch->synced())
		{

			wasoptest *w = userlist.chanlist[ch->channum].allowedOps;
			if(w && w->since + w->TOL <= NOW)
			{
				delete userlist.chanlist[ch->channum].allowedOps;
				userlist.chanlist[ch->channum].allowedOps = NULL;
			}

			a = push(NULL, arg[7], "!", arg[4], "@", arg[5], NULL);
			p = ch->gotJoin(a, (strchr(arg[8], '@') ? IS_OP : 0) | (strchr(arg[8], '+') ? IS_VOICE : 0));

			if(!strcasecmp(arg[7], ME.nick))
				ch->me = p;

			free(a);
		}
		return;
	}
	if(!strcmp(arg[1], "315"))
	{
		ch = ME.findNotSyncedChannel(arg[3]);
		if(ch)
		{
			if(ch->synced())
			{
				//net.send(HAS_N, "\0039[!] BUG, BUG >> Double WHO on ", (const char *) ch->name, " << BUG, BUG", NULL);
				return;
			}
			if(!ch->users.entries())
			{
				net.send(HAS_N, "[D] Empty WHO RPL", NULL);
				bk;
				return;
			}

			ch->synlevel = 1;

			if(userlist.chanlist[ch->channum].allowedOps)
			{
				delete userlist.chanlist[ch->channum].allowedOps;
				userlist.chanlist[ch->channum].allowedOps = NULL;
			}
			if(!ch->opedBots.entries())
				userlist.chanlist[ch->channum].status &= ~SET_TOPIC;


			HOOK(justSynced, justSynced(ch));
			stopParsing=false;
		}
		return;
	}
	if(!strcmp(arg[1], "324"))
	{
		ch = ME.findChannel(arg[3]);
		if(ch)
		{
			ch->limit = 0;
			ch->updateKey("");
			ch->setFlags(arg[4]);

			a = arg[4];

			for(i=5; *a && i < 7; ++a)
			{
				switch(*a)
				{
					case 'l':
						ch->limit = atol(arg[i++]);
						break;
					case 'k':
						ch->updateKey(arg[i++]);
						break;
					default: break;
				}
			}

			++ch->synlevel;
			if(ch->limit == -1)
				ch->nextlimit = -1;
			else
				ch->nextlimit = NOW + set.ASK_FOR_OP_DELAY;

			/*
			if(!ch->toKick.entries() && ch->opedBots.entries() + ch->botsToOp.entries() == 1 &&
					!(ch->flags & (FLAG_N | FLAG_S | FLAG_T)))
			{
				ch->modeQ[PRIO_LOW].add(NOW, "+s");
				ch->modeQ[PRIO_LOW].add(NOW, "+n");
				ch->modeQ[PRIO_LOW].add(NOW, "+t");
			}
			*/
		}
		else DEBUG(printf("unknown 324 for %s\n", arg[3]));
		return;
	}
	if(!strcmp(arg[1], "QUIT"))
	{
		ME.gotUserQuit(arg[0], srewind(data, 2));
		return;
	}
	if(!strcmp(arg[0], "PING"))
	{
		net.irc.send("PONG ", arg[1], NULL);
		return;
	}
	if(!strcmp(arg[1], "PONG"))
	{
		/* RTT measurement: the trailing parameter is the `L<ms>` token that
		   our keep-alive PING asked the ircd to echo back in PONG. */
		const char *tok = data ? strrchr(data, ':') : NULL;
		if(tok && !strncmp(++tok, "L", 1) && ircLagSentMs)
		{
			unsigned long long sent = strtoull(tok + 1, NULL, 10);
			unsigned long long now = monotonicMs();
			if(sent)
			{
				if(now > sent) ircLagMs = now - sent;
				else ircLagMs = 0;
				ircLagAt = NOW;   /* freshness marker: only apply floor to fresh lags */
			}
		}
		return;
	}
	if(!strcmp(arg[1], "433"))
	{
		if(net.irc.status & STATUS_REGISTERED)
			ME.nextNickCheck = NOW + set.KEEP_NICK_CHECK_DELAY;
		else
		{
			if(config.altnick.getLen() && !strcmp(arg[3], config.nick) && strcmp(arg[3], config.altnick))
				net.irc.send("NICK ", (const char*) config.altnick, NULL);
			else
				ME.registerWithNewNick(arg[3]);
			sleep(1);
		}
		return;
	}
	if(!strcmp(arg[1], "437"))
	{
		if(net.irc.status & STATUS_REGISTERED)
		{
			i = userlist.findChannel(arg[3]);
			if(i == -1)
			{
				/* Nick is temp...*/
				ME.nextNickCheck = NOW + set.KEEP_NICK_CHECK_DELAY;
			}
			else
			{
				/* Channel is temp... */
				ME.rejoin(arg[3], set.REJOIN_FAIL_DELAY);
			}
		}
		else
			ME.registerWithNewNick(arg[3]);

		return;
	}
	if(!strcmp(arg[1], "432"))
	{
		if(!(net.irc.status & STATUS_REGISTERED))
		{
			strncpy(arg[3], config.nick, MAX_LEN);
			ME.registerWithNewNick(arg[3]);
		}
	}

	if(!strcmp(arg[1], "043"))
	{
		/* collision, try to get nick back in 30 mins */
		ME.nextNickCheck = NOW + 1800;
		return;
	}

	if(!strcmp(arg[1], "001") && !(net.irc.status & STATUS_REGISTERED))
	{
		mem_strcpy(net.irc.name, arg[0]);
		ME.server.name=strdup(arg[0]);
		mem_strcpy(net.irc.origin, arg[0]);
		net.irc.status |= STATUS_REGISTERED;
		net.irc.lastPing = NOW;

		if(match("*!*@*", arg[9]))
		{
			if(userlist.me()->flags[GLOBAL] & HAS_P)
				hostNotify = 1;
			else
				hostNotify = 0;

			chanuser u(arg[9], NULL, 0, false);
			ME.nick = u.nick;
			ME.ident = u.ident;
			ME.host = u.host;
			ME.mask = arg[9];
		}
		else
		{
			/* if it does not tell us the hostmask, we catch only
			 * the nickname and do WHOIS.
			 * arg[9] should not be used as nickname because the 001
			 * lines can be very different - patrick
			 */

			hostNotify = 0;
			ME.nick = arg[2];
			net.irc.status|=STATUS_NEED_WHOIS;
			net.irc.send("WHOIS ", (const char*)ME.nick, NULL);
		}

		srand();

		net.propagate(NULL, S_CHNICK, " ", (const char *) ME.nick, " ", net.irc.name, NULL);
		if(strcmp(ME.nick, config.nick))
			ME.nextNickCheck = NOW + set.KEEP_NICK_CHECK_DELAY;
		else
			ME.nextNickCheck = 0;

		if(creation)
		{
			printf("[*] Please do `/msg %s mainowner <handle> <password>'\n", (const char *) ME.nick);
			printf("[*] eg. `/msg %s mainowner %s foobar'\n", (const char *) ME.nick, getenv("USER"));
		}
		else
			net.send(HAS_N, "[*] Connected to ", net.irc.name, " as ", (const char *) ME.nick, NULL);

		if(antiidle.away)
		{
			net.irc.send("AWAY :", antiidle.away, NULL);
			penalty = 4;
		}
		else penalty = 2;

		/* adaptive anti-flood: re-apply any pending flood cool-down so the
		   automatic reconnect does not immediately resume flooding */
		if(floodBackoffUntil > NOW && (long)(floodBackoffUntil - NOW) > penalty)
			penalty = (long)(floodBackoffUntil - NOW);

		if(!(net.irc.status&STATUS_NEED_WHOIS))
			ME.checkMyHost("*", true);
		ME.ircip.assign(net.irc.getPeerIpName(), strlen(net.irc.getPeerIpName()));
		net.irc.send("stats L ", (const char *) ME.nick, NULL);
		penalty += 2;

		if(!creation)
		{
			HOOK(connected, connected());
			stopParsing=false;
		}

		return;
	}
	if(!strcmp(arg[1], "211") && strlen(arg[3]))
	{
		char *at = strchr(arg[3], '@');

		if(at)
			ME.ircip.assign(at+1, strlen(at+1)-1);
		return;
	}

	if(!strcmp(arg[1], "002"))
	{
		if(!strcmp(arg[9], "2.11") || match("2.11.*", arg[9]))
			net.irc.status |= STATUS_211;

		return;
	}

	if(!strcmp(arg[1], "004"))
	{
		ME.server.version=strdup(arg[4]);
		ME.server.usermodes=strdup(arg[5]);
		ME.server.chanmodes=strdup(arg[6]);
		return;
	}

	if(!strcmp(arg[1], "005"))
	{
		// fill isupport with 005 tokens -- patrick

		char *isupport_str, *key, *value, *p;

		isupport_str=srewind(data, 3);

		if(!isupport_str)
			return;

		for(key=strtok_r(isupport_str, " ", &p); key; key=strtok_r(NULL, " ", &p))
		{
			if(*key == ':')
				break;

			if((value=strchr(key, '=')))
			{
				*value='\0';
				value++;
			}

			ME.server.isupport.insert(key, value);
		}

		ME.server.isupport.init();
		return;
	}

	if(!strcmp(arg[1], "042"))
	{
		ME.uid = arg[3];
		return;
	}
	if(!strcmp(arg[1], "311") && net.irc.status&STATUS_NEED_WHOIS) // RPL_WHOISUSER
	{
		char buffer[MAX_LEN];
		ME.ident = arg[4];
		ME.host = arg[5];
		snprintf(buffer, MAX_LEN, "%s!%s@%s", (const char*)ME.nick, (const char*)ME.ident, (const char*)ME.host);
		ME.mask = buffer;
		net.irc.status&= ~STATUS_NEED_WHOIS;

		if(userlist.me()->flags[GLOBAL] & HAS_P)
			hostNotify = 1;
		else
			hostNotify = 0;

		ME.checkMyHost("*", true);
	}
	if(!strcmp(arg[1], "332"))
	{
		chan *ch = ME.findNotSyncedChannel(arg[3]);
		if(ch)
		{
			ch->topic = srewind(data, 4)+1;
			HOOK(topicChange, topicChange(ch, ch->topic, NULL, NULL));
			stopParsing=false;
		}
		return;
	}

	if(!strcmp(arg[1], "TOPIC"))
	{
		chan *ch = ME.findChannel(arg[2]);
		if(ch)
		{
#ifdef HAVE_MODULES
			chanuser *u = ch->getUser(arg[0]);
#endif
			pstring<> oldtopic(ch->topic);
			ch->topic = srewind(data, 3)+1;

			HOOK(topicChange, topicChange(ch, ch->topic, u, oldtopic));
			stopParsing=false;
		}
	}

	if(!strcmp(arg[1], "INVITE"))
	{
		chan *ch = NULL;
		if((i = userlist.findChannel(arg[3])) != -1 && !(ch = ME.findChannel(arg[3])))
		{
			if(!(userlist.chanlist[i].status & JOIN_SENT) && userlist.isRjoined(i))
			{
				net.irc.send("JOIN ", arg[3], " ", (const char *) userlist.chanlist[i].pass, NULL);
				userlist.chanlist[i].status |= JOIN_SENT;
			}
		}

		HOOK(invite, invite(arg[0], arg[3], ch, i == -1 ? NULL : &userlist.chanlist[i]));
		stopParsing=false;
		return;
	}

	if(!strcmp(arg[1], "NOTICE"))
		{
			char *msg = srewind(data, 3);
			if(msg)
			{
				if(*msg == ':') ++msg;
				HOOK(privmsg, privmsg(arg[0], arg[2], msg));
			}

			if(stopParsing)
			{
				stopParsing=false;
				return;
			}

		if(strchr(arg[0], '.') && !strchr(arg[0], '@'))
		{
			chan *ch = ME.findChannel(arg[2]);

			if(ch)
			{
				if(!strcmp(arg[6], "invitation"))
				{
					if(strchr(arg[8], '@'))
						ME.overrider = arg[8];
					else
						ME.overrider = "-";

					return;
				}
			}
		}

		return;
	}

	if(!strcmp(arg[1], "PRIVMSG"))
	{
		/* CTCP */
		if(arg[3][0] == '\001')
		{
			if(data[strlen(data)-1] != '\001')
				return;
			data[strlen(data)-1] = '\0';
			for(i=0; i<3; )
				if(*data++ == ' ')
					                    ++i;
			parse_ctcp(arg[0], data + 2, arg[2]);
			return;
		}

		HOOK(privmsg, privmsg(arg[0], arg[2], srewind(data, 3) + 1));

		if(stopParsing)
		{
			stopParsing=false;
			return;
		}

		if(!strcmp(ME.nick, arg[2]))
		{
			/* op pass #chan */
			if(!strcmp(arg[3], "op") || !strcmp(arg[3], ".op") || !strcmp(arg[3], "!op"))
			{
				if(userlist.matchPassToHandle(arg[4], arg[0], 0))
					grantOpForAuthenticatedUser(arg[0], strlen(arg[5]) ? arg[5] : NULL);
				return;

			}

			if(!strcmp(arg[3], "voice") || !strcmp(arg[3], ".voice") || !strcmp(arg[3], "!voice"))
			{
				if(strlen(arg[5]))
				{
					ch = ME.findChannel(arg[5]);
					if(ch)
					{
						p = ch->getUser(arg[0]);
						if(p && p->flags & (HAS_V | HAS_O) && !(p->flags & IS_VOICE))
						{
							HANDLE *h = userlist.matchPassToHandle(arg[4], arg[0], 0);
							if(h) ch->modeQ[PRIO_LOW].add(NOW, "+v", p->nick);
						}
					}
				}
				else
				{
					i=0;
					foreachSyncedChannel(ch)
					{
						p = ch->getUser(arg[0]);
						if(p && p->flags & (HAS_V | HAS_O) && !(p->flags & IS_VOICE))
						{
							HANDLE *h = userlist.matchPassToHandle(arg[4], arg[0], 0);
							if(h) ch->modeQ[PRIO_LOW].add(NOW + i, "+v", p->nick);
							i+=4;
						}
					}
				}
				return;
			}



			/* invite pass #chan */
			if((!strcmp(arg[3], "invite") || !strcmp(arg[3], ".invite") || !strcmp(arg[3], "!invite")) && strlen(arg[5]))
			{
				ch = ME.findChannel(arg[5]);
				if(ch)
				{
					HANDLE *h = userlist.matchPassToHandle(arg[4], arg[0], 0);
					if(h && (h->flags[MAX_CHANNELS] & HAS_F || h->flags[ch->channum] & HAS_F))
					{
						ch->invite(arg[0]);
					}
				}
				return;
			}
			/* key pass chan */
			if((!strcmp(arg[3], "key") || !strcmp(arg[3], ".key") || !strcmp(arg[3], "!key")) && strlen(arg[5]))
			{
				ch = ME.findChannel(arg[5]);
				if(ch && ch->key && *ch->key)
				{
					HANDLE *h = userlist.matchPassToHandle(arg[4], arg[0], 0);
					if(h && (h->flags[MAX_CHANNELS] & HAS_F || h->flags[ch->channum] & HAS_F))
						ctcp.push("NOTICE ", arg[0], " :", arg[5], "'s key: ", (const char *) ch->key, NULL);
				}
				return;
			}
			/* pass oldpass newpass */
			if(config.bottype == BOT_MAIN && (!strcmp(arg[3], "pass") || !strcmp(arg[3], ".pass") || !strcmp(arg[3], "!pass")) && strlen(arg[4]))
			{
				HANDLE *h;
				if(strlen(arg[5])) // pass change
				{
					h = userlist.matchPassToHandle(arg[4], arg[0], 0);

					if(h)
					{
						if(strlen(arg[5]) < 8)
						{
							ctcp.push("NOTICE ", arg[0], " :New password must be at least 8 characters long!", NULL);
						}
						else
						{
							char buf[MAX_LEN];
							userlist.changePass(h->name, arg[5]);
							net.send(HAS_N, "[*] \002",(const char *) h->name, "\002 has changed his password", NULL);
							net.send(HAS_B, S_PASSWD, " ", h->name, " ", quoteHexStr(h->pass, buf), NULL);

							ctcp.push("NOTICE ", arg[0], " :Password changed", NULL);
							++userlist.SN;
							userlist.nextSave = NOW + SAVEDELAY;
						}
					}
					return;
				}
				else // pass set
				{
					h = userlist.findHandleByHost(arg[0]);
					if(h && h != userlist.first && (!strcmp((const char*) h->pass, "0000000000000000") || !strlen((const char*) h->pass))) // no pass
					{
						if(strlen(arg[4]) < 8)
						{
							ctcp.push("NOTICE ", arg[0], " :Password must be at least 8 characters long!", NULL);
						}
						else
						{
							char buf[MAX_LEN];
							userlist.changePass(h->name, arg[4]);
							net.send(HAS_N, "[*] \002",(const char *) h->name, "\002 has set his password", NULL);
							net.send(HAS_B, S_PASSWD, " ", h->name, " ", quoteHexStr(h->pass, buf), NULL);

							ctcp.push("NOTICE ", arg[0], " :Password set", NULL);
							++userlist.SN;
							userlist.nextSave = NOW + SAVEDELAY;
						}
					}
					return;
				}
			}

				/* chat */
				if(config.bottype == BOT_MAIN && (!strcmp(arg[3], "chat") || !strcmp(arg[3], ".chat") || !strcmp(arg[3], "!chat")))
				{
					if(userlist.hasPartylineAccess(arg[0]))
						ctcp.push("NOTICE ", arg[0], " :DCC CHAT is disabled. Connect to the partyline listener directly.", NULL);
					return;
				}

			/* mainowner */
			if(creation && !strcmp(arg[3], "mainowner") && strlen(arg[5]))
			{
				if(!strcmp(arg[4], "idiots"))
				{
					net.irc.send("PRIVMSG ", arg[0], " :Invalid handle", NULL);
					return;
				}
				if(strlen(arg[5]) < 8)
				{
					net.irc.send("PRIVMSG ", arg[0], " :Password must be at least 8 characters long", NULL);
					return;
				}

				HANDLE *h = userlist.addHandle(arg[4], 0, 0, 0, 0, arg[4]);
				if(h)
				{
					sprintf(buf, "*%s", strchr(arg[0], '!'));
					userlist.addHost(h, buf, arg[4], NOW);
					userlist.changePass(arg[4], arg[5]);
					userlist.changeFlags(arg[4], "aofmnstx", "");

					net.irc.send("PRIVMSG ", arg[0], " :Account created", NULL);
					printf("[*] Added user `%s' with host `%s' and password `%s'\n", arg[4], buf, arg[5]);
					printf("[*] Now do `/chat %s' and supply owner pass from the config file and %s's password\n", (const char *) ME.nick, arg[4]);

					++userlist.SN;
					userlist.save(config.userlist_file);

#ifdef HAVE_DEBUG
					if(!debug)
#endif
						lurk();
					creation = 0;
					++userlist.SN;
				}
				return;
			}

			/* IRC bootstrap: a fresh slave asks the hub for its host:port
			   credentials; the hub also auto-adds the slave's IRC host here */
			if(config.listenport && !strcmp(arg[3], "!evangeline-link") && strlen(arg[4]) && strlen(arg[5]))
			{
				HANDLE *lh = userlist.findHandle(arg[4]);
				char token[33], msk[MAX_LEN], vtok[33], hostbuf[MAX_LEN];
				const char *sh = strchr(arg[0], '!');

				if(!lh || !userlist.isBot(lh))
				{
					net.irc.send("PRIVMSG ", arg[0], " :!evangeline-link: handle not in botnet (run `.link-slave`/`.link-leaf` first)", NULL);
					return;
				}

				MD5HexHash(token, arg[4], strlen(arg[4]), lh->pass, 16);
				if(strcmp(token, arg[5]))
				{
					net.irc.send("PRIVMSG ", arg[0], " :!evangeline-link: bad token", NULL);
					return;
				}

				if(sh && sh[1] && extendhost(sh + 1, msk, MAX_LEN) && userlist.addHost(lh, msk, "link", NOW) != -1)
				{
					net.send(HAS_B, S_ADDHOST, " ", lh->name, " ", msk, NULL);
					++userlist.SN;
					userlist.nextSave = NOW + SAVEDELAY;
					net.send(HAS_N, "[*] ", lh->name, ": IRC host \002", msk, "\002 added", NULL);
					DEBUG(printf("[*] auto-added host %s for bot %s via !evangeline-link\n", msk, lh->name));
				}

				MD5HexHash(vtok, "hub", 3, lh->pass, 16);
#ifdef HAVE_IPV6
				if(!config.myipv6.isDefault())
					snprintf(hostbuf, MAX_LEN, "%s %d %s", (const char *) config.myipv6, (int) config.listenport, vtok);
				else
#endif
					snprintf(hostbuf, MAX_LEN, "%s %d %s", (const char *) ME.host, (int) config.listenport, vtok);
				net.irc.send("PRIVMSG ", arg[0], " :!evangeline-linkhost ", hostbuf, NULL);
				return;
			}

			/* IRC bootstrap reply: hub told us its host:port; set config.hub
			   (derived pass), persist and link */
			if(config.bottype != BOT_MAIN && strlen(config.mainnick)
				&& !strcmp(arg[3], "!evangeline-linkhost") && strlen(arg[4]) && strlen(arg[5]) && strlen(arg[6]))
			{
				char snd[64], vtok[33], passhex[33], hb[MAX_LEN];
				char *bang;
				unsigned char p[16];

				strncpy(snd, arg[0], sizeof(snd) - 1);
				snd[sizeof(snd) - 1] = '\0';
				if((bang = strchr(snd, '!'))) *bang = '\0';
				if(strcasecmp(snd, config.mainnick))
					return;

				MD5BotPass(p, config.handle, config.botnetword);
				MD5HexHash(vtok, "hub", 3, p, 16);
				if(strcmp(vtok, arg[6]))
					return;

				quoteHexStr(p, passhex, 16);
				snprintf(hb, sizeof(hb), "%s %s %s", arg[4], arg[5], passhex);
				if(!config.hub.setValue("hub", hb, 0) || !config.hub.getPort())
					return;

				config.currentHub = &config.hub;
				config.hub.failures = 0;
				config.save();
				DEBUG(printf("[*] auto-configured hub: %s\n", hb));
				ME.nextConnToHub = NOW;
				ME.connectToHUB();
				return;
			}
		}

		return;
	}
	if(!strcmp(arg[1], "CAP"))
	{
		if(!strcmp(arg[3], "LS"))
		{
			char *cap_list, *cap, *p;
			bool send_cap_end = true;
			cap_list = srewind(data, 4) + 1;
			DEBUG(printf("[*] Capabilities supported: %s\n", cap_list));

			for(cap = strtok_r(cap_list, " ", &p); cap; cap=strtok_r(NULL, " ", &p))
			{
				if(!strcasecmp(cap, "sasl")
					&& config.sasl_mechanism > 0 && config.sasl_username.getLen() && config.sasl_password.getLen())
				{
					net.irc.send("CAP REQ :sasl", NULL);
					send_cap_end = false;
				}
			}

			if(send_cap_end)
			{
				// No caps requested
				net.irc.send("CAP END", NULL);
			}
		}
		if(!strcmp(arg[3], "ACK"))
		{
			char *cap_list, *cap, *p;
			bool send_cap_end = true;
			cap_list = srewind(data, 4) + 1;
			DEBUG(printf("[*] Capabilities acknowledged: %s\n", cap_list));

			for(cap = strtok_r(cap_list, " ", &p); cap; cap=strtok_r(NULL, " ", &p))
			{
				if(!strcasecmp(cap, "sasl"))
				{
					if(config.sasl_mechanism == SASL_MECHANISM_PLAIN)
					{
						net.irc.send("AUTHENTICATE PLAIN", NULL);
					}
#ifdef HAVE_SSL
					if (config.sasl_mechanism == SASL_MECHANISM_SCRAM_SHA_1
						|| config.sasl_mechanism == SASL_MECHANISM_SCRAM_SHA_256
						|| config.sasl_mechanism == SASL_MECHANISM_SCRAM_SHA_512)
					{
						std::string mechanism;

						switch (config.sasl_mechanism)
						{
							case SASL_MECHANISM_SCRAM_SHA_1 : mechanism = "SCRAM-SHA-1"; break;
							case SASL_MECHANISM_SCRAM_SHA_256 : mechanism = "SCRAM-SHA-256"; break;
							case SASL_MECHANISM_SCRAM_SHA_512 : mechanism = "SCRAM-SHA-512"; break;
						}

						delete scram;

						try {
							scram = new Scram(mechanism);
						}
						catch (const std::invalid_argument& e) {
							scram = nullptr;
							net.send(HAS_N, "[-] Could not create SCRAM session: ", e.what(), NULL);
							net.irc.send("QUIT :changing servers", NULL);
						}

						net.irc.send("AUTHENTICATE ", mechanism.c_str(), NULL);
					}
#endif
					send_cap_end = false;
				}
			}

			if(send_cap_end)
			{
				net.irc.send("CAP END", NULL);
			}
		}
	}
	if(!strcmp(arg[0], "AUTHENTICATE"))
	{
		if(!strcmp(arg[1], "+"))
		{
			if(config.sasl_mechanism == SASL_MECHANISM_PLAIN)
			{
				char *auth_message, *auth_message64;
				size_t username_len, password_len, auth_message_len;

				username_len = strlen(config.sasl_username);
				password_len = strlen(config.sasl_password);
				auth_message_len = 2 + username_len + password_len;
				auth_message = (char *) malloc(auth_message_len);
				auth_message[0] = '\0';
				memcpy(auth_message + 1, config.sasl_username, username_len);
				auth_message[1 + username_len] = '\0';
				memcpy(auth_message + 1 + username_len + 1, config.sasl_password, password_len);
				auth_message64 = encode_base64(auth_message_len, (unsigned char*) auth_message);
				ME.sendAuthentication(auth_message64);
				free(auth_message64);
				free(auth_message);
			}
			else if(config.sasl_mechanism == SASL_MECHANISM_EXTERNAL)
			{
				net.irc.send("AUTHENTICATE +", NULL);
			}
		}
#ifdef HAVE_SSL
		if (scram != nullptr && (config.sasl_mechanism == SASL_MECHANISM_SCRAM_SHA_1 ||
								 config.sasl_mechanism == SASL_MECHANISM_SCRAM_SHA_256 ||
								 config.sasl_mechanism == SASL_MECHANISM_SCRAM_SHA_512))
		{
			scram->authenticate(std::string(arg[1]));
		}
#endif
	}
	if(!strcmp(arg[1], "903") )
	{
		// SASL authentication successful
		DEBUG(printf("[-] SASL authentication successful\n"));
		net.irc.send("CAP END", NULL);
	}
	if(!strcmp(arg[1], "904") )
	{
		// SASL authentication failed
		DEBUG(printf("[-] SASL authentication failed\n"));
		net.send(HAS_N, "[-] SASL authentication failed on ", arg[0], NULL);
		net.irc.send("QUIT :changing servers", NULL);
	}
	/* some numeric replies */
	if((i = atoi(arg[1])))
	{
		ch = ME.findChannel(arg[3]);
		if(ch)
		{
			protmodelist::entry *global, *local;

			switch(i)
			{
				case RPL_BANLIST:
					ch->list[BAN].add(arg[4], "", protmodelist::isSticky(arg[4], BAN, ch) ? 0 : set.BIE_MODE_BOUNCE_TIME);
					return;
				case RPL_ENDOFBANLIST:
					++ch->synlevel;
					ch->list[BAN].received=true;
					return;
				case RPL_EXCEPTLIST:
					local=ch->protlist[EXEMPT]->find(arg[4]);
					global=userlist.protlist[EXEMPT]->find(arg[4]);
					ch->list[EXEMPT].add(arg[4], "", ((local && local->sticky) || (global && global->sticky)) ? 0 : set.BIE_MODE_BOUNCE_TIME);
					if(ch->chset->USER_EXEMPTS==2 && !local && !global)
						ch->modeQ[PRIO_LOW].add(NOW+penalty+10, "-e", arg[4]);
					return;
				case RPL_ENDOFEXCEPTLIST:
					++ch->synlevel;
					ch->list[EXEMPT].received=true;
					return;
				case RPL_INVITELIST:
					local=ch->protlist[INVITE]->find(arg[4]);
					global=userlist.protlist[INVITE]->find(arg[4]);
					ch->list[INVITE].add(arg[4], "", ((local && local->sticky) || (global && global->sticky)) ? 0 : set.BIE_MODE_BOUNCE_TIME);
					if(ch->chset->USER_INVITES==2 && !local && !global)
						ch->modeQ[PRIO_LOW].add(NOW+penalty+10, "-I", arg[4]);
					return;
				case RPL_ENDOFINVITELIST:
					++ch->synlevel;
					ch->list[INVITE].received=true;
					return;
				case RPL_REOPLIST:
					local=ch->protlist[REOP]->find(arg[4]);
					global=userlist.protlist[REOP]->find(arg[4]);
					ch->list[REOP].add(arg[4], "", ((local && local->sticky) || (global && global->sticky)) ? 0 : set.BIE_MODE_BOUNCE_TIME);
					if(ch->chset->USER_REOPS==2 && !local && !global)
						ch->modeQ[PRIO_LOW].add(NOW+penalty+10, "-R", arg[4]);
					return;
				case RPL_ENDOFREOPLIST:
					++ch->synlevel;
					ch->list[REOP].received=true;
					return;
				case ERR_NOSUCHNICK:
					penalty -= 2;
					return;
				case ERR_NOSUCHCHANNEL:
					penalty--;
					return;
				default:
					break;
			}
		}
		//not on channel
		else
		{
			//if arg[3] is channel name, set rejoin delay
			if(userlist.findChannel(arg[3]) != -1)
				ME.rejoin(arg[3], set.REJOIN_FAIL_DELAY);
			//else if(chan::valid(arg[3]))
			//	net.send(HAS_N, "[!] \002>> Strange server resposne: ", data, " <<\002", NULL);

			srand();

			switch(i)
			{
				//+i: S_INVITE <seed> <channel>
				case ERR_INVITEONLYCHAN:
				{
					if(userlist.findChannel(arg[3]) != -1)
						net.propagate(NULL, S_INVITE, " ", itoa(rand() % 2048), " ", arg[3], NULL);
					return;
				}
				//+b: S_UNBANME <seed> <nick!ident@host> <channel> [ip] [uid]
				case ERR_BANNEDFROMCHAN:
				{
					if(userlist.findChannel(arg[3]) != -1)
						net.propagate(NULL, S_UNBANME, " ", itoa(rand() % 2048), " ", (const char *) ME.mask,
									  " ", arg[3],  " ", (const char *) ME.ircip, " ", (const char *) ME.uid, NULL);
						return;
				}
				//+l: S_BIDLIMIT <seed> <channel>
				case ERR_CHANNELISFULL:
				{
					if(userlist.findChannel(arg[3]) != -1)
						net.propagate(NULL, S_BIDLIMIT, " ", itoa(rand() % 2048), " ", arg[3], NULL);
					return;
				}
				//+k: S_KEY <seed> <channel>
				case ERR_BADCHANNELKEY:
				{
					if(userlist.findChannel(arg[3]) != -1)
						net.propagate(NULL, S_KEY, " ", itoa(rand() % 2048), " ", arg[3], NULL);
					return;
				}
				//k:lined
				case ERR_YOUREBANNEDCREEP:
				{
					net.irc.status |= STATUS_KLINED;
					mem_strcpy(net.irc.name, arg[0]);
					a = srewind(data, 10);
					if(a)
						net.irc.close(a);
					else
						net.irc.close("K-lined");
					return;
				}
				default:
				break;
			}
		}
	}

	HOOK(crap, crap(data));
	stopParsing=false;
}
