#ifndef PSOTNIC_GLOBAL_VAR_H
#define PSOTNIC_GLOBAL_VAR_H 1

extern time_t NOW;
extern client ME;
extern settings set;
extern ul userlist;
extern prvset pset;
extern CONFIG config;
extern char *thisfile;
extern inet net;
extern penal penalty;
extern EXPANDINFO expandinfo;
extern ign ignore;
extern fifo ctcp;
extern fifo invite;
extern QTIsaac<8, int> Isaac;
extern idle antiidle;
extern unit_table ut_time[];
extern unit_table ut_perc[];
extern asyn_socks5 socks5;
extern update psotget;
extern int hostNotify;
extern int stopEvangeline;
extern time_t floodBackoffUntil;
extern unsigned long long ircLagMs;
extern unsigned long long ircLagSentMs;
extern time_t ircLagAt;
extern ptrlist<module> modules;
extern bool stopParsing;
extern ptrlist<linkpending> pendingLinks;

#ifdef HAVE_DEBUG
extern int debug;
#endif
extern int creation;
extern int autocrypt;
extern int configOnly;

#ifdef HAVE_TCL
extern tcl tclparser;
#endif

//extern int noulimit;

#ifdef HAVE_ADNS
extern adns *resolver;
#endif

#ifdef HAVE_IRC_BACKTRACE
extern char irc_buf[IRC_BUFS][MAX_LEN];
extern int current_irc_buf;
#endif

#endif
