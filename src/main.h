/*  Open DC Hub - A Linux/Unix version of the Direct Connect hub.
 *  Copyright (C) 2002,2003  Jonatan Nilsson 
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */



#include <sys/types.h>

/* Using the 32 bit int (sometimes even 64 bits) for boolean variables and
 * other variables that always will be between -128 and 127 would be a waste
 * of space, especially those in the user_t struct since it's used to 
 * frequently.  */
#define BYTE char

#define ALARM_TIME         900             /* Seconds between alarm calls */ 
#define MAX_NICK_LEN       50              /* Maximum length of nickname, 20 is max in win client */
#define MAX_HOST_LEN       121             /* Maximum length of hostname */
#define MAX_VERSION_LEN    30              /* Maximum length of version name */
#define MAX_MESS_SIZE      0xFFFF          /* Maximum size of a received message */
#define MAX_HUB_NAME       25              /* Maximum length of hub name, 25 from win version */
#define MAX_HUB_DESC       100             /* Maximum length of hub description */
#define MAX_ADMIN_PASS_LEN 50              /* Maximum length of admin pass */
#define MAX_BUF_SIZE       1000000         /* Maximum length of users buf */
#define MAX_FDP_LEN	   100		   /* Maximum length of file/dir/path variables */
#define USER_LIST_ENT_SIZE 173             /* Size of an entry in the user list, 
					    * nick length + host length.  */

#define CONFIG_FILE        "config"        /* Name of config file */
#define MOTD_FILE          "motd"          /* Name of file containing the motd */
#define BAN_FILE           "banlist"       /* Name of file with banlist */
#define NICKBAN_FILE       "nickbanlist"   /* Name of file with nick banlist */
#define ALLOW_FILE         "allowlist"     /* Name of file with allowlist */
#define REG_FILE           "reglist"       /* Name of file with list of registered users */
#define LINK_FILE          "linklist"      /* Name of file with list of linked hubs */
#define OP_PERM_FILE       "op_permlist"   /* Name of file with op permissions */
#define LOG_FILE           "log"           /* Name of log file */
#define UN_SOCK_NAME       "odch"          /* Name of unix socket file */
#define USER_LIST          "odchlist"      /* Name of temporary user list file */
#define SCRIPT_DIR         "scripts"       /* Name of script directory.  */
#define SYSLOG_IDENT       "odch"          /* Identity for system log */

#define INIT_MESS          1
#define HELLO_MESS         2 
#define HUB_FULL_MESS      3
#define BAN_MESS           4
#define GET_PASS_MESS      5
#define LOGGED_IN_MESS     6
#define OP_LOGGED_IN_MESS  7
#define BAD_PASS_MESS      8
#define INIT_ADMIN_MESS    9
#define	GET_PASS_MESS2	  10

/* The different user types */
#define UNKEYED            0x1
#define NON_LOGGED         0x2
#define REGULAR            0x4
#define REGISTERED         0x8
#define OP                 0x10
#define OP_ADMIN           0x20
#define ADMIN              0x40
#define FORKED             0x80
#define LINKED             0x100
#define SCRIPT             0x200
#define NON_LOGGED_ADM     0x400

/* The different OP permissions */
#define BAN_ALLOW          0x1
#define USER_INFO          0x2
#define MASSMESSAGE        0x4
#define USER_ADMIN         0x8

#define PRIV               0
#define TO_ALL             1

#define ALLOW              0
#define BAN                1
#define REG                2
#define CONFIG             3
#define LINK               4
#define NICKBAN            5

#define HOST               0
#define IP                 1

#ifndef HAVE_STRTOLL
# ifdef HAVE_STRTOQ
#  define strtoll(X, Y, Z) (long long)strtoq(X, Y, Z)
# endif
#endif

/* Possible values for user->rem  */
#define REMOVE_USER        0x1 
#define SEND_QUIT          0x2
#define REMOVE_FROM_LIST   0x4


struct user_t 
{ 
   int sock;                          /* What socket the user is on */ 
   long unsigned ip;                  /* Ip address of user */ 
   char hostname[MAX_HOST_LEN+1];     /* Hostname of user */
   int  type;                         /* Type of user, types defined above. */
   char nick[MAX_NICK_LEN+1];         /* Nickname of user */ 
   char version[MAX_VERSION_LEN+1];   /* Version of client */ 
   char *email;                       /* Email of user, optional */ 
   char *desc;                        /* Description of users files, optional */ 
   BYTE con_type;                     /* Users connection type: 1: 28,8; 2: 33,6;  
				       3: 56; 4: Satellite; 5: ISDN; 6: DSL;  
				       7: Cable; 8: LAN(T1); 9: LAN(T3);
				       10: Wireless; 11: Modem; 12:Netlimiter;
				       255: Unknown */ 
   BYTE flag;                         /* Users flag, represented by one byte */ 
   long long share;                   /* Size of users share in bytes */
   char *buf;                         /* If a command doesnt't fit in one packet,
				       * it's saved here for later */
   char *outbuf;                      /* Buf of stuff that will be sent to a user */
   BYTE timeout;                      /* Check user timeout */
   struct user_t *next;               /* Next user in list*/
   int key;                           /* Start value for the generated key */
   BYTE rem;                          /* 1 if user is to be removed */
   time_t last_search;                /* Time of the last search attempt */
   int  permissions;                  /* Operator permissions (listed above) */
};

/* This is used for a linked list of the humans. This is to get faster 
 * send_to_all:s. I'm pretending it contains the user's sockets, but it really
 * only contains pointers to the users.  */
struct sock_t 
{
   struct user_t *user;
   struct sock_t *next;
};

/* This is system defined as "semun" on some systems, but not defined at all on
 * other systems. I'm just defining it as my_semun for simplicity.  */
union my_semun
{ 
      int val;                    /* value for SETVAL */
      struct semid_ds *buf;       /* buffer for IPC_STAT, IPC_SET */
      unsigned short int *array;  /* array for GETALL, SETALL */
      struct seminfo *__buf;      /* buffer for IPC_INFO */
};

/* Global variables */
pid_t  pid;                         /* Pid of process if parent, if it's a child, pid is 0, for scripts, it's -1 and for hublist upload processes it's -2  */
int    users_per_fork;              /* Users in hub when fork occurs */
struct user_t *non_human_user_list; /* List of non-human users */
struct user_t **human_hash_table;  /* Hashtable of human users */
struct sock_t *human_sock_list;
unsigned int listening_port;        /* Port on which we listen for connections */
unsigned int admin_port;            /* Administration port */
BYTE   admin_localhost;             /* 1 to bind administration port localhost only */
int    admin_listening_socket;      /* Socket for incoming connections from admins */
int    listening_socket;            /* Socket for incoming connections from clients */
int    listening_unx_socket;        /* Socket for forked processes to connect to */
int    listening_udp_socket;        /* Socket for incoming multi-hub messages */
char   hub_name[MAX_HUB_NAME+1];    /* Name of the hub. */
BYTE   debug;                       /* 1 for debug mode, else 0 */
BYTE   registered_only;             /* 1 for registered only mode, else 0 */
BYTE   hublist_upload;              /* User set variable, if 1, upload */
BYTE   ban_overrides_allow;         /* 1 for banlist to override allowlist */
BYTE   redir_on_min_share;          /* 1 if user should be redirected if user shares less than the minimum share */
BYTE   check_key;                   /* Checks key from client if set to 1 */
BYTE   reverse_dns;                 /* If 1, reverse dns lookups are made on newly connected clients.  */
BYTE   verbosity;                   /* This sets the verbosity of the log file, may vary from 0 to 5 */
char   hub_description[MAX_HUB_DESC+1]; /* The description of hub that is uploaded to public hublist */
char   public_hub_host[MAX_HOST_LEN+1]; /* This is the hostname to upload hub description to */
char   min_version[MAX_VERSION_LEN+1];  /* Minimum client verison to allow users to the hub. */
char   hub_hostname[MAX_HOST_LEN+1];    /* This is the hostname that is uploaded to the public hublist, so don't try setting this to "127.0.0.1" or "localhost" */
char   redirect_host[MAX_HOST_LEN+1]; /* Host to redirect users to if hub is full */
char   *hub_full_mess;
int    max_users;
int    max_sockets;
long long min_share;      /* Minimum share for clients */
int    total_share_shm;    /* Identifier for the shared memory segment that contains the total share on hub, uploaded to public hub list.  */
int    total_share_sem;    /* Semaphore Id for the shared momry segment above.  */
int    user_list_shm_shm;  /* Identifier for shared memory segment containing the shared memory segment for the user list :)  */
int    user_list_sem;      /* And a semaphore to control access to it.  */ 
char   admin_pass[MAX_ADMIN_PASS_LEN+1];
char   link_pass[MAX_ADMIN_PASS_LEN+1]; /* Password for hub linking */
char   default_pass[MAX_ADMIN_PASS_LEN+1];
BYTE   upload;                      /* keeps track on when it's time to upload to public hub list */
BYTE   quit;
BYTE   do_write;
BYTE   do_send_linked_hubs;
BYTE   do_purge_user_list;
BYTE   do_fork;
BYTE   script_reload;
char   config_dir[MAX_FDP_LEN+1];
char   un_sock_path[MAX_FDP_LEN+1];
char   logfile[MAX_FDP_LEN+1];	/* Logfile if specifically set */
BYTE   syslog_enable;
BYTE   syslog_switch;
BYTE   searchcheck_exclude_internal;
BYTE   searchcheck_exclude_all;
int    kick_bantime;
int    searchspam_time;
uid_t  dchub_user;
gid_t  dchub_group;
char   working_dir[MAX_FDP_LEN+1];
time_t hub_start_time;
int    max_email_len;
int    max_desc_len;
BYTE   crypt_enable;
int    current_forked;   /* This is used to keep track on which 
			  * process that holds the listening
			  * sockets.  */

/* Functions */
void   hub_mess(struct user_t *user, int mess_type);
int    new_human_user(int sock);
int    socket_action(struct user_t *user);
int    udp_action(void);
void   remove_user(struct user_t *our_user, int send_quit, int remove_from_list);
void   send_init(int sock);
void   do_upload_to_hublist(void);
int    handle_command(char *buf, struct user_t *user);
void   send_user_info(struct user_t *from_user, char *to_user_nick, int all);
void   init_sig(void);
void   remove_all(int type, int send_quit, int remove_from_list);
void   new_forked_process(void);
void   kill_forked_process(void);
void   term_signal(int z);
void   alarm_signal(int z);
int    set_default_vars(void);
void   new_admin_connection();
void   add_non_human_to_list(struct user_t *user);
void   remove_non_human(struct user_t *our_user);
void   add_human_to_hash(struct user_t *user);
void   remove_human_from_hash(char *nick);
struct user_t* get_human_user(char *nick);
void   remove_human_user(struct user_t *user);
void   encrypt_pass(char* password);
