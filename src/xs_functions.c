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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_PERL

#include <stdlib.h>
#include <stdio.h>
#include <EXTERN.h>
#include <perl.h>
#include <XSUB.h>
#include <sys/shm.h>

#include "xs_functions.h"
#include "main.h"
#include "network.h"
#include "fileio.h"
#include "utils.h"
#include "userlist.h"

#define EXTERN_C extern

EXTERN_C void boot_DynaLoader (CV* cv);
static char *user_list = NULL;
static char *description = NULL;
static char *email = NULL;

XS(xs_get_type)
{
   struct user_t *user;
   int type;
   dXSARGS;
   
   if(items != 1)
     XSRETURN_UNDEF;
   
   if(!SvPOK(ST(0)))
     XSRETURN_UNDEF;
   
   if((user = get_human_user(SvPVX(ST(0)))) == NULL)
     XSRETURN_IV(0);
   
   type = user->type;
   
   XSRETURN_IV(type);
}

XS(xs_get_ip)
{
   struct user_t *user;
   char ip[20];
   dXSARGS;
   
   if(items != 1)
     XSRETURN_UNDEF;
   
   if(!SvPOK(ST(0)))
     XSRETURN_UNDEF;
   
   if((user = get_human_user(SvPVX(ST(0)))) == NULL)
     XSRETURN_UNDEF;
   
   sprintf(ip, "%s", ip_to_string(user->ip));
   
   XSRETURN_PV(ip);
}

XS(xs_get_hostname)
{
   struct user_t *user;
   char hostname[MAX_HOST_LEN+1];
   dXSARGS;
   
   /* Check that number of items on the stack equals 1.  */
   if(items != 1)
     XSRETURN_UNDEF;
   
   /* Check that the first one is a string.  */
   if(!SvPOK(ST(0)))
     XSRETURN_UNDEF;
   
   /* Get the user.  */
   if((user = get_human_user(SvPVX(ST(0)))) == NULL)
     XSRETURN_UNDEF;
   
   /* Get hostname.  */
   strcpy(hostname, user->hostname);
   
   /* Return the hostname and exit.  */
   XSRETURN_PV(hostname);
}

XS(xs_get_version)
{
   struct user_t *user;
   char version[MAX_VERSION_LEN+1];
   dXSARGS;
   
   if(items != 1)
     XSRETURN_UNDEF;
   
   if(!SvPOK(ST(0)))
     XSRETURN_UNDEF;
   
   if((user = get_human_user(SvPVX(ST(0)))) == NULL)
     XSRETURN_UNDEF;
   
   strcpy(version, user->version);
   
   XSRETURN_PV(version);
}

XS(xs_get_description)
{
   struct user_t *user;
   dXSARGS;
   
   if(items != 1)
     XSRETURN_UNDEF;
   
   if(!SvPOK(ST(0)))
     XSRETURN_UNDEF;
   
   if((user = get_human_user(SvPVX(ST(0)))) == NULL)
     XSRETURN_UNDEF;

   if(user->desc == NULL)
     XSRETURN_PV("");
   
   /* If we just allocate new memory every time this is called, we will get
    * a memory leak.  */
   if(description != NULL)
     free(description);
   
   if((description = (char *) malloc(sizeof(char) * (strlen(user->desc) + 1))) == NULL)
     {
	logprintf(1, "Error - In get_description()/malloc(): ");
	logerror(1, errno);
	quit = 1;
	XSRETURN_UNDEF;
     }
   
   strcpy(description, user->desc);
   
   XSRETURN_PV(description);
}

XS(xs_get_email)
{
   struct user_t *user;
   dXSARGS;
   
   if(items != 1)
     XSRETURN_UNDEF;
   
   if(!SvPOK(ST(0)))
     XSRETURN_UNDEF;
   
   if((user = get_human_user(SvPVX(ST(0)))) == NULL)
     XSRETURN_UNDEF;

   if(user->email == NULL)
     XSRETURN_PV("");
   
   /* If we just allocate new memory every time this is called, we will get
    * a memory leak.  */
   if(email != NULL)
     free(email);
   
   if((email = (char *) malloc(sizeof(char) * (strlen(user->email) + 1))) == NULL)
     {
	logprintf(1, "Error - In get_email()/malloc(): ");
	logerror(1, errno);
	quit = 1;
	XSRETURN_UNDEF;
     }
   
   strcpy(email, user->email);
   
   XSRETURN_PV(email);
}

XS(xs_get_connection)
{
   struct user_t *user;
   char connection;
   dXSARGS;
   
   if(items != 1)
     XSRETURN_UNDEF;
   
   if(!SvPOK(ST(0)))
     XSRETURN_UNDEF;
   
   if((user = get_human_user(SvPVX(ST(0)))) == NULL)
     XSRETURN_UNDEF;
   
   connection = user->con_type;
   
   XSRETURN_IV(connection);
}

XS(xs_get_flag)
{
   struct user_t *user;
   char flag;
   dXSARGS;
   
   if(items != 1)
     XSRETURN_UNDEF;
   
   if(!SvPOK(ST(0)))
     XSRETURN_UNDEF;
   
   if((user = get_human_user(SvPVX(ST(0)))) == NULL)
     XSRETURN_UNDEF;
   
   flag = user->flag;
   
   XSRETURN_IV(flag);
}

XS(xs_get_share)
{
   struct user_t *user;
   long long share;
   dXSARGS;
   
   if(items != 1)
     XSRETURN_UNDEF;
   
   if(!SvPOK(ST(0)))
     XSRETURN_UNDEF;
   
   if((user = get_human_user(SvPVX(ST(0)))) == NULL)
     XSRETURN_UNDEF;
   
   share = user->share;
   
   XSRETURN_NV(share);
}

XS(xs_check_if_banned)
{
   struct user_t *user;
   int ret;
   dXSARGS;
   
   if(items != 1)
     XSRETURN_UNDEF;
   
   if(!SvPOK(ST(0)))
     XSRETURN_UNDEF;
   
   if((user = get_human_user(SvPVX(ST(0)))) == NULL)
     XSRETURN_UNDEF;
   
   ret = check_if_banned(user, BAN);
   if(ret != 1)
     ret = check_if_banned(user, NICKBAN);
   
   (ret == 1) ? XSRETURN_IV(1) : XSRETURN_IV(0);
}

XS(xs_check_if_allowed)
{
   struct user_t *user;
   int ret;
   dXSARGS;
   
   if(items != 1)
     XSRETURN_UNDEF;
   
   if(!SvPOK(ST(0)))
     XSRETURN_UNDEF;
   
   if((user = get_human_user(SvPVX(ST(0)))) == NULL)
     XSRETURN_UNDEF;
   
   ret = check_if_allowed(user);
   
   (ret == 1) ? XSRETURN_IV(1) : XSRETURN_IV(0);
}

XS(xs_data_to_user)
{
   struct user_t *user;
   char *data;
   dXSARGS;
   
   if(items != 2)
     XSRETURN_UNDEF;

   if(!SvPOK(ST(0)))
     XSRETURN_UNDEF;

   if(!SvPOK(ST(1)))
     XSRETURN_UNDEF;
   
   if((user = get_human_user(SvPVX(ST(0)))) == NULL)
     XSRETURN_UNDEF;

   data = SvPVX(ST(1));
   
   /* The ScriptToUser command is handled by the parent process. Eventually, 
    * only the data part is sent to the user.  */
   uprintf(non_human_user_list, "$ScriptToUser %s ", user->nick);
   
   send_to_user(data, non_human_user_list);
   
   if(data[strlen(data) - 1] != '|')
     send_to_user("|", non_human_user_list);
}

XS(xs_kick_user)
{
   struct user_t *user;
   dXSARGS;
   
   if(items != 1)
     XSRETURN_UNDEF;
   
   if(!SvPOK(ST(0)))
     XSRETURN_UNDEF;
   
   if((user = get_human_user(SvPVX(ST(0)))) == NULL)
     XSRETURN_UNDEF;
   
   /* Using the regular Kick command.  */
   uprintf(non_human_user_list, "$Kick %s|", user->nick);
}

XS(xs_force_move_user)
{
   struct user_t *user;
   char *host;
   dXSARGS;
   
   if(items != 2)
     XSRETURN_UNDEF;
   
   if(!SvPOK(ST(0)))
     XSRETURN_UNDEF;
   
   if(!SvPOK(ST(1)))
     XSRETURN_UNDEF;
   
   if((user = get_human_user(SvPVX(ST(0)))) == NULL)
     XSRETURN_UNDEF;
   
   host = SvPVX(ST(1));
   
   /* Using the ScriptToUser command to send the command to the user.  */
   uprintf(non_human_user_list, "$ScriptToUser %s $ForceMove %s|", 
	   user->nick, host);
   
   /* After that, the user is kicked.  */
   uprintf(non_human_user_list, "$Kick %s|", user->nick);
}

XS(xs_get_variable)
{
   char *var_name;
   long long share;
   double uptime;
   dXSARGS;
   
   if(items != 1)
     XSRETURN_UNDEF;
   
   if(!SvPOK(ST(0)))
     XSRETURN_UNDEF;
   
   var_name = SvPVX(ST(0));
   
   if(!strncmp(var_name, "hub_name", 8))
     XSRETURN_PV(hub_name);
   else if(!strncmp(var_name, "max_users", 9))
     XSRETURN_IV(max_users);
   else if(!strncmp(var_name, "hub_full_mess", 13))
     XSRETURN_PV(hub_full_mess);
   else if(!strncmp(var_name, "hub_description", 15))
     XSRETURN_PV(hub_description);
   else if(!strncmp(var_name, "min_share", 9))
     XSRETURN_NV(min_share);
   else if(!strncmp(var_name, "admin_pass", 10))
     XSRETURN_PV(admin_pass);
   else if(!strncmp(var_name, "default_pass", 12))
     XSRETURN_PV(default_pass);
   else if(!strncmp(var_name, "link_pass", 9))
     XSRETURN_PV(link_pass);
   else if(!strncmp(var_name, "users_per_fork", 14))
     XSRETURN_IV(users_per_fork);
   else if(!strncmp(var_name, "listening_port", 14))
     XSRETURN_IV(listening_port);
   else if(!strncmp(var_name, "admin_port", 10))
     XSRETURN_IV(admin_port);
   else if(!strncmp(var_name, "admin_localhost", 15))
     XSRETURN_IV(admin_localhost);
   else if(!strncmp(var_name, "public_hub_host", 15))     
     XSRETURN_PV(public_hub_host);
   else if(!strncmp(var_name, "hub_hostname", 12))
     XSRETURN_PV(hub_hostname);
   else if(!strncmp(var_name, "min_version", 11))
     XSRETURN_PV(min_version);
   else if(!strncmp(var_name, "hublist_upload", 14))
     XSRETURN_IV(hublist_upload);
   else if(!strncmp(var_name, "redirect_host", 13))
     XSRETURN_PV(redirect_host);
   else if(!strncmp(var_name, "registered_only", 15))
     XSRETURN_IV(registered_only);
   else if(!strncmp(var_name, "check_key", 9))
     XSRETURN_IV(check_key);
   else if(!strncmp(var_name, "reverse_dns", 11))
     XSRETURN_IV(reverse_dns);
   else if(!strncmp(var_name, "verbosity", 9))
     XSRETURN_IV(verbosity);
   else if(!strncmp(var_name, "redir_on_min_share", 18))
     XSRETURN_IV(redir_on_min_share);
   else if(!strncmp(var_name, "ban_overrides_allow", 19))
     XSRETURN_IV(ban_overrides_allow);
   else if(!strncmp(var_name, "syslog_enable", 13))
     XSRETURN_IV(syslog_enable);
   else if(!strncmp(var_name, "searchcheck_exclude_internal", 28))
     XSRETURN_IV(searchcheck_exclude_internal);
   else if(!strncmp(var_name, "searchcheck_exclude_all", 23))
     XSRETURN_IV(searchcheck_exclude_all);
   else if(!strncmp(var_name, "kick_bantime", 12))
     XSRETURN_IV(kick_bantime);
   else if(!strncmp(var_name, "searchspam_time", 15))
     XSRETURN_IV(searchspam_time);
   else if(!strncmp(var_name, "max_email_len", 13))
     XSRETURN_IV(max_email_len);
   else if(!strncmp(var_name, "max_desc_len", 12))
     XSRETURN_IV(max_desc_len);
   else if(!strncmp(var_name, "crypt_enable", 12))
     XSRETURN_IV(crypt_enable);
   else if(!strncmp(var_name, "working_dir", 11))
     XSRETURN_PV(working_dir);
   else if(!strncmp(var_name, "hub_uptime", 10))
     {
	uptime = get_uptime();
	XSRETURN_NV(uptime);
     }
   else if(!strncmp(var_name, "total_share", 11))
     {
	share = get_total_share();
	XSRETURN_NV(share);
     }
}

XS(xs_set_variable)
{   
   char *var_name;
   char *value;
   dXSARGS;
   
   if(items != 2)
     XSRETURN_UNDEF;
   
   if(!SvPOK(ST(0)))
     XSRETURN_UNDEF;
   
   if(!SvPOK(ST(1)))
     XSRETURN_UNDEF;
   
   var_name = SvPVX(ST(0));
   value = SvPVX(ST(1));
   
   send_to_user("$Set ", non_human_user_list);
   send_to_user(var_name, non_human_user_list);
   send_to_user(" ", non_human_user_list);
   send_to_user(value, non_human_user_list);
   send_to_user("|", non_human_user_list);
}

XS(xs_add_ban_entry)
{   
   char *entry;
   dXSARGS;
   
   if(items != 1)
     XSRETURN_UNDEF;
   
   if(!SvPOK(ST(0)))
     XSRETURN_UNDEF;
   
   entry = SvPVX(ST(0));
   
   send_to_user("$Ban ", non_human_user_list);
   send_to_user(entry, non_human_user_list);
   send_to_user("|", non_human_user_list);
}

XS(xs_add_nickban_entry)
{   
   char *entry;
   dXSARGS;
   
   if(items != 1)
     XSRETURN_UNDEF;
   
   if(!SvPOK(ST(0)))
     XSRETURN_UNDEF;
   
   entry = SvPVX(ST(0));
   
   send_to_user("$NickBan ", non_human_user_list);
   send_to_user(entry, non_human_user_list);
   send_to_user("|", non_human_user_list);
}

XS(xs_add_allow_entry)
{   
   char *entry;
   dXSARGS;
   
   if(items != 1)
     XSRETURN_UNDEF;
   
   if(!SvPOK(ST(0)))
     XSRETURN_UNDEF;
   
   entry = SvPVX(ST(0));
   
   send_to_user("$Allow ", non_human_user_list);
   send_to_user(entry, non_human_user_list);
   send_to_user("|", non_human_user_list);
}

XS(xs_remove_ban_entry)
{   
   char *entry;
   dXSARGS;
   
   if(items != 1)
     XSRETURN_UNDEF;
   
   if(!SvPOK(ST(0)))
     XSRETURN_UNDEF;
   
   entry = SvPVX(ST(0));
   
   send_to_user("$Unban ", non_human_user_list);
   send_to_user(entry, non_human_user_list);
   send_to_user("|", non_human_user_list);
}

XS(xs_remove_allow_entry)
{   
   char *entry;
   dXSARGS;
   
   if(items != 1)
     XSRETURN_UNDEF;
   
   if(!SvPOK(ST(0)))
     XSRETURN_UNDEF;
   
   entry = SvPVX(ST(0));
   
   send_to_user("$Unallow ", non_human_user_list);
   send_to_user(entry, non_human_user_list);
   send_to_user("|", non_human_user_list);
}

XS(xs_remove_nickban_entry)
{   
   char *entry;
   dXSARGS;
   
   if(items != 1)
     XSRETURN_UNDEF;
   
   if(!SvPOK(ST(0)))
     XSRETURN_UNDEF;
   
   entry = SvPVX(ST(0));
   
   send_to_user("$UnNickBan ", non_human_user_list);
   send_to_user(entry, non_human_user_list);
   send_to_user("|", non_human_user_list);
}

XS(xs_add_reg_user)
{   
   char *nick;
   char *password;
   int type;
   dXSARGS;
   
   if(items != 3)
     XSRETURN_UNDEF;
   
   if(!SvPOK(ST(0)))
     XSRETURN_UNDEF;
   
   if(!SvPOK(ST(1)))
     XSRETURN_UNDEF;
   
   if(!SvIOK(ST(2)))
     XSRETURN_UNDEF;
   
   nick = SvPVX(ST(0));
   password = SvPVX(ST(1));
   type = SvIVX(ST(2));
   
   send_to_user("$AddRegUser ", non_human_user_list);
   send_to_user(nick, non_human_user_list);
   send_to_user(" ", non_human_user_list);
   send_to_user(password, non_human_user_list);
   uprintf(non_human_user_list, " %d|", type);
}

XS(xs_remove_reg_user)
{   
   char *entry;
   dXSARGS;
   
   if(items != 1)
     XSRETURN_UNDEF;
   
   if(!SvPOK(ST(0)))
     XSRETURN_UNDEF;
   
   entry = SvPVX(ST(0));
   
   send_to_user("$RemoveRegUser ", non_human_user_list);
   send_to_user(entry, non_human_user_list);
   send_to_user("|", non_human_user_list);
}

XS(xs_add_linked_hub)
{   
   char *host;
   int port;
   dXSARGS;
   
   if(items != 2)
     XSRETURN_UNDEF;
   
   if(!SvPOK(ST(0)))
     XSRETURN_UNDEF;
   
   if(!SvIOK(ST(1)))
     XSRETURN_UNDEF;
   
   host = SvPVX(ST(0));
   port = SvIVX(ST(1));
   
   send_to_user("$AddLinkedHub ", non_human_user_list);
   send_to_user(host, non_human_user_list);
   uprintf(non_human_user_list, " %d|", port);
}

XS(xs_remove_linked_hub)
{   
   char *host;
   int port;
   dXSARGS;
   
   if(items != 2)
     XSRETURN_UNDEF;
   
   if(!SvPOK(ST(0)))
     XSRETURN_UNDEF;
   
   if(!SvIOK(ST(1)))
     XSRETURN_UNDEF;
   
   host = SvPVX(ST(0));
   port = SvIVX(ST(1));
   
   send_to_user("$RemoveLinkedHub ", non_human_user_list);
   send_to_user(host, non_human_user_list);
   uprintf(non_human_user_list, " %d|", port);
}

XS(xs_data_to_all)
{   
   char *data;
   dXSARGS;
   
   if(items != 1)
     XSRETURN_UNDEF;
   
   if(!SvPOK(ST(0)))
     XSRETURN_UNDEF;
   
   data = SvPVX(ST(0));
   
   send_to_user("$DataToAll ", non_human_user_list);
   send_to_user(data, non_human_user_list);
}

XS(xs_count_users)
{
   int i;   
   dXSARGS;
   
   if(items != 0)
     XSRETURN_UNDEF;
   
   i = count_all_users();
   
   XSRETURN_IV(i);
}

XS(xs_register_script_name)
{
   char *nick;
   char c;
   char randpass[11];
   char regstring[MAX_NICK_LEN + 30];
   int i;
   
   dXSARGS;
   
   if(items != 1)
     XSRETURN_UNDEF;

   if(!SvPOK(ST(0)))
     XSRETURN_UNDEF;
   
   nick = SvPVX(ST(0));
   
   /* Check that it's a proper nick.  */
   if((nick[0] == '\0') || (nick[0] == '\r') || (nick[0] == '\n') 
      || (strlen(nick) > MAX_NICK_LEN))
     XSRETURN_UNDEF;
   
   /* Register the nick in the nicklist.  */
   if(check_if_registered(nick) == 0)
     {
	/* Generate a random password.  */
	srand(time(NULL));
	for(i = 0; i <= 9; i++)
	  {
	     c = 'A' + rand()%('z' - 'a');
	     randpass[i] = c;
	  }
	randpass[10] = '\0';
	sprintf(regstring, "$AddRegUser %s %s %d|", nick, randpass, 2);
	add_reg_user(regstring, NULL);
     }
   
   send_to_user("$ValidateNick ", non_human_user_list);
   send_to_user(nick, non_human_user_list);
   send_to_user("|", non_human_user_list);
}

XS(xs_check_if_registered)
{   
   int isregged;
   dXSARGS;
   if(items != 1)
     XSRETURN_UNDEF;
   if (!SvPOK(ST(0)))
     XSRETURN_UNDEF;
   isregged = check_if_registered( SvPVX(ST(0)) );
   if(isregged == -1)
     XSRETURN_UNDEF;
   XSRETURN_IV(isregged);
}

XS(xs_get_user_list)
{
   char *buf, *bufp;
   char temp_nick[MAX_NICK_LEN+1];
   char temp_host[MAX_HOST_LEN+1];
   int spaces=0, entries=0;
   int i;  

   dXSARGS;
   
   if(items != 0)
     XSRETURN_UNDEF;
   
   if(user_list != NULL)
     free(user_list);
   
   if((user_list = malloc(sizeof(char) * 2)) == NULL)
     {	
	logprintf(1, "Error - In get_user_list()/malloc(): ");
	logerror(1, errno);
	quit = 1;
	XSRETURN_UNDEF;
     }
   
   *user_list = '\0';
   
   sem_take(user_list_sem);
   
   /* Attach to the shared segment */
   if((buf = (char *)shmat(get_user_list_shm_id(), NULL, 0))
      == (char *)-1)
     {	
	logprintf(1, "Error - In get_user_list()/shmat(): ");
	logerror(1, errno);
	sem_give(user_list_sem);
	quit = 1;
	XSRETURN_UNDEF;
     }
   
   if(sscanf(buf, "%d %d", &spaces, &entries) != 2)
     {	
	logprintf(1, "Error - In get_op_list(): Couldn't get number of entries\n");
	shmdt(buf);
	sem_give(user_list_sem);
	quit = 1;
	XSRETURN_UNDEF;
     }
   
   bufp = buf + 30;
   
   for(i = 1; i <= spaces; i++)
     {       
	if(*bufp != '\0')
	  {	     
	     sscanf(bufp, "%50s %120s", temp_nick, temp_host);
	     if((user_list = realloc(user_list, sizeof(char)
		* (strlen(user_list) + strlen(temp_nick) + 2))) == NULL)
	       {		       
		  logprintf(1, "Error - In get_user_list()/realloc(): ");
		  logerror(1, errno);
		  shmdt(buf);
		  sem_give(user_list_sem);
		  quit = 1;
		  XSRETURN_UNDEF;
	       }		  
	     sprintfa(user_list, "%s ", temp_nick);	       	     
	  }	
	bufp += USER_LIST_ENT_SIZE;
     }
   
   shmdt(buf);
   sem_give(user_list_sem);        
   
   XSRETURN_PV(user_list);
}
   
EXTERN_C void xs_init(void)
{
   char *file = __FILE__;
   newXS("DynaLoader::boot_DynaLoader", boot_DynaLoader, file);
   newXS("odch::get_type", xs_get_type, "xs_functions.c");
   newXS("odch::get_ip", xs_get_ip, "xs_functions.c");
   newXS("odch::get_hostname", xs_get_hostname, "xs_functions.c");
   newXS("odch::get_version", xs_get_version, "xs_functions.c");
   newXS("odch::get_description", xs_get_description, "xs_functions.c");
   newXS("odch::get_email", xs_get_email, "xs_functions.c");
   newXS("odch::get_connection", xs_get_connection, "xs_functions.c");
   newXS("odch::get_flag", xs_get_flag, "xs_functions.c");
   newXS("odch::get_share", xs_get_share, "xs_functions.c");
   newXS("odch::check_if_banned", xs_check_if_banned, "xs_functions.c");
   newXS("odch::check_if_allowed", xs_check_if_allowed, "xs_functions.c");
   newXS("odch::data_to_user", xs_data_to_user, "xs_functions.c");
   newXS("odch::kick_user", xs_kick_user, "xs_functions.c");
   newXS("odch::force_move_user", xs_force_move_user, "xs_functions.c");
   newXS("odch::get_variable", xs_get_variable, "xs_functions.c");
   newXS("odch::set_variable", xs_set_variable, "xs_functions.c");
   newXS("odch::add_ban_entry", xs_add_ban_entry, "xs_functions.c");
   newXS("odch::add_nickban_entry", xs_add_nickban_entry, "xs_functions.c");
   newXS("odch::add_allow_entry", xs_add_allow_entry, "xs_functions.c");
   newXS("odch::remove_ban_entry", xs_remove_ban_entry, "xs_functions.c");
   newXS("odch::remove_nickban_entry", xs_remove_nickban_entry, "xs_functions.c");
   newXS("odch::remove_allow_entry", xs_remove_allow_entry, "xs_functions.c");
   newXS("odch::add_reg_user", xs_add_reg_user, "xs_functions.c");
   newXS("odch::remove_reg_user", xs_remove_reg_user, "xs_functions.c");
   newXS("odch::add_linked_hub", xs_add_linked_hub, "xs_functions.c");
   newXS("odch::remove_linked_hub", xs_remove_linked_hub, "xs_functions.c");
   newXS("odch::data_to_all", xs_data_to_all, "xs_functions.c");
   newXS("odch::count_users", xs_count_users, "xs_functions.c");
   newXS("odch::register_script_name", xs_register_script_name, "xs_functions.c");
   newXS("odch::check_if_registered", xs_check_if_registered, "xs_functions.c");
   newXS("odch::get_user_list", xs_get_user_list, "xs_functions.c");
}

#endif /* #ifdef HAVE_PERL */
