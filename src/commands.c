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

#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#if HAVE_UNISTD_H
# include <unistd.h>
#endif
#if HAVE_FCNTL_H
# include <fcntl.h>
#endif
#if HAVE_MALLOC_H
#include <malloc.h>
#endif
#include <errno.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/sem.h>

#include "main.h"
#include "utils.h"
#include "fileio.h"
#include "commands.h"
#include "network.h"
#include "userlist.h"
#ifdef HAVE_PERL
# include "perl_utils.h"
#endif

#ifndef HAVE_STRTOLL
# ifdef HAVE_STRTOQ
#  define strtoll(X, Y, Z) (long long)strtoq(X, Y, Z)
# endif
#endif

/* This command has the following format:
 * $SR fromnick filename\5filesize openslots/totalslots\5hubname (hubip:hubport)\5tonick| */
void sr(char *buf, struct user_t *user)
{
   char command[6];
   char fromnick[MAX_NICK_LEN+1];
   char filename[501]; /* Should do */
   long long unsigned filesize;
   int openslots;
   int totalslots;
   char hubname[301];
   char tonick[MAX_NICK_LEN+1];
   char *send_buf;
   struct user_t *to_user;

   if(sscanf(buf, "%5s %50s %500[^\5]\5%llu %d/%d\5%300[^\5]\5%50[^|]|", 
	  command, fromnick, filename, &filesize, &openslots, 
	     &totalslots, hubname, tonick) != 8)
     {
	/* Sometimes, the filesize seems to be skipped. */
	if(sscanf(buf, "%5s %50s %500[^\5]\5%300[^\5]\5%50[^|]|", 
		  command, fromnick, filename, hubname, tonick) != 5)
	  {	     
	     logprintf(4, "Received bad $SR command from %s at %s:\n", 
		       user->nick, user->hostname);
	     if(strlen(buf) < 3500)
	       logprintf(4, "%s\n", buf);
	     else
	       logprintf(4, "too large buf\n");
	     return;
	  }	
     }
   
   /* First a validation check */
   if(tonick[0] == '\0')
     {
	logprintf(4, "Received bad $SR command from %s at %s:\n", user->nick, user->hostname);
	if(strlen(buf) < 3500)
	  logprintf(4, "%s\n", buf);
	else
	  logprintf(4, "too large buf\n");
	return;
     }
   if((user->type & (REGULAR | REGISTERED | OP | OP_ADMIN | ADMIN)) != 0)
     {
	if((strncmp(fromnick, user->nick, strlen(fromnick)) != 0)
	   || (strlen(fromnick) != strlen(user->nick)))
	  {
	     logprintf(3, "User %s at %s claims to be someone else in $SR:\n", user->nick, user->hostname);
	     if(strlen(buf) < 3500)
	       logprintf(3, "%s\n", buf);
	     else
	       logprintf(3, "too large buf\n");
	     user->rem = REMOVE_USER | SEND_QUIT | REMOVE_FROM_LIST;
	     return;
	  }
     }
  
   if((send_buf = malloc(sizeof(char) * (strlen(buf) + 1))) == NULL)
     {
	logprintf(1, "Error - In sr()/malloc(): ");
	logerror(1, errno);
	quit = 1;
	return;
     }
   strcpy(send_buf, buf);

   /* Remove the nick at the end */
   *(strrchr(send_buf, '\005') + 1) = '\0';
   *(strrchr(send_buf, '\005')) = '|';

   /* And then forward it */
   if((to_user = get_human_user(tonick)) != NULL)
     send_to_user(send_buf, to_user);
   else   
     /* If user wasn't found, forward to other processes */
     send_to_non_humans(buf, FORKED, user);
   
   free(send_buf);
}

/* The search command, has the following format:
 * $Search ip:port byte1?byte2?size?byte3?searchpattern|
 * If the search was made by a client in passive mode, the ip:port is replaced
 * by Hub:nickname */
void search(char *buf, struct user_t *user)
{
   char command[15]; 
   char ip[MAX_HOST_LEN+1];
   char port[MAX_NICK_LEN+1];
   char byte1, byte2, byte3;
   char pattern[51]; /* It's the last argument, so it doesn't matter if it fits in the string */
   long long unsigned size;
   time_t now;

   /* Don't bother to check the command if it was sent from a forked process */
   if(user->type != FORKED)
     {	
	if(sscanf(buf, "%14s %122[^:]:%50s %c?%c?%llu?%c?%50[^|]|", 
		  command, ip, port, &byte1, &byte2, &size, &byte3, pattern) != 8)
	  {
	     logprintf(4, "Received bad $Search command from %s at %s:\n", user->nick, user->hostname);
	     if(strlen(buf) < 3500)
	       logprintf(4, "%s\n", buf);
	     else
	       logprintf(4, "too large buf\n");
	     return;
	  }
	
	/* Make sure that the user is the one he claims to be.  */
	if(((user->type & (REGULAR | REGISTERED | OP | OP_ADMIN)) != 0) &&
	   (searchcheck_exclude_all == 0))
	  {	     
	     if(!((strncmp(ip, ip_to_string(user->ip), strlen(ip)) == 0)
		  || (strncmp(port, user->nick, strlen(port)) == 0)
                  || (is_internal_address(user->ip) == 0)))
	       {
		  logprintf(1, "%s from %s claims to be someone else in $Search, removing user\n", user->nick, user->hostname);
		  user->rem = REMOVE_USER | SEND_QUIT | REMOVE_FROM_LIST;
		  return;
	       }	
	  }
	
	if(pattern[0] == '\0')
	  {
	     logprintf(4, "Received bad $Search command from %s at %s:\n", user->nick, user->hostname);
	     if(strlen(buf) < 3500)
	       logprintf(4, "%s\n", buf);
	     else
	       logprintf(4, "too large buf\n");
	     return;
	  }
     }
   
   if(user->type != FORKED)
     {
	
	now = time(NULL);
	if((searchspam_time > 0) && 
	   (difftime(now, user->last_search) <= (double)searchspam_time))
	  {
	     user->last_search = now;
	     uprintf(user, "<Hub-Security> Search ignored.  Please leave at least %d seconds between search attempts.|", searchspam_time);
	     return;
	  }
	user->last_search = now;
   
   /* If you want to control searches, here is the place to add the source.
    * The search pattern is in the variable pattern. A couple of examples: */
   
   /* If the search is three characters or less, throw it away: */
   /*
    * 
    if(strlen(pattern) <= 3)
        return; 
    */
   
   /* If user is searching for a bad word, tell him about it and kick him: */
   /*
    * 
   if(strstr(pattern, "bad word") != NULL)
     {
	uprintf(user, "<Hub-Security> No searches for bad words in this hub!|");
	user->rem = REMOVE_USER | SEND_QUIT | REMOVE_FROM_LIST;
	return;
     }
    */					 
     }
   
   /* Now, forward to all users */
   send_to_humans(buf, REGULAR | REGISTERED |  OP | OP_ADMIN, NULL);
   send_to_non_humans(buf, FORKED, user);
}

/* Search on linked hubs, same format as $Search */
void multi_search(char *buf, struct user_t *user)
{
   char command[15]; 
   char ip[MAX_HOST_LEN+1];
   unsigned int port;
   char byte1, byte2, byte3;
   char pattern[11];
   char *temp;   
   long long unsigned size;
   
   if(sscanf(buf, "%14s %122[^:]:%u %c?%c?%llu?%c?%10[^|]|", 
	     command, ip, &port, &byte1, &byte2, &size, &byte3, pattern) != 8)
     {	
	logprintf(4, "Received bad $MultiSearch command from %s at %s:\n", user->nick, user->hostname);
	if(strlen(buf) < 3500)
	  logprintf(4, "%s\n", buf);
	else
	  logprintf(4, "too large buf\n");
	return;
     }
   
   if(pattern[0] == '\0')
     {                                                                               
	logprintf(4, "Received bad $MultiSearch command from %s at %s:\n", user->nick, user->hostname);
	if(strlen(buf) < 3500)
	  logprintf(4, "%s\n", buf);
	else
	  logprintf(4, "too large buf\n");
	return;
     }
   
   
   /* If we are the parent, forward it to linked hubs. Otherwise, forward to 
    * parent process */  
   
   if(pid > 0)
     {
	/* Send $Search to linked hubs */
	temp = buf+5;
	temp[0] = '$';	
	send_to_non_humans(temp, LINKED, user);
	temp[0] = 'i';
     }
   else
     send_to_non_humans(buf, FORKED, user);
}

/* Connect to users on linked hubs, the format is:
 * $MultiConnectToMe requested_user requesting_ip:requesting_port hub_ip:hub_port, 
 * but the hubport doesn't show if it's 411 */
void multi_connect_to_me(char *buf, struct user_t *user)
{
   int i;
   char command[21];
   char requested[MAX_NICK_LEN+1];
   char ip[MAX_HOST_LEN+1];
   char hubip[MAX_HOST_LEN+10];
   unsigned int port;
   char *temp;
   char *pointer;
   char save1, save2;
   
   if(sscanf(buf, "%20s %50s %121[^:]:%u %130[^|]|", command, requested, 
	     ip, &port, hubip) != 5)
     {                                                                           
	logprintf(4, "Received bad $MultiConnectToMe command from %s at %s:\n", user->nick, user->hostname);
	if(strlen(buf) < 3500)
	  logprintf(4, "%s\n", buf);
	else
	  logprintf(4, "too large buf\n");
	return;
     }
   
   /* Validation check */
   if((user->type & (REGULAR | REGISTERED | OP | OP_ADMIN | ADMIN)) != 0)
     {
	if(port == 0)
	  {                                                                                  
	     logprintf(4, "Received bad $MultiConnectToMe command from %s at %s:\n", user->nick, user->hostname);
	     if(strlen(buf) < 3500)
	       logprintf(4, "%s\n", buf);
	     else
	       logprintf(4, "too large buf\n");
	     return;
	  }
     }
  
   /* If we are the parent, forward it to linked hubs. Otherwise, forward to 
    * parent process */  
   
   if(pid > 0)
     {
	temp = buf+5;
	pointer = temp;
	for(i = 1; i <= 3; i++)
	  {
	     pointer++;
	     if((pointer = strchr(pointer, ' ')) == NULL)
	       return;
	  }
	save1 = *pointer;
	save2 = *(pointer+1);
	*pointer = '|';
	*(pointer+1) = '\0';
	temp[0] = '$';
	send_to_non_humans(temp, LINKED, user);
	*pointer = save1;
	*(pointer+1) = save2;
	temp[0] = 'i';
     }
   else
     send_to_non_humans(buf, FORKED, user);
}  
	     
	     
/* Forwards to all logged in users */
void chat(char *buf, struct user_t *user)
{
   char nick[MAX_NICK_LEN+1];
   char chatstring[31];
   char *temp;
   char tempstr[MAX_HOST_LEN+1];
   char path[MAX_FDP_LEN+1];
   int ret;

  chatstring[0] = '\0';
   
   /* Only check nick if the command was sent directly from user */
   if((user->type & (REGULAR | REGISTERED | OP | OP_ADMIN | ADMIN)) != 0)
     {
	if(sscanf(buf, "<%50[^>]> %30[^|]|", nick, chatstring) < 1)
	  {                                                                             
	     logprintf(4, "Received bad chat command from %s at %s:\n", user->nick, user->hostname);
	     if(strlen(buf) < 3500)
	       logprintf(4, "%s\n", buf);
	     else
	       logprintf(4, "too large buf\n");
	     return;
	  }
	  
	if(chatstring[0] == '\0')
	  {                                                                             
	     logprintf(4, "Received bad chat command from %s at %s:\n", user->nick, user->hostname);
	     if(strlen(buf) < 3500)
	       logprintf(4, "%s\n", buf);
	     else
	       logprintf(4, "too large buf\n");
	     return;
	  }
	if((strncmp(buf + 1, user->nick, strlen(nick)) != 0) || (strlen(nick) != strlen(user->nick)))
	  {
	     logprintf(3, "User %s at %s claims to be someone else in chat:\n", user->nick, user->hostname);
	     if(strlen(buf) < 3500)
	       logprintf(3, "%s\n", buf);
	     else
	       logprintf(3, "too large buf\n");
	     user->rem = REMOVE_USER | SEND_QUIT | REMOVE_FROM_LIST;
	     return;
	  }
     }
   
   /* Parse commands from Regged users. Commands start with '!' */
   if(((user->type & (REGISTERED | OP | OP_ADMIN)) != 0) && (chatstring[0] == '!'))
     {
	if(strncasecmp(chatstring, "!setpass ", 9) == 0)
	  {
	     temp = strchr(chatstring, ' ') + 1;
	     
	     /* Using path here and tempstr a few lines down might be a bad idea. */	   
	     strncpy(path,temp,MAX_FDP_LEN); 
	     
	     if(remove_reg_user(user->nick, user) > 0)
	       {		
		  encrypt_pass(path);
		  
		  if (user->type == OP_ADMIN)
		    snprintf(tempstr, MAX_HOST_LEN, "%s %s %d", user->nick, path, 2);
		  else if (user->type == OP)
		    snprintf(tempstr, MAX_HOST_LEN, "%s %s %d", user->nick, path, 1);
		  else
		    snprintf(tempstr, MAX_HOST_LEN, "%s %s %d", user->nick, path, 0);
		  
		  snprintf(path, MAX_FDP_LEN, "%s/%s", config_dir, REG_FILE);
		  
		  if (add_line_to_file(tempstr, path) > 0)
		    {
		       uprintf(user, "<Hub-Security> Password changed|");
		       logprintf(4, "User %s changed it's password\n", user->nick);
		    }
	       }
	     else
	       logprintf(1, "Error - Failed to change password for user %s\n", user->nick);
	     
	     return;
	  }
     }
   
   /* Parse commands from Op Admins in chat, they start with '!' */
   if(((user->type & (OP_ADMIN | OP)) != 0) && (chatstring[0] == '!'))
     {
	temp = strchr(buf, ' ') + 1;
	if((user->type == OP_ADMIN) && (strncasecmp(temp, "!set ", 5) == 0))
	  set_var(temp, user);
	else if(((user->permissions & BAN_ALLOW) != 0) && (strncasecmp(temp, "!ban ", 5) == 0))
	  {	     	     
	     if((ret = ballow(temp+5, BAN, user)) == -1)
	       {
		  uprintf(user, "<Hub-Security> Couldn't add entry to ban list|");
		  logprintf(4, "Error - Failed adding entry to ban list\n");
	       }
	     else if(ret == 2)		  
	       uprintf(user, "<Hub-Security> Entry is already on the list|");
	     else
	       {
		  uprintf(user, "<Hub-Security> Added entry to ban list|");
		  sscanf(temp+5, "%120[^|]", tempstr);
		  logprintf(3, "OP Admin %s at %s added %s to ban list\n", user->nick, user->hostname, tempstr);
	       }	     	    	     
	  }
	
	else if(((user->permissions & BAN_ALLOW) != 0) && (strncasecmp(temp, "!nickban ", 9) == 0))
	  {	     	     
	     if((ret = ballow(temp+9, NICKBAN, user)) == -1)
	       {
		  uprintf(user, "<Hub-Security> Couldn't add entry to nickban list|");
		  logprintf(4, "Error - Failed adding entry to nickban list\n");
	       }
	     else if(ret == 2)		  
	       uprintf(user, "<Hub-Security> Entry is already on the list|");
	     else
	       {
		  uprintf(user, "<Hub-Security> Added entry to nickban list|");
		  sscanf(temp+9, "%120[^|]", tempstr);
		  logprintf(3, "OP Admin %s at %s added %s to nickban list\n", user->nick, user->hostname, tempstr);
	       }	     	    	     
	  }
	
	else if(((user->permissions & BAN_ALLOW) != 0) && (strncasecmp(temp, "!allow ", 7) == 0))
	  {	    	     
	     if((ret = ballow(temp+7, ALLOW, user)) == -1)
	       {
		  uprintf(user, "<Hub-Security> Couldn't add entry to allow list|");
		  logprintf(4, "Error - Failed adding entry to allow list\n");
	       }
	     else if(ret == 2)		  
	       uprintf(user, "<Hub-Security> Entry is already on the list|");
	     else
	       {
		  uprintf(user, "<Hub-Security> Added entry to allow list|");
		  sscanf(temp+7, "%120[^|]", tempstr);
		  logprintf(3, "OP Admin %s at %s added %s to allow list\n", user->nick, user->hostname, tempstr);
	       }	     	    	     
	  }	
	else if(((user->permissions & BAN_ALLOW) != 0) && (strncasecmp(temp, "!unban ", 7) == 0))
	  {	     	     
	     if((ret = unballow(temp+7, BAN)) == -1)
	       {
		  uprintf(user, "<Hub-Security> Couldn't remove entry from ban list|");
		  logprintf(4, "Error - Failed removing entry from ban list\n");
	       }
	     else if(ret == 0)		  
	       uprintf(user, "<Hub-Security> Entry wasn't found in list|");
	     else
	       {
		  uprintf(user, "<Hub-Security> Removed entry from ban list|");
		  sscanf(temp+7, "%120[^|]", tempstr);
		  logprintf(3, "OP Admin %s at %s removed %s from ban list\n", user->nick, user->hostname, tempstr);
	       }	     	    	     
	  }
	else if(((user->permissions & BAN_ALLOW) != 0) && (strncasecmp(temp, "!unnickban ", 11) == 0))
	  {	     	     
	     if((ret = unballow(temp+11, NICKBAN)) == -1)
	       {
		  uprintf(user, "<Hub-Security> Couldn't remove entry from nickban list|");
		  logprintf(4, "Error - Failed removing entry from nickban list\n");
	       }
	     else if(ret == 0)		  
	       uprintf(user, "<Hub-Security> Entry wasn't found in list|");
	     else
	       {
		  uprintf(user, "<Hub-Security> Removed entry from nickban list|");
		  sscanf(temp+11, "%120[^|]", tempstr);
		  logprintf(3, "OP Admin %s at %s removed %s from nickban list\n", user->nick, user->hostname, tempstr);
	       }	     	    	     
	  }
	else if(((user->permissions & BAN_ALLOW) != 0) && (strncasecmp(temp, "!unallow ", 9) == 0))
	  {	     	     
	     if((ret = unballow(temp+9, ALLOW)) == -1)
	       {
		  uprintf(user, "<Hub-Security> Couldn't remove entry from allow list|");
		  logprintf(4, "Error - Failed removing entry from allow list\n");
	       }
	     else if(ret == 0)		  
	       uprintf(user, "<Hub-Security> Entry wasn't found in list|");
	     else
	       {
		  uprintf(user, "<Hub-Security> Removed entry from allow list|");
		  sscanf(temp+9, "%120[^|]", tempstr);
		  logprintf(3, "OP Admin %s at %s removed %s from allow list\n", user->nick, user->hostname, tempstr);
	       }	     	    	     
	  }
	else if(((user->permissions & BAN_ALLOW) != 0) && (strncasecmp(temp, "!getbanlist", 11) == 0))
	  {
	     uprintf(user, "<Hub-Security> Ban list:\r\n");
	     send_user_list(BAN, user);
	     send_to_user("|", user);
	  }
	else if(((user->permissions & BAN_ALLOW) != 0) && (strncasecmp(temp, "!getnickbanlist", 15) == 0))
	  {
	     uprintf(user, "<Hub-Security> Nickban list:\r\n");
	     send_user_list(NICKBAN, user);
	     send_to_user("|", user);
	  }
	else if(((user->permissions & BAN_ALLOW) != 0) && (strncasecmp(temp, "!getallowlist", 13) == 0))
	  {
	     uprintf(user, "<Hub-Security> Allow list:\r\n");
	     send_user_list(ALLOW, user);
	     send_to_user("|", user);
	  }
	else if(((user->permissions & USER_ADMIN) != 0) && (strncasecmp(temp, "!addreguser ", 12) == 0))
	  {
	     if((ret = add_reg_user(temp, user)) == -1)
	       uprintf(user, "<Hub-Security> Couldn't add user to reg list|");
	     else if(ret == 2)
	       uprintf(user, "<Hub-Security> Bad format for addreguser. Correct format is:\r\naddreguser <nickname> <password> <opstatus>|");
	     else if(ret == 3)
	       uprintf(user, "<Hub-Security> That nickname is already registered.|");
	     else
	       {		  
		  uprintf(user, "<Hub-Security> Added user to reglist|");
		  logprintf(3, "OP Admin %s at %s added entry to reglist\n", user->nick, user->hostname);
	       }	     
	  }
	else if(((user->permissions & USER_ADMIN) != 0) && (strncasecmp(temp, "!removereguser ", 15) == 0))
	  {
	     if((ret = remove_reg_user(temp+15, user)) == 0)
	       uprintf(user, "<Hub-Security> User wasn't found in reg list|");
	     else if(ret == 2)
	       uprintf(user, "<Hub-Security> Couldn't remove user from reg list|");
	     else
	       {		  
		  uprintf(user, "<Hub-Security> Removed user from reglist|");
		  logprintf(3, "OP Admin %s at %s removed entry from reglist\n", user->nick, user->hostname);
	       }	     
	  }
	else if(((user->permissions & USER_ADMIN) != 0) && (strncasecmp(temp, "!getreglist ", 11) == 0))
	  {
	     uprintf(user, "<Hub-Security> Reg list:\r\n");
	     send_user_list(REG, user);
	     send_to_user("|", user);
	  }
	else if((user->type == OP_ADMIN) && (strncasecmp(temp, "!addlinkedhub ", 14) == 0))
	  {	     
	     if((ret = add_linked_hub(temp)) == -1)
	       uprintf(user, "<Hub-Security> Couldn't add hub to link list|");
	     else if(ret == 2)
	       uprintf(user, "<Hub-Security> Bad format for addlinkedhub. Correct format is:\r\naddlinkedhub <ip> <port>|");
	     else if(ret == 3)
	       uprintf(user, "<Hub-Security> That hub is already in the link list|");
	     else
	       {		  
		  uprintf(user, "<Hub-Security> Added hub to link list|");
		  logprintf(3, "OP Admin %s at %s added entry to linklist\n", user->nick, user->hostname);
	       }	     
	  }
	else if((user->type == OP_ADMIN) && (strncasecmp(temp, "!removelinkedhub ", 17) == 0))
	  {
	     if((ret = remove_linked_hub(temp+17)) == 0)
	       uprintf(user, "<Hub-Security> Hub wasn't found in link list|");
	     else if(ret == -1)
	       uprintf(user, "<Hub-Security> Couldn't remove hub from link list|");
	     else if(ret == 2)
	       uprintf(user, "<Hub-Security> Bad format for $RemoveLinkedHub. Correct format is:\r\n$RemoveLinkedHub <ip> <port>|");
	     else
	       {		  
		  uprintf(user, "<Hub-Security> Removed hub from linklist|");
		  logprintf(3, "OP Admin %s at %s removed entry from linklist\n", user->nick, user->hostname);
	       }	     
	  }	
	else if((user->type == OP_ADMIN) && (strncasecmp(temp, "!getlinklist ", 12) == 0))
	  {
	     uprintf(user, "<Hub-Security> Link list:\r\n");
	     send_user_list(LINK, user);
	     send_to_user("|", user);
	  }
	else if((user->type == OP_ADMIN) && (strncasecmp(temp, "!getconfig ", 10) == 0))
	  {
	     uprintf(user, "<Hub-Security> Config:\r\n");
	     send_user_list(CONFIG, user);
	     send_to_user("|", user);
	  }
	else if((user->type == OP_ADMIN) && (strncasecmp(temp, "!getmotd ", 8) == 0))
	  {
	     uprintf(user, "<Hub-Security> Motd:\r\n");
	     send_motd(user);
	     send_to_user("|", user);
	  }
	else if((user->type == OP_ADMIN) && (strncasecmp(temp, "!quitprogram", 12) == 0))
	  {
	     uprintf(user, "<Hub-Security> Shutting down hub...|");
	     quit = 1;
	  }
	else if((user->type == OP_ADMIN) && (strncmp(temp, "!exit", 5) == 0))
	  {
	     logprintf(1, "Got exit from OP Admin %s at %s, haning up\n", user->nick, user->hostname);
	     user->rem = REMOVE_USER | SEND_QUIT | REMOVE_FROM_LIST;
	  }
	else if((user->type == OP_ADMIN) && (strncasecmp(temp, "!redirectall ", 13) == 0))
	  {
	     uprintf(user, "<Hub-Security> Redirecting all users...|");
	     logprintf(1, "OP Admin at %s redirected all users\n", user->hostname);
	     redirect_all(temp+13, user);
	  }
	else if(((user->permissions & USER_INFO) != 0) && (strncasecmp(temp, "!gethost ", 9) == 0))
	  {	     
	     get_host(temp, user, HOST);
	  }
	else if(((user->permissions & USER_INFO) != 0) && (strncasecmp(temp, "!getip ", 7) == 0))
	  {	     
	     get_host(temp, user, IP);
	  }
	else if((user->permissions > 0) && (strncasecmp(temp, "!commands", 9) == 0))
	  {
	     send_commands(user);
	  }
	else if(((user->permissions & MASSMESSAGE) != 0) && (strncasecmp(temp, "!massmessage ", 13) == 0))
	  {
	     send_mass_message(temp + 13, user);
	  }	
	else if((user->type == OP_ADMIN) && (strncasecmp(temp, "!reloadscripts", 14) == 0))
	  {
	     uprintf(user, "<Hub-Security> Reloading scripts...|");
	     if(pid > 0)
	       script_reload = 1;
	     else
	       send_to_non_humans("$ReloadScripts|", FORKED, NULL);
	  }
	else if((user->type == OP_ADMIN) && (strncasecmp(temp, "!addperm", 8) == 0))
	  {
	     if((ret = add_perm(temp, user)) == -1)
	       uprintf(user, "<Hub-Security> Couldn't add permission to user|");
	     else if(ret == 2)
	       uprintf(user, "<Hub-Security> Bad format for addperm. Correct format is:\r\naddperm <nick> <permission>\r\nand permission is one of: BAN_ALLOW, USER_INFO, MASSMESSAGE, USER_ADMIN|");
	     else if(ret == 3)
	       uprintf(user, "<Hub-Security> User already has that permission.|");
	     else if(ret == 4)
	       uprintf(user, "<Hub-Security> User is not an operator.|");
	     else
	       {		  
		  uprintf(user, "<Hub-Security> Added permission to user|");
		  logprintf(3, "OP Admin %s at %s added permission to user\n", user->nick, user->hostname);
	       }
	  }
	else if((user->type == OP_ADMIN) && (strncasecmp(temp, "!removeperm", 11) == 0))
	  {
	     if((ret = remove_perm(temp, user)) == -1)
	       uprintf(user, "<Hub-Security> Couldn't remove permission from user|");
	     else if(ret == 2)
	       uprintf(user, "<Hub-Security> Bad format for removeperm. Correct format is:\r\nremoveperm <nick> <permission>\r\nand permission is one of: BAN_ALLOW, USER_INFO, MASSMESSAGE, USER_ADMIN|");
	     else if(ret == 3)
	       uprintf(user, "<Hub-Security> User does not have that permission.|");
	     else if(ret == 4)
	       uprintf(user, "<Hub-Security> User is not an operator.|");
	     else
	       {		  
		  uprintf(user, "<Hub-Security> Removed permission from user|");
		  logprintf(3, "OP Admin %s at %s removed permission from user\n", user->nick, user->hostname);
	       }
	  }
	else if((user->type == OP_ADMIN) && (strncasecmp(temp, "!showperms", 10) == 0))
	  {
	     if((ret = show_perms(user, temp)) == 2)
	       uprintf(user, "<Hub-Security> Bad format for showperms. Correct format is:\r\nshowperms <nick>|");
	     else if(ret == 3)
	       uprintf(user, "<Hub-Security> User is not an operator.|");
	  }
	else if (user->permissions > 0)
	  uprintf(user, "<Hub-Security> Unknown command: %s|", chatstring);
     }   
   
   else
     {		
	/* And forward the message to all.  */
	send_to_non_humans(buf, FORKED, user);
	send_to_humans(buf, REGULAR | REGISTERED | OP | OP_ADMIN, NULL);
     }
}

/* Forwards request from one user to another, 
 $RevConnectToMe requesting_user requested_user| i.e, the other way around if you compare it
 with $ConnectToMe */
void rev_connect_to_me(char *buf, struct user_t *user)
{
   char command[21];
   char requesting[MAX_NICK_LEN+1];
   char requested[MAX_NICK_LEN+1];
   struct user_t *to_user;
   
   if(sscanf(buf, "%20s %50s %50[^|]|", command, requesting, requested) != 3)
     {                                                                           
	logprintf(4, "Received bad $RevConnectToMe command from %s at %s:\n", user->nick, user->hostname);
	if(strlen(buf) < 3500)
	  logprintf(4, "%s\n", buf);
	else
	  logprintf(4, "too large buf\n");
	return;
     }
  
   if((user->type & (REGULAR | REGISTERED | OP | OP_ADMIN | ADMIN)) != 0)
     {
	if(requested[0] == '\0')
	  {	                                                                               
	     logprintf(4, "Received bad $RevConnectToMe command from %s at %s:\n", user->nick, user->hostname);
	     if(strlen(buf) < 3500)
	       logprintf(4, "%s\n", buf);
	     else
	       logprintf(4, "too large buf\n");
	     return;
	  }
	if((strncmp(requesting, user->nick, strlen(requesting)) != 0) 
	    || (strlen(requesting) != strlen(user->nick)))
	    {	                                                                                   
	       logprintf(3, "User %s at %s claims to be someone else in $RevConnectToMe:\n", user->nick, user->hostname);
	       if(strlen(buf) < 3500)
		 logprintf(3, "%s\n", buf);
	       else
		 logprintf(3, "too large buf\n");
	       user->rem = REMOVE_USER | SEND_QUIT | REMOVE_FROM_LIST;
	       return;
	    }
     }
   
   /* And forward to requested user.  */
   if((to_user = get_human_user(requested)) != NULL)
     send_to_user(buf, to_user);
   else
     send_to_non_humans(buf, FORKED, user);
}
       

/* Forwards request from one user to another. The command has the following fomat:
 $ConnectToMe requested_user requesting_ip:requesting_port */
void connect_to_me(char *buf, struct user_t *user)
{
   char command[21];
   char requested[MAX_NICK_LEN+1];
   char ip[MAX_HOST_LEN+1];
   unsigned int port;
   struct user_t *to_user;
   
   if(sscanf(buf, "%20s %50s %121[^:]:%u|", command, requested, ip, &port) != 4)
     {                                                                        
	logprintf(4, "Received bad $ConnectToMe command from %s at %s:\n", user->nick, user->hostname);
	if(strlen(buf) < 3500)
	  logprintf(4, "%s\n", buf);
	else
	  logprintf(4, "too large buf\n");
	return;
     }
   
   /* Validation check */
     if((user->type & (REGULAR | REGISTERED | OP | OP_ADMIN | ADMIN | LINKED)) != 0)
     {
	if(port == 0)
	  {	                                                                            
	     logprintf(4, "Received bad $ConnectToMe command from %s at %s:\n", user->nick, user->hostname);
	     if(strlen(buf) < 3500)
	       logprintf(4, "%s\n", buf);
	     else
	       logprintf(4, "too large buf\n");
	     return;
	  }
     }
	
   /* And forward to requested user */
   if((to_user = get_human_user(requested)) != NULL)
     send_to_user(buf, to_user);
   else
     send_to_non_humans(buf, FORKED, user);
}
   
/* Send message from user to specified user, has the following format:
 * $To: tonick From: fromnick $message string| */
void to_from(char *buf, struct user_t *user)
{
   char command[6];
   struct user_t *to_user;
   char fromnick[MAX_NICK_LEN+1];
   char tonick[MAX_NICK_LEN+1];
   char chatnick[MAX_NICK_LEN+1];
   char message[11];
   
   if(sscanf(buf, "%5s %50s From: %50s $<%50[^>]> %10[^|]|", command, tonick, fromnick, chatnick, message) != 5)
     {                                                                
	logprintf(4, "Received bad $To command from %s at %s:\n", user->nick, user->hostname);
	if(strlen(buf) < 3500)
	  logprintf(4, "%s\n", buf);
	else
	  logprintf(4, "too large buf\n");
	return;
     }
   
   if((user->type & (REGULAR | REGISTERED | OP | OP_ADMIN | ADMIN)) != 0)
     {
	if(message[0] == '\0')
	  {	                                                                    
	     logprintf(4, "Received bad $To command from %s at %s:\n", user->nick, user->hostname);
	     if(strlen(buf) < 3500)
	       logprintf(4, "%s\n", buf);
	     else
	       logprintf(4, "too large buf\n");
	     return;
	  }
	if((user->type & (REGULAR | REGISTERED)) != 0)
	  {	     
	     if(((strncmp(fromnick, user->nick, strlen(fromnick)) != 0) 
		 || (strlen(fromnick) != strlen(user->nick))) 
		|| ((strncmp(chatnick, user->nick, strlen(fromnick)) != 0) 
		    || (strlen(chatnick) != strlen(user->nick))))
	       {	                                                                   	                        
		  logprintf(3, "User %s at %s claims to be someone else in $To:\n", user->nick, user->hostname);
		  if(strlen(buf) < 3500)
		    logprintf(3, "%s\n", buf);
		  else
		    logprintf(3, "too large buf\n");
		  user->rem = REMOVE_USER | SEND_QUIT | REMOVE_FROM_LIST;
		  return;
	       }
	  }	
     }
   
   /* And forward the message to specified user.  */
   if((to_user = get_human_user(tonick)) != NULL)
     send_to_user(buf, to_user);
   else
     send_to_non_humans(buf, FORKED, user);
}
  

/* If a user wants info about one other, it looks like this:
 * $GetINFO requested_user requesting_user| */
void get_info(char *buf, struct user_t *user)
{
   char command[11];
   char requesting[MAX_NICK_LEN+1];
   char requested[MAX_NICK_LEN+1];
   struct user_t *from_user;
   
   if(sscanf(buf, "%10s %50s %50[^|]|", command, requested, requesting) != 3)
     {                                                                    
	logprintf(4, "Received bad $GetINFO command from %s at %s:\n", user->nick, user->hostname);
	if(strlen(buf) < 3500)
	  logprintf(4, "%s\n", buf);
	else
	  logprintf(4, "too large buf\n");
	return;
     }
   
   if((user->type & (REGULAR | REGISTERED | OP | OP_ADMIN | ADMIN)) != 0)
     {
	if(requesting[0] == '\0')
	  {                                                                         
	     logprintf(4, "Received bad $GetINFO command from %s at %s:\n", user->nick, user->hostname);
	     if(strlen(buf) < 3500)
	       logprintf(4, "%s\n", buf);
	     else
	       logprintf(4, "too large buf\n");
	     return;
	  }
	if((strncmp(requesting, user->nick, strlen(requesting)) != 0) 
	    || (strlen(requesting) != strlen(user->nick)))
	    {	                                                                       	                      
	       logprintf(3, "User %s at %s claims to be someone else in $GetINFO:\n", user->nick, user->hostname);
	       if(strlen(buf) < 3500)
		 logprintf(3, "%s\n", buf);
	       else
		 logprintf(3, "too large buf\n");
	       user->rem = REMOVE_USER | SEND_QUIT | REMOVE_FROM_LIST;
	       return;
	    }
     }
  
   /* Nobody should be able to fool us by pretenting to be the a script.  */
   if((strncmp(requesting, "$Script", 7) == 0) && ((user->type & (FORKED | SCRIPT)) == 0))
     return;
   
   /* Check if the requested user is connected to this process.  */
   if((from_user = get_human_user(requested)) != NULL)
     {	
	/* Check if it's the $Script user, if so, send user info to scripts if
	 * we are the parent.  */
	if(strncmp(requesting, "$Script", 7) == 0)
	  {	     	 
#ifdef HAVE_PERL
	     command_to_scripts("$Script user_info %s %lu %s %d %s|", from_user->nick,
				from_user->ip, from_user->hostname, from_user->type, from_user->version);
	     if(pid > 0)
	       send_user_info(from_user, requesting, TO_ALL);
	     else
	       send_user_info(from_user, requesting, PRIV);
#endif
	  }
	/* If the requesting user is connected to this process.  */
	else if(get_human_user(requesting) != NULL)
	  send_user_info(from_user, requesting, TO_ALL);
	/* If the requesting user isn't connected to this process, forward it.  */
	else
	  send_user_info(from_user, requesting, PRIV);
     }   
   else
     send_to_non_humans(buf, FORKED, user);
}

/* Handles the MyINFO command. Returns 0 if user should be removed. 
 * Has the following format:
 * $MyINFO $ALL nickname filedescription$ $connection type$email$sharesize$| 
 * Since some of these variables can be empty, I havent used sscanf which 
 * makes this function a little bit hard to follow.  */
int my_info(char *org_buf, struct user_t *user)
{
   int i, k, ret;
   int desc_too_long = 0;
   int email_too_long = 0;
   char *buf;
   char *send_buf;
   char hello_buf[MAX_NICK_LEN+9];
   char temp_size[50];
   char to_nick[MAX_NICK_LEN+1];
   char temp_nick[MAX_NICK_LEN+1];
   struct user_t *to_user;
   char quit_string[MAX_NICK_LEN+10];
   struct user_t *save_user = NULL;
   int new_user = 0;   /* 0 for users that are already logged in, 1 for users
			 * who send $MyINFO for the first time.  */
   
   buf = org_buf + 9;
   
   /* Check if message is for all or for a specific user */
   if(strncmp(buf, "ALL ", 4) == 0)
     {
	buf += 4;
	
	/* If user is a process, just forward the command.  */
	if(user->type == FORKED)
	  {	     
	     send_to_non_humans(org_buf, FORKED | SCRIPT, user);
	     send_to_humans(org_buf, REGULAR | REGISTERED | OP | OP_ADMIN, 
			    user);
	     return 1;
	  }
	if(*user->nick == (char) NULL)
	  return 0;
	
	if((check_if_registered(user->nick) != 0)
	   && ((user->type & (UNKEYED | NON_LOGGED | REGULAR)) != 0))
	  {
	     logprintf(1, "User at %s tried to log in with registered nick without providing password, kicking user\n", user->hostname);
	     return 0;
	  } else if((strlen(default_pass) > 0)
                    && ((user -> type & (UNKEYED | NON_LOGGED)) != 0))
	    {
               logprintf(1, "User at %s tried to log in with %s without providing default password, kicking user\n", user->hostname, user->nick);
	       return 0;
            }
     }
   else
     {	
	/* It's not $MyINFO $ALL, but $MyINFO to_nick, so send $MyINFO $ALL to
	 * the specified user in to_nick.  */
	i = cut_string(buf, ' ');
	if((i == -1) || (i>50) || (user->type != FORKED))
	  return -1;
	
	strncpy(to_nick, buf, i);
	to_nick[i] = '\0';
	buf += (i + 1);
	
	/* Check if the destination user is in this process */
	if(((to_user = get_human_user(to_nick)) != NULL) 
	   || (strncmp(to_nick, "$Script", 7) == 0))
	  {
	     if((send_buf = malloc(sizeof(char) * (strlen(buf) + 14))) == NULL)
	       {
		  logprintf(1, "Error - In my_info()/malloc(): ");
		  logerror(1, errno);
		  quit = 1;
		  return -1;
	       }
	     strcpy(send_buf, "$MyINFO $ALL ");
	     strcat(send_buf, buf);
	     /* If it's the $Script user, send to all scripts.  */
	     if((strncmp(to_nick, "$Script", 7) == 0) && (pid > 0))
	       send_to_non_humans(send_buf, SCRIPT, user);
	     /* Otherwise, send to the specified user.  */
	     else
	       send_to_user(send_buf, to_user);
	     free(send_buf);
	  }
	else
	  /* The user wasn't connected to this process, forward to other 
	   * processes.  */
	  send_to_non_humans(org_buf, FORKED, user);
	
	return 1;
     }  
   
   /* If the user was NON_LOGGED before, or if the flag was 0, it's the first 
    * time the user sends $MyINFO $ALL.  */
   if((user->type == NON_LOGGED) 
      || ((user->flag == 0) 
	  && ((user->type & (REGISTERED | OP | OP_ADMIN)) != 0)))
     new_user = 1;
   
   /* First set users variables */
   if(((i = cut_string(buf, ' ')) == -1)
      || cut_string(buf, ' ') > cut_string(buf, '$'))
     return 0;
     
   sscanf(buf, "%50s", temp_nick);
   
   /* If we are a script process, temporary save the parent process user.  */
   if(pid == -1)
     {
	save_user = user;
	if((user = get_human_user(temp_nick)) == NULL)
	  return -1;
     }   
   
   /* Make sure that user isn't on the user list already. This could only
    * happen if a user first sends ValidateNick, then the process forks, and
    * after that the user sends MyINFO $ALL.  */
   if(user->type == NON_LOGGED)
     {		
	if((check_if_on_user_list(temp_nick)) != NULL)
	  return 0;
     }
   
   /* If the command was sent from a human, make sure that the provided nick 
    * matches the one provided with $ValidateNick.  */
    if((user->type & (NON_LOGGED | REGULAR | REGISTERED | OP | OP_ADMIN)) != 0)
     {
	if((strncmp(temp_nick, user->nick, strlen(user->nick)) != 0)
	   || (strlen(temp_nick) != strlen(user->nick)))
	  {
	     logprintf(3, "User from %s provided a nick in $MyINFO that does not match the one from $ValidateNick, removing user.\n", user->hostname);
	     return 0;
	  }
     }
   
   buf = buf + i + 1;
   
   if(user->desc != NULL)
     {
	free(user->desc);
	user->desc = 0;
     }
     
   if(*buf != '$')
     {
	k = cut_string(buf, '$');
	if((max_desc_len == 0) || (k <= max_desc_len))
	  {
	     if((user->desc = (char *) malloc(sizeof(char) * (k + 1))) == NULL)
	       {
		  logprintf(1, "Error - In my_info()/malloc(): ");
		  logerror(1, errno);
		  quit = 1;
		  return -1;
	        }
	     strncpy(user->desc, buf, k);
	     user->desc[k] = '\0';
	  }
	else
	     desc_too_long = 1;
	buf = buf + k + 1;
     }
   buf++;
   
   /* Not sure if the next argument is ever set to anything else than a 
    * blankspace. Skipping it for now.  */
    if((i = cut_string(buf, '$')) == -1)
     return 0;
   
   buf = buf + i + 1;
   
   /* Get connection of user */
    if((i = cut_string(buf, '$')) == -1)
     return 0;
   
   /* Switching the first letter in connection name */
   switch(*buf)
     {
      case '2':
	user->con_type = 1;
	break;
      case '3':
	user->con_type = 2;
	break;
      case '5':
	user->con_type = 3;
	break;
      case 'S':
	user->con_type = 4;
	break;
      case 'I':
	user->con_type = 5;
	break;
      case 'D':
	user->con_type = 6;
	break;
      case 'C':
	user->con_type = 7;
	break;
      case 'L':
	/* We have both T1 and T3 here */
	if(buf[i-3] == '3')
	  user->con_type = 9;
	else
	  user->con_type = 8;
	break;
// @Ciuly: Added a list of connection types (issue derived from 1027168	
      case 'W':
        user->con_type = 10; //Wireless
        break;
      case 'M':
        user->con_type = 11; //Modem
	break;
      case 'N':
        user->con_type = 12; //Netlimiter
	break;
// end @Ciuly
      default:
// Start fix for 1027168 by Ciuly
//	return 0;
        user->con_type = 255;//unknown
	break;
// End fix for 1027168
     }
   
   /* Set flag */
   user->flag = (int)buf[i - 1];
   
   buf = buf + i + 1;
   
   if((i = cut_string(buf, '$')) == -1)
     return 0;
	
   if(user->email != NULL)
     {
	free(user->email);
	user->email = 0;
     }

   /* Set email.  */
   if(buf[0] != '$')
     {
	k = cut_string(buf, '$');
	if((max_email_len == 0) || (k <= max_email_len))
	  {
	     if((user->email = (char *) malloc(sizeof(char) * (k + 1))) == NULL)
	       {
		  logprintf(1, "Error - In my_info()/malloc(): ");
		  logerror(1, errno);
		  quit = 1;
		  return -1;
	       }
	     strncpy(user->email, buf, k);
	     user->email[k] = '\0';
	  }
	else
	     email_too_long = 1;
     }
   buf = buf + i + 1;
   
   /* Parse share size.  */
   if((i = cut_string(buf, '$')) == -1)
     return 0;
   
   /* If a user has uploaded share size before, we'll have to subtract the 
    * old share from the total share first.  */
   if(((user->type & (REGULAR | REGISTERED | OP | OP_ADMIN)) != 0) 
      && (user->share != 0) && (save_user == NULL))
     add_total_share(-user->share);
   
   /* If the size of users share is a number with more than 20 digits, 
    * something must be wrong */
   if(i>20)
     return 0;

   memset(temp_size, 0, sizeof(temp_size));
   if(*buf != '$')
     {
	strncpy(temp_size, buf, i);
	user->share = strtoll(temp_size,(char **)NULL, 10);
     }
   else
     user->share = 0;

   /* Switch back to the parent process user.  */
   if(save_user != NULL)
     user = save_user;
   
   /* Check if user is sharing enough.  */
   /* Op:s don't have to meet the requirement for now. May be optional in 
    * the future.  */
   if(((user->type & (NON_LOGGED | REGULAR | REGISTERED)) != 0)
      && (user->share < min_share))
     {
	user->flag = 0;
	if(min_share < (1 << 30))
	  {
	     if((redir_on_min_share == 1) && (redirect_host != NULL) && ((int)redirect_host[0] > 0x20))
	       {		  
		  uprintf(user, "$Hello %s|$To: %s From: Hub $Minimum share for this hub is %lld MegaBytes. You are being redirected.|", user->nick, user->nick, (long long)min_share / (1024*1024));
		  uprintf(user, "$ForceMove %s|", redirect_host);
		  logprintf(1, "User %s at %s doesn't share enough, redirecting user\n", user->nick, user->hostname);		  
		  if((user->type & (REGULAR | REGISTERED)) != 0)
		    {
		       remove_user_from_list(user->nick);
		       remove_human_from_hash(user->nick);
		       user->type = NON_LOGGED;
		       sprintf(quit_string, "$Quit %s|", user->nick);
		       send_to_humans(quit_string, REGULAR | REGISTERED | OP 
				      | OP_ADMIN, user);
		       send_to_non_humans(quit_string, FORKED, NULL);
#ifdef HAVE_PERL		       
		       command_to_scripts("$Script user_disconnected %c%c", '\005', '\005');
		       non_format_to_scripts(user->nick);
		       command_to_scripts("|");		       
#endif		       
		    }		  
		  return 1;
	       }
	     else
	       uprintf(user, "$Hello %s|$To: %s From: Hub $Minimum share for this hub is %lld MegaBytes. Please share some more.|", user->nick, user->nick, (long long)min_share / (1024*1024));
	  }
	
	else
	  {
	     if((redir_on_min_share == 1) && (redirect_host != NULL) && ((int)redirect_host[0] > 0x20))
	       {		  
		  uprintf(user, "$Hello %s|$To: %s From: Hub $Minimum share for this hub is %2.2f GigaBytes. You are being redirected.|", user->nick, user->nick, (double)min_share / (1024*1024*1024));
		  uprintf(user, "$ForceMove %s|", redirect_host);
		  logprintf(1, "User %s at %s doesn't share enough, redirecting user\n", user->nick, user->hostname);
		  if((user->type & (REGULAR | REGISTERED | OP | OP_ADMIN)) 
		     != 0)
		    {
		       remove_user_from_list(user->nick);
		       remove_human_from_hash(user->nick);
		       user->type = NON_LOGGED;
		       sprintf(quit_string, "$Quit %s|", user->nick);
		       send_to_humans(quit_string, REGULAR | REGISTERED | OP 
				      | OP_ADMIN, user);
		       send_to_non_humans(quit_string, FORKED, NULL);
#ifdef HAVE_PERL		       
		       command_to_scripts("$Script user_disconnected %c%c", '\005', '\005');
		       non_format_to_scripts(user->nick);
		       command_to_scripts("|");		       
#endif		       
		    }		  
		  return 1;
	       }
	     else
	       uprintf(user, "$Hello %s|$To: %s From: Hub $Minimum share for this hub is %2.2f GigaBytes. Please share some more.|", user->nick, user->nick, (double)min_share / (1024*1024*1024));
	  }
	
	logprintf(1, "User %s at %s doesn't share enough, kicking user\n", user->nick, user->hostname);
	return 0;
     }

   /* Disconnect user if email or descriptions are too long */
   if(desc_too_long != 0)
     {
	uprintf(user, "$Hello %s|$To: %s From: Hub $Your description is too long for this hub.  The maximum allowed description is %d characters, please modify yours.|", user->nick, user->nick, max_desc_len);
	logprintf(1, "User %s at %s has too long a description, kicking user\n", user->nick, user->hostname);
	return 0;
     }
   if(email_too_long != 0)
     {
	uprintf(user, "$Hello %s|$To: %s From: Hub $Your email address is too long for this hub.  The maximum allowed email address is %d characters, please modify yours.|", user->nick, user->nick, max_email_len);
	logprintf(1, "User %s at %s has too long an email address, kicking user\n", user->nick, user->hostname);
	return 0;
     }
   
   /* If the user has been non logged in so far, send Hello string first.  */
   if((user->type & (NON_LOGGED | FORKED)) != 0)
     {
	sprintf(hello_buf, "$Hello %s|", user->nick);
	send_to_non_humans(hello_buf, FORKED, user);
	send_to_humans(hello_buf, REGULAR | REGISTERED | OP | OP_ADMIN, user);
     }

    /* By now, the user should have passed all tests and therefore be counted
     * as logged in.  */
   if(user->type == NON_LOGGED)
     {	
	user->type = REGULAR;
	logprintf(1, "%s logged in from %s\n", user->nick, user->hostname);
     }       
   
   /* Add share to total_share.  */
   if((user->type & (FORKED | SCRIPT)) == 0)
     add_total_share(user->share);
   
   /* To scripts, also send the info not covered by MyINFO.  */     
#ifdef HAVE_PERL
   if((new_user != 0) 
      && ((user->type & (REGULAR | REGISTERED | OP | OP_ADMIN)) != 0))
     command_to_scripts("$Script user_info %s %lu %s %d %s|", user->nick,
			user->ip, user->hostname, user->type, user->version);
#endif
   
   /* And then send the MyINFO string. */
   send_to_non_humans(org_buf, FORKED | SCRIPT, user);
   
   send_to_humans(org_buf, REGULAR | REGISTERED | OP | OP_ADMIN, NULL);     
   
   /* Send to scripts */
#ifdef HAVE_PERL
   if(new_user)
     { 
	if(user->type == REGULAR)
	  command_to_scripts("$Script new_user_connected %c%c%s|", 
			     '\005', '\005', user->nick);
	else if(user->type == OP_ADMIN)
	  command_to_scripts("$Script op_admin_connected %c%c%s|", 
			     '\005', '\005', user->nick);
	else if(user->type == OP)
	  command_to_scripts("$Script op_connected %c%c%s|", 
			     '\005', '\005', user->nick);
	else if(user->type == REGISTERED)
	  command_to_scripts("$Script reg_user_connected %c%c%s|", 
			     '\005', '\005', user->nick);
     }   
#endif
   
   if((new_user != 0) && (user->type == REGULAR))
     add_human_to_hash(user);
   
   /* Add user to user list */
   if((user->type & (NON_LOGGED | REGULAR | REGISTERED | OP | OP_ADMIN | ADMIN)) != 0)
     {	
	if((ret = add_user_to_list(user)) == 0)
	  {
	     increase_user_list();
	     if(add_user_to_list(user) == -1)
	       return 0;
	  }	
	else if(ret == -1)
	  return 0;
     }   
   return 1;
}

/* Handles the ValidateNick command */
/* This one has to check if the name is taken or if it is reserved */
/* Returns 0 if user should be kicked */
int validate_nick(char *buf, struct user_t *user)
{
   char temp_nick[MAX_NICK_LEN+1];
   char command[21];
   char kickstring[MAX_NICK_LEN+10];
   char hello_buf[MAX_NICK_LEN+10];
   struct sock_t *sock;
   struct user_t *non_human;
   char *user_list_nick;
   char *op_list;
   
   if(sscanf(buf, "%20s %50s|", command, temp_nick) != 2)
     {                                                                         
	logprintf(4, "Received bad $ValidateNick command from %s at %s:\n", user->nick, user->hostname);
	if(strlen(buf) < 3500)
	  logprintf(4, "%s\n", buf);
	else
	  logprintf(4, "too large buf\n");
	return 0;
     }
   
   /* Remove trailing '|'  */
   if(temp_nick[strlen(temp_nick)-1] == '|')
     temp_nick[strlen(temp_nick)-1] = '\0';
   
   /* Make sure that it doesn't contain ascii char 5.  */
   if(strchr(temp_nick, '\005') != NULL)
     {
	uprintf(user, "$ValidateDenide %s|", temp_nick);
	return 0;
     }
   
   /* Check that it isn't "Hub-Security" */
   if((strncasecmp(temp_nick, "hub-security", 12) == 0) && (user->type != SCRIPT))
     {	
	/* I know that it should be spelled "ValidateDenied", but since the
	 * protocol is designed this way, we can't expect the clients to 
	 * understand the command if it's spelled in any other way.  */
	uprintf(user, "$ValidateDenide %s|", temp_nick);
	return 0;
     }
   
   /* Or "Administrator"  */
   if((strncasecmp(temp_nick, "Administrator", 13) == 0) 
      && (user->type != SCRIPT))
     {
	uprintf(user, "$ValidateDenide %s|", temp_nick);
	return 0;
     }   
   
   /* Check if it's already taken.  */
   if((((user_list_nick = check_if_on_user_list(temp_nick)) != NULL)
       || (get_human_user(temp_nick) != NULL)) 
      && (check_if_registered(temp_nick) == 0))
     {
	if(user->type != SCRIPT)
	  {	     
	     uprintf(user, "$ValidateDenide %s|", temp_nick);
	     memset(temp_nick, 0, sizeof(temp_nick));
	     return -1;
	  }
	else
	  {
	     /* If user is a script, kick the user who has taken the nick.  */
	     logprintf(4, "validate_nick() - Warning: Script already in user_list.\n");	
	     sprintf(kickstring, "$Kick %s|", temp_nick);
	     kick(kickstring, NULL, 0);
	  }
     }

   if(user->type != SCRIPT)
     {		
	strcpy(user->nick, temp_nick);
	if(check_if_registered(temp_nick) != 0)
	  {
	     hub_mess(user, GET_PASS_MESS);	     

	     if(check_if_banned(user, NICKBAN) != 0)
	       {
		  uprintf(user, "$To: %s From: Hub $Sorry, you have been banned from this hub.|", temp_nick);
		  return 0;
	       }

	     return 1;
	  }

	else if(strlen(default_pass) > 0)
          {
	     hub_mess(user, GET_PASS_MESS2);

	     if(check_if_banned(user, NICKBAN) != 0)
	       {
		  uprintf(user, "$To: %s From: Hub $Sorry, you have been banned from this hub.|", temp_nick);
	          return 0;
	       }

	     return 1;
	  }

	else if(registered_only != 0)
	  {
	     uprintf(user, "$To: %s From: Hub $Sorry, only registered users are allowed on this hub.|", temp_nick);
	     return 0;
	  }
	
	if(check_if_banned(user, NICKBAN) != 0)
	  {
	     uprintf(user, "$To: %s From: Hub $Sorry, you have been banned from this hub.|", temp_nick);
	     return 0;
	  }

	if(strlen(default_pass) == 0)
	  {
	     hub_mess(user, HELLO_MESS);
	     if(welcome_mess(user) == -1)
	       return 0;
          }
     }
   /* And if user is a script, set the nick and add to nicklist.  */
   else
     {	
	strcpy(user->nick, temp_nick);
	if(add_user_to_list(user) == 0)
	  {
	     increase_user_list();
	     add_user_to_list(user);
	  }	
	sprintf(hello_buf, "$Hello %s|", user->nick);
	sock = human_sock_list;
	op_list = get_op_list();
	while(sock != NULL)
	  {
	     if(((sock->user->type & (REGULAR | REGISTERED | OP | OP_ADMIN | FORKED)) != 0)
		&& (user != sock->user))
	       {
		  send_to_user(hello_buf, sock->user);
		  send_to_user(op_list, sock->user);
	       }
	     sock = sock->next;
	  }
	non_human = non_human_user_list;
	while(non_human != NULL)
	  {
	     if(((non_human->type & FORKED) != 0)
		&& (user != non_human))
	       {
		  send_to_user(hello_buf, non_human);
		  send_to_user(op_list, non_human);
	       }
	     non_human = non_human->next;
	  }
	free(op_list);
     }
   return 1;
}

/* Sets the version of the client the user is using */
int version(char *buf, struct user_t *user)
{  
   if(sscanf(buf, "$Version %30[^ |]|", user->version) != 1)
     {                                                                    
	logprintf(4, "Received bad $Version command from %s at %s:\n", user->nick, user->hostname);
	if(strlen(buf) < 3500)
	  logprintf(4, "%s\n", buf);
	else
	  logprintf(4, "too large buf\n");
	return 0;
     }
   
   
   /* Check if version is equal to min_version or later */
   if((int)min_version[0] > 0x20)
     {
	if(strcmp(min_version, user->version) > 0)
	  {
	     uprintf(user, "<Hub-Security> Sorry, only clients of version %s or later are allowed to this hub.|", min_version);
	     return 0;
	  }
     }
   return 1;
}

/* Checks if users password is valid and if user is op.  */
int my_pass(char *buf, struct user_t *user)
{
   int ret;
   struct sock_t *sock;
   struct user_t *non_human;
   char hello_buf[MAX_NICK_LEN+10];
   char *op_list;
   char remove_string[MAX_NICK_LEN+15];
   char quit_string[MAX_NICK_LEN+10];
   struct user_t *d_user;
   char *user_list_nick;
   
   ret = check_pass(buf, user);
   
   switch(ret)
     {
      case 4:
	/* User is OP admin, i.e, an OP with priviledges to admin the hub
	 * from the chat */

	if((user_list_nick = check_if_on_user_list(user->nick)) != NULL)
	  {
	     remove_user_from_list(user->nick);
	     sprintf(quit_string, "$Quit %s|", user_list_nick);
	     send_to_humans(quit_string, REGULAR | REGISTERED | OP | OP_ADMIN,
			    user);
	     send_to_non_humans(quit_string, FORKED, NULL);	     
	     if((d_user = get_human_user(user->nick)) != NULL)
	       {		 
		  remove_human_from_hash(user->nick);
		  /* Change the nick so that it won't be removed from the
		   * hashtable after it has been added again.  */
		  strcpy(d_user->nick, "removed user");
		  d_user->rem = REMOVE_USER;
	       }    
	     else
	       {		  
		  sprintf(remove_string, "$DiscUser %s|", user->nick);
		  send_to_non_humans(remove_string, FORKED, NULL);
	       }	     
	  }
	
	add_human_to_hash(user);
	
	/* Add to user list */
	if(add_user_to_list(user) == 0)
	  {
	     increase_user_list();
	     add_user_to_list(user);
	  }
	user->type = OP_ADMIN;
	user->permissions = 0xFFFF;
	hub_mess(user, LOGGED_IN_MESS);
	hub_mess(user, OP_LOGGED_IN_MESS);
	sock = human_sock_list;
	if((op_list = get_op_list()) == NULL)
	  return 0;
	
	send_to_user(op_list, user);
	if(welcome_mess(user) == -1)
	  {
	     free(op_list);
	     return 0;
	  }	
	
	logprintf(1, "OP Admin %s logged in from %s\n", user->nick, user->hostname);
	
	/* Send the Hello and op list to all users */
	sprintf(hello_buf, "$Hello %s|", user->nick);
	if((op_list = get_op_list()) == NULL)
	  return 0;
	
	while(sock != NULL)
	  {
	     if(((sock->user->type & (REGULAR | REGISTERED | OP | OP_ADMIN | FORKED)) != 0)
		&& (user != sock->user))
	       {
		  send_to_user(hello_buf, sock->user);
		  send_to_user(op_list, sock->user);
	       }
	     sock = sock->next;
	  }
	non_human = non_human_user_list;
	while(non_human != NULL)
	  {
	     if(((non_human->type & FORKED) != 0)
		&& (user != non_human))
	       {
		  send_to_user(hello_buf, non_human);
		  send_to_user(op_list, non_human);
	       }
	     non_human = non_human->next;
	  }

	free(op_list);
	break;
	
      case 3:
	/* User is OP */
	
	if((user_list_nick = check_if_on_user_list(user->nick)) != NULL)
	  {	
	     remove_user_from_list(user->nick);
	     sprintf(quit_string, "$Quit %s|", user_list_nick);
	     send_to_humans(quit_string, REGULAR | REGISTERED | OP | OP_ADMIN,
			    user);
	     send_to_non_humans(quit_string, FORKED, NULL);
	     if((d_user = get_human_user(user->nick)) != NULL)
	       {
		  remove_human_from_hash(user->nick);
		  strcpy(d_user->nick, "removed user");
		  d_user->rem = REMOVE_USER;
	       }   
	     else
	       {		  
		  sprintf(remove_string, "$DiscUser %s|", user->nick);
		  send_to_non_humans(remove_string, FORKED, NULL);
	       }	     
	  }
	
	add_human_to_hash(user);
	
	/* Add to user list */
	if(add_user_to_list(user) == 0)
	  {
	     increase_user_list();
	     add_user_to_list(user);
	  }
	user->type = OP;
	user->permissions = get_permissions(user->nick);
	hub_mess(user, LOGGED_IN_MESS);
	hub_mess(user, OP_LOGGED_IN_MESS);
	
	if((op_list = get_op_list()) == NULL)
	  return 0;
	
	send_to_user(op_list, user);
	
	if(welcome_mess(user) == -1)
	  {
	     free(op_list);
	     return 0;
	  }
	
	logprintf(1, "OP %s logged in from %s\n", user->nick, user->hostname);
	
	/* Send the Hello and op list to all users */
	sprintf(hello_buf, "$Hello %s|", user->nick);
	op_list = get_op_list();
	sock = human_sock_list;
	while(sock != NULL)
	  {
	     if(((sock->user->type & (REGULAR | REGISTERED | OP | OP_ADMIN | FORKED)) != 0)
		&& (user != sock->user))
	       {
		  send_to_user(hello_buf, sock->user);
		  send_to_user(op_list, sock->user);
	       }
	     sock = sock->next;
	  }
	non_human = non_human_user_list;
	while(non_human != NULL)
	  {
	     if(((non_human->type & FORKED) != 0)
		&& (user != non_human))
	       {
		  send_to_user(hello_buf, non_human);
		  send_to_user(op_list, non_human);
	       }
	     non_human = non_human->next;
	  }
	

	free(op_list);
	break;
	
      case 2:
	/* User is registered */
	
	if((user_list_nick = check_if_on_user_list(user->nick)) != NULL)
	  {	
	     remove_user_from_list(user->nick);
	     sprintf(quit_string, "$Quit %s|", user_list_nick);
	     send_to_humans(quit_string, REGULAR | REGISTERED | OP | OP_ADMIN,
			    user);
	     send_to_non_humans(quit_string, FORKED, NULL);
	     if((d_user = get_human_user(user->nick)) != NULL)
	       {		 
		  remove_human_from_hash(user->nick);
		  strcpy(d_user->nick, "removed user");
		  d_user->rem = REMOVE_USER;
	       }   
	     else
	       {		  
		  sprintf(remove_string, "$DiscUser %s|", user->nick);
		  send_to_non_humans(remove_string, FORKED, NULL);
	       }	     
	  }
	
	add_human_to_hash(user);
	
	if(add_user_to_list(user) == 0)
	  {
	     increase_user_list();
	     add_user_to_list(user);
	  }	
	user->type = REGISTERED;
	hub_mess(user, LOGGED_IN_MESS);
	if(welcome_mess(user) == -1)
	  return 0;
	logprintf(1, "Registered user %s logged in from %s\n", user->nick, user->hostname);
	sprintf(hello_buf, "$Hello %s|", user->nick);
	sock = human_sock_list;
	while(sock != NULL)
	  {
	     if(((sock->user->type & (REGULAR | REGISTERED | OP | OP_ADMIN | FORKED)) != 0)
		&& (user != sock->user))
	       send_to_user(hello_buf, sock->user);
	     
	     sock = sock->next;
	  }
	
	non_human = non_human_user_list;
	while(non_human != NULL)
	  {
	     if(((non_human->type & FORKED) != 0)
		&& (user != non_human))
	       send_to_user(hello_buf, non_human);
	     
	     non_human = non_human->next;
	  }
	
	break;

      case 1:
	if((user_list_nick = check_if_on_user_list(user->nick)) != NULL)
	  {
	     hub_mess(user, BAD_PASS_MESS);
	     logprintf(1, "Host %s attempted to re-use %s nick\n", user->hostname, user_list_nick);
	     return 0;
          }

	add_human_to_hash(user);

	if(add_user_to_list(user) == 0)
	  {
	     increase_user_list();
	     add_user_to_list(user);
          }
	user->type = REGULAR;
	hub_mess(user, LOGGED_IN_MESS);
	if(welcome_mess(user) == -1)
	  return 0;
	logprintf(1, "Regular user %s logged in from %s\n", user->nick, user->hostname);
	sprintf(hello_buf, "$Hello %s|", user->nick);
	sock = human_sock_list;
	while(sock != NULL)
	  {
	     if(((sock->user->type & (REGULAR | REGISTERED | OP | OP_ADMIN | FORKED)) != 0)
	        && (user != sock->user))
	       send_to_user(hello_buf, sock->user);

	     sock = sock->next;
          }

	non_human = non_human_user_list;
	while(non_human != NULL)
	  {
	     if(((non_human->type & FORKED) != 0)
	        && (user != non_human))
	       send_to_user(hello_buf, non_human);

	     non_human = non_human->next;
	  }

	break;
		
      case 0:
	/* Validation failed */
	hub_mess(user, BAD_PASS_MESS);
	return 0;
     }
   return 1;
}

/* Removes a user without sending $Quit.  */
void disc_user(char *buf, struct user_t *user)
{
   char nick[MAX_NICK_LEN+1];
   struct user_t *remove_user;
   
   if(pid > 0)
     send_to_non_humans(buf, FORKED, user);
   else
     {	
	sscanf(buf, "$DiscUser %50[^|]|", nick);
	if((remove_user = get_human_user(nick)) != NULL)
	  {
	     remove_human_from_hash(nick);
	     remove_user->rem = REMOVE_USER;
	  }
     }
}

/* Kick a user. tempban is 1 if the command is sent from a human, but 0 if
 * used internally.  */
void kick(char *buf, struct user_t *user, int tempban)
{
   char command[11];
   char nick[MAX_NICK_LEN+1];
   char host[MAX_HOST_LEN+1];
   char ban_command[MAX_HOST_LEN+4];
   struct user_t *to_user;
   
   if(sscanf(buf, "%10s %50[^|]|", command, nick) != 2)
     {                                                                 
	logprintf(4, "Received bad $Kick command from %s at %s:\n", user->nick, user->hostname);
	if(strlen(buf) < 3500)
	  logprintf(4, "%s\n", buf);
	else
	  logprintf(4, "too large buf\n");
	return;
     }
   
   if((user != NULL) && (strncmp(nick, user->nick, strlen(nick)) == 0)
      && (strlen(nick) == strlen(user->nick)))
     return;
  
   /* If it was triggered internally.  */
   if(user == NULL)
     {
	if(check_if_on_user_list(nick) == NULL)
	  return;
	remove_user_from_list(nick);
     }
   
   else if((user->type & (OP | OP_ADMIN | ADMIN)) != 0)
     {	
	if(check_if_on_user_list(nick) == NULL)
	  {
	     if(user->type == ADMIN)
	       uprintf(user, "\r\nUser %s wasn't found in this hub\r\n", nick);
	     return;
	  }
	
	get_users_hostname(nick, host);
	logprintf(1, "User %s at %s was kicked by %s\n", nick, host, user->nick);
	if(user->type == ADMIN)
	  uprintf(user, "\r\nUser %s was kicked\r\n", nick);
	remove_user_from_list(nick);

	if((kick_bantime > 0) && (tempban != 0))
	  {
	     sprintf(ban_command, "%s %dm", host, kick_bantime);
	     ballow(ban_command, BAN, user);
	  }
	
#ifdef HAVE_PERL
	command_to_scripts("$Script kicked_user %c%c%s%c%c%s|",
			   '\005', '\005', nick, '\005', '\005', user->nick);
#endif	
     }
   
   else if(user->type == SCRIPT)
     {
	if(check_if_on_user_list(nick) == NULL)
	  return;
	
	remove_user_from_list(nick);
     }   
   
   if((to_user = get_human_user(nick)) != NULL)
     {	
	to_user->rem = REMOVE_USER | SEND_QUIT | REMOVE_FROM_LIST;
	return;
     }
   
   send_to_non_humans(buf, FORKED, user);
}

/* Quits the program */
void quit_program(void)
{  
   /* If we are a child process and the command wasn't sent from a forked
    * process, don't remove users.  */
   if(pid <= 0) 
     send_to_non_humans("$QuitProgram|", FORKED | SCRIPT, NULL);
   
   else
     {	   
	logprintf(1, "Got term signal, exiting...\n\n");
	
	/* If we are the parent.  */
	remove_all(0xFFFF, 0, 0);

	/* Give child processes some time to remove their users.  */
	sleep(1);
	
	/* Remove semaphores and shared memory segments.  */
	semctl(total_share_sem, 0, IPC_RMID, NULL);
	shmctl(total_share_shm, IPC_RMID, NULL);
	semctl(user_list_sem, 0, IPC_RMID, NULL);
	shmctl(get_user_list_shm_id(), IPC_RMID, NULL);
	shmctl(user_list_shm_shm, IPC_RMID, NULL);	
	write_config_file();	  
	
	/* If we are the parent, close the listening sockets and close the temp file */
	close(listening_socket);
	close(listening_unx_socket);
	unlink(un_sock_path);
	exit(EXIT_SUCCESS);
     }
}

/* Validate admin pass */
int check_admin_pass(char *buf, struct user_t *user)
{
   char command[21];
   char pass[MAX_ADMIN_PASS_LEN+1];
   
   sscanf(buf, "%20s %50[^|]|", command, pass);
      
   if((strncmp(pass, admin_pass, strlen(pass)) == 0) 
      && (strlen(pass) == strlen(admin_pass)))
     {
	if(get_human_user("Administrator") != NULL)
	  {	     
	     send_to_user("\r\nAdministrator is already logged in.\r\n", user);
	     return 0;
	  }		
	send_to_user("\r\nPassword accepted\r\n", user);
	user->type = ADMIN;
	remove_human_from_hash(user->nick);
	strcpy(user->nick, "Administrator");
	add_human_to_hash(user);
	logprintf(1, "%s logged in from %s.\n", user->nick, user->hostname);
     }
   else
     {
	send_to_user("\r\nBad Admin Password\r\n", user);
	return 0;
     }
   return 1;
}
    
/* Set various variables through the admin connection */
void set_var(char *org_buf, struct user_t *user)
{
   char *buf;
   char *c;
   char temp1[31];
   char temp2[31];
   
   buf = org_buf+5;
   
   if(strncmp(buf, "motd ", 5) == 0)
     {
	buf += 5;
	if((c = strrchr(buf, '|')) == NULL)
	  return;
	*c = '\0';
	if(write_motd(buf, 1) == -1)
	  return;
	if(user->type == ADMIN)
	  {
	     uprintf(user, "\r\nMotd set to: ");
	     send_motd(user);
	     uprintf(user, "\r\n");
	  }
	else if(user->type == OP_ADMIN)
	  {
	     uprintf(user, "<Hub-Security> Motd set to: ");
	     send_motd(user);
	     uprintf(user, "%c", '|');
	  }
     }
   else if(strncmp(buf, "hub_name ", 9) == 0)
     {
	buf += 9;
	strncpy(hub_name, buf, (cut_string(buf, '|') > MAX_HUB_NAME) ? MAX_HUB_NAME : cut_string(buf, '|'));
	hub_name[cut_string(buf, '|')] = '\0';
	if(user->type == ADMIN)
	  uprintf(user, "\r\nHub Name set to \"%s\"\r\n", hub_name);
	else if(user->type == OP_ADMIN)
	  uprintf(user, "<Hub-Security> Hub Name set to \"%s\"|", hub_name);
     }
   else if(strncmp(buf, "max_users ", 10) == 0)
     {
	buf += 10;
	max_users = atoi(buf);
	if(user->type == ADMIN)
	  uprintf(user, "\r\nMax Users set to %d\r\n", max_users);
	else if(user->type == OP_ADMIN)
	  uprintf(user, "<Hub-Security> Max Users set to %d|", max_users);
     }
   else if(strncmp(buf, "hub_full_mess ", 14) == 0)
     {
	buf += 14;
	if((hub_full_mess = realloc(hub_full_mess, sizeof(char) 
			   * (cut_string(buf, '|') + 1))) == NULL)
	  {
	     logprintf(1, "Error - In set_var()/realloc(): ");
	     logerror(1, errno);
	     quit = 1;
	     return;
	  }
	strncpy(hub_full_mess, buf, cut_string(buf, '|'));
	hub_full_mess[cut_string(buf, '|')] = '\0';
	if(user->type == ADMIN)
	  uprintf(user, "\r\nHub Full Mess set to \"%s\"\r\n", hub_full_mess);
	else if(user->type == OP_ADMIN)
	  uprintf(user, "<Hub-Security> Hub Full Mess set to \"%s\"|", hub_full_mess);
     }
   else if(strncmp(buf, "hub_description ", 16) == 0)
     {
	buf += 16;
	strncpy(hub_description, buf, (cut_string(buf, '|') > MAX_HUB_DESC) ? MAX_HUB_DESC : cut_string(buf, '|'));
	hub_description[cut_string(buf, '|')] = '\0';
	if(user->type == ADMIN)
	  uprintf(user, "\r\nHub Description set to \"%s\"\r\n", hub_description);
	else if(user->type == OP_ADMIN)
	  uprintf(user, "<Hub-Security> Hub Description set to \"%s\"|", hub_description);	
     }
   else if(strncmp(buf, "min_share ", 10) == 0)
     {
	buf += 10;
	memset(temp2, 0, sizeof(temp2));
	if(sscanf(buf, "%30s %30[^|]|", temp1, temp2) == 2)
	  {
	     min_share = strtoll(temp1, (char **)NULL, 10);
	     if(!strcasecmp(temp2, "mb"))
	       min_share = min_share << 20;
	     else if(!strcasecmp(temp2, "gb"))
	       min_share = min_share << 30;
	  }
	else
	  min_share = strtoll(temp1, (char **)NULL, 10);
	if(user->type == ADMIN)
	  {	     
	     if(!strcasecmp(temp2, "mb"))
	       uprintf(user, "\r\nMin Share set to %lld MegaBytes\r\n", min_share >> 20);
	     else if(!strcasecmp(temp2, "gb"))
	       uprintf(user, "\r\nMin Share set to %lld GigaBytes\r\n", min_share >> 30);
	     else
	       uprintf(user, "\r\nMin Share set to %lld Bytes\r\n", min_share);
	  }
	
	else if(user->type == OP_ADMIN)
	  {
	     if(!strcasecmp(temp2, "mb"))
	       uprintf(user, "<Hub-Security> Min Share set to %lld MegaBytes|", min_share >> 20);
	     else if(!strcasecmp(temp2, "gb"))
	       uprintf(user, "<Hub-Security> Min Share set to %lld GigaBytes|", min_share >> 30);
	     else
	       uprintf(user, "<Hub-Security> Min Share set to %lld Bytes|", min_share);
	  }
     }
   else if(strncmp(buf, "admin_pass ", 11) == 0)
     {
	buf += 11;
	strncpy(admin_pass, buf, (cut_string(buf, '|') > MAX_ADMIN_PASS_LEN) ? MAX_ADMIN_PASS_LEN : cut_string(buf, '|'));
	admin_pass[cut_string(buf, '|')] = '\0';
	if(user->type == ADMIN)
	  uprintf(user, "\r\nAdmin Pass set to \"%s\"\r\n", admin_pass);
	else if(user->type == OP_ADMIN)
	  uprintf(user, "<Hub-Security> Admin Pass set to \"%s\"|", admin_pass);
     }
   else if(strncmp(buf, "default_pass ", 13) == 0)
     {
        buf += 13;
        strncpy(default_pass, buf, (cut_string(buf, '|') > MAX_ADMIN_PASS_LEN) ? MAX_ADMIN_PASS_LEN : cut_string(buf, '|'));
        default_pass[cut_string(buf, '|')] = '\0';
        if(user->type == ADMIN)
          uprintf(user, "\r\nDefault Pass set to \"%s\"\r\n", default_pass);
        else if(user->type == OP_ADMIN)
          uprintf(user, "<Hub-Security> Default Pass set to \"%s\"|", default_pass);
     }
   else if(strncmp(buf, "link_pass ", 10) == 0)
     {
	buf += 10;
	strncpy(link_pass, buf, (cut_string(buf, '|') > MAX_ADMIN_PASS_LEN) ? MAX_ADMIN_PASS_LEN : cut_string(buf, '|'));
	link_pass[cut_string(buf, '|')] = '\0';
	if(user->type == ADMIN)
	  uprintf(user, "\r\nLink Pass set to \"%s\"\r\n", link_pass);
	else if(user->type == OP_ADMIN)
	  uprintf(user, "<Hub-Security> Link Pass set to \"%s\"|", link_pass);
     }
   else if(strncmp(buf, "users_per_fork ", 15) == 0)
     {
	buf += 15;
	users_per_fork = atoi(buf);
	if(user->type == ADMIN)
	  uprintf(user, "\r\nUsers Per Fork set to %d\r\n", users_per_fork);
	else if(user->type == OP_ADMIN)
	  uprintf(user, "<Hub-Security> Users Per Fork set to %d|", users_per_fork);
     }      
   else if(!strncmp(buf, "listening_port ", 15))
     {	
	buf += 15;
	listening_port = (unsigned int)(atoi(buf));
	if(user->type == ADMIN)
	  uprintf(user, "\r\nListening Port set to %u\r\n", listening_port);
	else if(user->type == OP_ADMIN)
	  uprintf(user, "<Hub-Security> Listening Port set to %u|", listening_port);
     }   
   else if(!strncmp(buf, "admin_port ", 11))
     {	
	buf += 11;
	admin_port = atoi(buf);
	if(user->type == ADMIN)
	  uprintf(user, "\r\nAdmin port set to %d\r\n", admin_port);
	else if(user->type == OP_ADMIN)
	  uprintf(user, "<Hub-Security> Admin port set to %d|", admin_port);
     }         
   else if(!strncmp(buf, "admin_localhost ", 16))
     {
	buf += 16;
	admin_localhost = atoi(buf);
	if(user->type == ADMIN)
	  uprintf(user, "\r\nAdmin localhost set to %d\r\n", admin_localhost);
        else if(user->type == OP_ADMIN)
	  uprintf(user, "<Hub-Security> Admin localhost set to %d|", admin_localhost);
     }
   else if(strncmp(buf, "public_hub_host ", 16) == 0)
     {
	buf += 16;
	strncpy(public_hub_host, buf, (cut_string(buf, '|') > MAX_HOST_LEN) ? MAX_HOST_LEN : cut_string(buf, '|'));
	public_hub_host[cut_string(buf, '|')] = '\0';
	if(user->type == ADMIN)
	  uprintf(user, "\r\nPublic hub host set to \"%s\"\r\n", public_hub_host);
	else if(user->type == OP_ADMIN)
	  uprintf(user, "<Hub-Security> Public hub host set to \"%s\"|", public_hub_host);
     }
   else if(strncmp(buf, "hub_hostname ", 13) == 0)
     {
	buf += 13;
	strncpy(hub_hostname, buf, (cut_string(buf, '|') > MAX_HOST_LEN) ? MAX_HOST_LEN : cut_string(buf, '|'));
	hub_hostname[cut_string(buf, '|')] = '\0';
	if(user->type == ADMIN)
	  uprintf(user, "\r\nHub Hostname set to \"%s\"\r\n", hub_hostname);
	else if(user->type == OP_ADMIN)
	  uprintf(user, "<Hub-Security> Hub Hostname set to \"%s\"|", hub_hostname);
     }
   else if(strncmp(buf, "min_version ", 12) == 0)
     {
	buf += 12;
	strncpy(min_version, buf, (cut_string(buf, '|') > MAX_VERSION_LEN) ? MAX_VERSION_LEN : cut_string(buf, '|'));
	min_version[cut_string(buf, '|')] = '\0';
	if(user->type == OP_ADMIN)
	  uprintf(user, "\r\nMinimum version set to \"%s\"\r\n", min_version);
	else if(user->type == ADMIN)
	  uprintf(user, "<Hub-Security> Minimum version set to \"%s\"|", min_version);
     }
   else if(strncmp(buf, "hublist_upload ", 15) == 0)
     {
	buf += 15;
	hublist_upload = atoi(buf);
	if(user->type == ADMIN)
	  uprintf(user, "\r\nHublist upload set to %d\r\n", hublist_upload);
	else if(user->type == OP_ADMIN)
	  uprintf(user, "<Hub-Securitye> Hublist upload set to %d|", hublist_upload);
     }
    else if(strncmp(buf, "redirect_host ", 14) == 0)
     {
	buf += 14;
	strncpy(redirect_host, buf, (cut_string(buf, '|') > MAX_HOST_LEN) ? MAX_HOST_LEN : cut_string(buf, '|'));
	redirect_host[cut_string(buf, '|')] = '\0';
	if(user->type == ADMIN)
	  uprintf(user, "\r\nRedirect Host set to \"%s\"\r\n", redirect_host);
	else if(user->type == OP_ADMIN)
	  uprintf(user, "<Hub-Security> Redirect Host set to \"%s\"|", redirect_host);
     }
   else if(strncmp(buf, "registered_only ", 16) == 0)
     {
	buf += 16;
	registered_only = atoi(buf);
	if(user->type == ADMIN)
	  uprintf(user, "\r\nRegistered only set to %d\r\n", registered_only);
	else if(user->type == OP_ADMIN)
	  uprintf(user, "<Hub-Security> Registered only set to %d|", registered_only);
     }
   else if(strncmp(buf, "check_key ", 10) == 0)
     {
	buf += 10;
	check_key = atoi(buf);
	if(user->type == ADMIN)
	  uprintf(user, "\r\nCheck key set to %d\r\n", check_key);
	else if(user->type == OP_ADMIN)
	  uprintf(user, "<Hub-Security> Check key set to %d|", check_key);
     }
    else if(strncmp(buf, "reverse_dns ", 12) == 0)
     {
	buf += 12;
	reverse_dns = atoi(buf);
	if(user->type == ADMIN)
	  uprintf(user, "\r\nReverse DNS set to %d\r\n", reverse_dns);
	else if(user->type == OP_ADMIN)
	  uprintf(user, "<Hub-Security> Reverse DNS set to %d|", reverse_dns);
     }
   else if(strncmp(buf, "verbosity ", 10) == 0)
     {
	buf += 10;
	verbosity = atoi(buf);
	if(user->type == ADMIN)
	  uprintf(user, "\r\nVerbosity set to %d\r\n", verbosity);
	else if(user->type == OP_ADMIN)
	  uprintf(user, "<Hub-Security> Verbosity set to %d|", verbosity);
     }
   else if(strncmp(buf, "redir_on_min_share ", 19) == 0)
     {
	buf += 19;
	redir_on_min_share = atoi(buf);
	if(user->type == ADMIN)
	  uprintf(user, "\r\nRedir on min share set to %d\r\n", redir_on_min_share);
	else if(user->type == OP_ADMIN)
	  uprintf(user, "<Hub-Security> Redir on min share set to %d|", redir_on_min_share);
     }
   else if(strncmp(buf, "ban_overrides_allow ", 20) == 0)
     {
	buf += 20;
	ban_overrides_allow = atoi(buf);
	if(user->type == ADMIN)
	  uprintf(user, "\r\nBan overrides allow set to %d\r\n", ban_overrides_allow);
	else if(user->type == OP_ADMIN)
	  uprintf(user, "<Hub-Security> Ban overrides allow set to %d|", ban_overrides_allow);
     }
   else if(strncmp(buf, "syslog_enable ", 14) == 0)
     {
	buf += 14;
	syslog_enable = atoi(buf);
	if(user->type == ADMIN)
	  uprintf(user, "\r\nSyslog enable set to %d\r\n", syslog_enable);
	else if(user->type == OP_ADMIN)
	  uprintf(user, "<Hub-Security> Syslog enable set to %d|", syslog_enable);
     }
   else if(strncmp(buf, "searchcheck_exclude_internal ", 29) == 0)
     {
	buf += 29;
	searchcheck_exclude_internal = atoi(buf);
	if(user->type == ADMIN)
	  uprintf(user, "\r\nSearchcheck exclude internal set to %d\r\n", searchcheck_exclude_internal);
	else if(user->type == OP_ADMIN)
	  uprintf(user, "<Hub-Security> Searchcheck exclude internal  set to %d|", searchcheck_exclude_internal);
     }
    else if(strncmp(buf, "searchcheck_exclude_all ", 24) == 0)
     {
	buf += 24;
	searchcheck_exclude_all = atoi(buf);
	if(user->type == ADMIN)
	  uprintf(user, "\r\nSearchcheck exclude all set to %d\r\n", searchcheck_exclude_all);
	else if(user->type == OP_ADMIN)
	  uprintf(user, "<Hub-Security> Searchcheck exclude all set to %d|", searchcheck_exclude_all);
     }
   else if(strncmp(buf, "kick_bantime ", 13) == 0)
     {
	buf += 13;
	kick_bantime = atoi(buf);
	if(user->type == ADMIN)
	  uprintf(user, "\r\nKick bantime set to %d\r\n", kick_bantime);
	else if(user->type == OP_ADMIN)
	  uprintf(user, "<Hub-Security> Kick bantime set to %d|", kick_bantime);
     }
   else if(strncmp(buf, "searchspam_time ", 16) == 0)
     {
	buf += 16;
	searchspam_time = atoi(buf);
	if(user->type == ADMIN)
	  uprintf(user, "\r\nSearchspam time set to %d\r\n", searchspam_time);
	else if(user->type == OP_ADMIN)
	  uprintf(user, "<Hub-Security> Searchspam time set to %d|", searchspam_time);
     }
   else if(strncmp(buf, "max_email_len ", 14) == 0)
     {
	buf += 14;
	max_email_len = atoi(buf);
	if(user->type == ADMIN)
	  uprintf(user, "\r\nMaximum email length set to %d\r\n", max_email_len);
	else if(user->type == OP_ADMIN)
	  uprintf(user, "<Hub-Security> Maximum email length set to %d|", max_email_len);
     }
   else if(strncmp(buf, "max_desc_len ", 13) == 0)
     {
	buf += 13;
	max_desc_len = atoi(buf);
	if(user->type == ADMIN)
	  uprintf(user, "\r\nMaximum description length set to %d\r\n", max_desc_len);
	else if(user->type == OP_ADMIN)
	  uprintf(user, "<Hub-Security> Maximum description length set to %d|", max_desc_len);
     }
   else if(strncmp(buf, "crypt_enable ", 13) == 0)
     {
	buf += 13;
	crypt_enable = atoi(buf);
	if(user->type == ADMIN)
	  uprintf(user, "\r\nPassword encryption set to %d\r\n", crypt_enable);
	else if(user->type == OP_ADMIN)
	  uprintf(user, "<Hub-Security> Password encryption set to %d|", crypt_enable);
     }
   
   
   if((user->type & (REGULAR | REGISTERED | OP | OP_ADMIN | ADMIN)) != 0)
     write_config_file();
   
   
   /* Forward command to other processes */
   
   /* If it was a "!set", the '!' has to be changed to a '$' */
   *org_buf = '$';
   
   if(strncmp(org_buf + 5, "motd ", 5) != 0)
     {	
	send_to_non_humans(org_buf, FORKED | SCRIPT, user);
	
	/* If it was sent from a script, we need to send it back.  */
	if((user->type == SCRIPT) && (pid > 0))
	  send_to_user(org_buf, user);
     }   
}

/* Adds an entry to banlist if type is BAN. Adds entry to allowlist if type is
 * ALLOW */
int ballow(char *buf, int type, struct user_t *user)
{
   FILE *fp;
   int fd;
   int i, j;
   int ret;
   int erret;
   char path[MAX_FDP_LEN+1];
   char line[1024];
   char period = '\0';
   char ban_host[MAX_HOST_LEN+1];
   char ban_line[MAX_HOST_LEN+12];
   /*   char ban_user[MAX_NICK_LEN+1]; */
   time_t ban_time = 0;
   time_t old_time;
   time_t now_time;
   
   /*   ban_user[0] = '\0'; */
   
   if(type == BAN)
     snprintf(path, MAX_FDP_LEN, "%s/%s", config_dir, BAN_FILE);
   else if(type == ALLOW)
     snprintf(path, MAX_FDP_LEN, "%s/%s", config_dir, ALLOW_FILE);
   else if(type == NICKBAN)
     snprintf(path, MAX_FDP_LEN, "%s/%s", config_dir, NICKBAN_FILE);
   else
     return -1;
   
   now_time = time(NULL);
   if(type == NICKBAN)
     {
	if(sscanf(buf, "%50s %lu%c", ban_host, &ban_time, &period) == 1)
	  ban_host[strlen(ban_host) - 1] = '\0';
	
	if(check_if_registered(ban_host) > check_if_registered(user->nick))
	  return -1;
     }
   else
     {
	if (sscanf(buf, "%120s %lu%c", ban_host, &ban_time, &period) == 1)
	   ban_host[strlen(ban_host) - 1] = '\0';
	
	/* The ban_user will only work if both time and period is provided, 
	 * otherwise the address of ban_user will be read into ban_time or 
	 * period. For example, !ban 100.100.100.100 joohn  adds a currupted 
	 * ban entry. Maybe gcc 3.x only assigns variables of the correct type
	 * with sscanf, but it doesn't work with 2.95 and it's probably not 
	 * the right way to do it anyway.  */
/*	ret = sscanf(buf, "%120s %lu%c %50[^|]", temp, &ban_time, &period, ban_user); */
	
/*	if(ret == 1)
	  {
             ret = sscanf(temp, "%120s %50[^|]", ban_host, ban_user);
	     if(ret == 1)
	       ban_host[strlen(ban_host) - 1] = '\0';
	     period = '\0';
	  }
	else 
	  if(ret == 2)
	  {
	     sscanf(temp, "%120s %lu %50[^|]", ban_host, &ban_time, ban_user);
	     period = '\0';
	  }
	else
	     strcpy(ban_host, temp);

	if(strlen(ban_user) == 0)
	     strcpy(ban_user, "-");*/
     }
   
   switch(period)
     {
	case 'd':
	  ban_time = ban_time * 24;
	case 'h':
	  ban_time = ban_time * 60;
	case 'm':
	  ban_time = ban_time * 60;
	case 's':
	default:
	  break;
     }

   /* First, check if user is already on list */
   while(((fd = open(path, O_RDONLY)) < 0) && (errno == EINTR))
     logprintf(1, "Error - In ballow()/open(): Interrupted system call. Trying again.\n");
   
   if(fd < 0)
     {
	logprintf(1, "Error - In ballow()/open(): ");
	logerror(1, errno);
	return -1;
     }
   
   /* Set the lock */
   if(set_lock(fd, F_RDLCK) == 0)
     {
	logprintf(1, "Error - In ballow(): Couldn't set file lock\n");
	close(fd);
	return -1;
     }
   
   if((fp = fdopen(fd, "r")) == NULL)
     {
	set_lock(fd, F_UNLCK);
	logprintf(1, "Error - In ballow()/fdopen(): ");
	logerror(1, errno);
	close(fd);
	return -1;
     }
   
   while(fgets(line, 1023, fp) != NULL)
     {
	trim_string(line);
	old_time = 0;
	
	j = strlen(line);
	if(j != 0)
	  {
	     /* Jump to next char which isn't a space */
	     i = 0;
	     while(line[i] == ' ')
	       i++;
	     
	     sscanf(line+i, "%120s %lu", ban_line, &old_time);
	     if((strcmp(ban_host, ban_line) == 0) &&
		((old_time == 0) || (old_time > now_time)))
	       {
		  set_lock(fd, F_UNLCK);
		  
		  while(((erret = fclose(fp)) != 0) && (errno == EINTR))
		    logprintf(1, "Error - In ballow()/fclose(): Interrupted system call. Trying again.\n");
		  
		  if(erret != 0)
		    {
		       logprintf(1, "Error - In ballow()/fclose(): ");
		       logerror(1, errno);
		       return -1;
		    }		  
		  
		  return 0;
	       }
	  }
     }
   set_lock(fd, F_UNLCK);
   
   while(((erret = fclose(fp)) != 0) && (errno == EINTR))
     logprintf(1, "Error - In ballow()/fclose(): Interrupted system call. Trying again.\n");
   
   if(erret != 0)
     {
	logprintf(1, "Error - In ballow()/fclose(): ");
	logerror(1, errno);
	return -1;
     }	
   
   if(type == NICKBAN)
     {
	if (ban_time > 0)
	   sprintf(ban_line, "%s %lu", ban_host, now_time + ban_time);
	else
	   sprintf(ban_line, "%s 0", ban_host);
     }
   else
     {
	if (ban_time > 0)
	  /* sprintf(ban_line, "%s %lu %s", ban_host, now_time + ban_time, ban_user); */
	  sprintf(ban_line, "%s %lu", ban_host, now_time + ban_time);
	else	  
	  /* sprintf(ban_line, "%s 0 %s", ban_host, ban_user); */
	  sprintf(ban_line, "%s 0", ban_host);
     }
   ret = add_line_to_file(ban_line, path); 
   
   /* Send to scripts */
#ifdef HAVE_PERL
   if(ret == 1)
     {
	if(type == BAN)
	  {	     
	     if (ban_time > 0)
	       {
		  command_to_scripts("$Script added_temp_ban %c%c", '\005', '\005');
		  non_format_to_scripts(ban_host);
		  command_to_scripts("%c%c%lu", '\005', '\005', ban_time);
	       }
	     else
	       {
		  command_to_scripts("$Script added_perm_ban %c%c", '\005', '\005');
		  non_format_to_scripts(ban_host);
	       }
	     command_to_scripts("|");
	  }	
	else if(type == ALLOW)
	    {	     
	       if (ban_time > 0)
		 {
		    command_to_scripts("$Script added_temp_allow %c%c", '\005', '\005');
		    non_format_to_scripts(ban_host);
		    command_to_scripts("%c%c%lu", '\005', '\005', ban_time);
		 }
	       else
		 {
		    command_to_scripts("$Script added_perm_allow %c%c", '\005', '\005');
		    non_format_to_scripts(ban_host);
		 }
	       command_to_scripts("|");
	    }
	else if(type == NICKBAN)
	    {
	       if (ban_time > 0)
		 {
		    command_to_scripts("$Script added_temp_nickban %c%c", '\005', '\005');
		    non_format_to_scripts(ban_host);
		    command_to_scripts("%c%c%lu", '\005', '\005', ban_time);
		 }
	       else
		 {
		    command_to_scripts("$Script added_perm_nickban %c%c", '\005', '\005');
		    non_format_to_scripts(ban_host);
		 }
	       command_to_scripts("|");
	    }	
     }   
#endif
   
   return ret;
}


/* Removes an entry from banlist or allowlist */
int unballow(char *buf, int type)
{
   int ret;
   char line[MAX_HOST_LEN+1];
   char path[MAX_FDP_LEN+1];
   
   if(type == BAN)
     snprintf(path, MAX_FDP_LEN, "%s/%s", config_dir, BAN_FILE);
   else if(type == ALLOW)
     snprintf(path, MAX_FDP_LEN, "%s/%s", config_dir, ALLOW_FILE);
   else if(type == NICKBAN)
     snprintf(path, MAX_FDP_LEN, "%s/%s", config_dir, NICKBAN_FILE);
   else
     return -1;
   
   sscanf(buf, "%120[^|]", line);
   remove_exp_from_file(time(NULL), path);
   ret = remove_line_from_file(line, path, 0);
   
   return ret;
}

/* Send banlist, allowlist or reg list to user */
void send_user_list(int type, struct user_t *user)
{
   FILE *fp;
   int fd;
   int erret;
   char line[4095];
   char pass[51];
   char nick[MAX_NICK_LEN+1];
   int regtype;
   char path[MAX_FDP_LEN+1];
   
   if(type == BAN)
     snprintf(path, MAX_FDP_LEN, "%s/%s", config_dir, BAN_FILE);
   else if(type == ALLOW)
     snprintf(path, MAX_FDP_LEN, "%s/%s", config_dir, ALLOW_FILE);
   else if(type == REG)
     snprintf(path, MAX_FDP_LEN, "%s/%s", config_dir, REG_FILE);
   else if(type == CONFIG)
     snprintf(path, MAX_FDP_LEN, "%s/%s", config_dir, CONFIG_FILE);
   else if(type == LINK)
     snprintf(path, MAX_FDP_LEN, "%s/%s", config_dir, LINK_FILE);
   else if(type == NICKBAN)
     snprintf(path, MAX_FDP_LEN, "%s/%s", config_dir, NICKBAN_FILE);
   else
     return;
   
   while(((fd = open(path, O_RDONLY)) < 0) && (errno == EINTR))
     logprintf(1, "Error - In send_user_list()/open(): Interrupted system call. Trying again.\n");
   
   if(fd < 0)
     {
	logprintf(1, "Error - In send_user_list()/open(): ");
	logerror(1, errno);
	return;
     }
   
   /* Set the lock */
   if(set_lock(fd, F_RDLCK) == 0)
     {
	logprintf(1, "Error - In send_user_list(): Couldn't set file lock\n");
	close(fd);
	return;
     }              
   
   if((fp = fdopen(fd, "r")) == NULL)
     {
	logprintf(1, "Error - In send_user_list()/fdopen(): ");
	logerror(1, errno);
	set_lock(fd, F_UNLCK);
	close(fd);
	return;
     }
   
   if(fgets(line, 4094, fp) != NULL)
     {	
	trim_string(line);
	if(type == REG)
	  {
	     sscanf(line, "%s %s %d", nick, pass, &regtype);
	     uprintf(user, "%s %d", nick, regtype);
	  }
	else
	  uprintf(user, "%s", line);
	
	while(fgets(line, 4094, fp) != NULL)
	  {	     
	     trim_string(line);
	     if(type == REG)
	       {
		  sscanf(line, "%s %s %d", nick, pass, &regtype);
		  uprintf(user, "\r\n%s %d", nick, regtype);
	       }
	     else
	       uprintf(user, "\r\n%s", line);
	  }	
     }
   
   set_lock(fd, F_UNLCK);
   while(((erret = fclose(fp)) != 0) && (errno == EINTR))
     logprintf(1, "Error - In send_user_list()/fclose(): Interrupted system call. Trying again.\n");
   
   if(erret != 0)
     {
	logprintf(1, "Error - In send_user_list()/fclose(): ");
	logerror(1, errno);
     }	
}

/* Redirect a user by request from op or admin, the format is:
 * $OpForceMove $Who:nick$Where:redirectip$Msg:message| */
void op_force_move(char *buf, struct user_t *user)
{
   char command[21];
   char *temp;
   char nick[MAX_NICK_LEN+1];
   char ip[MAX_HOST_LEN+1];
   char message[11];
   struct user_t *to_user;
   char quit_string[MAX_NICK_LEN+10];
   int num;
   
   num = sscanf(buf, "%20s $Who:%50[^$]$Where:%121[^$]$Msg:%10[^|]|",
		  command, nick, ip, message);
   if(user->type != FORKED)
     {
	if(num != 4)
	  {		
	     logprintf(4, "Received bad $OpForceMove command from %s at %s:\n", user->nick, user->hostname);
	     if(strlen(buf) < 3500)
	       logprintf(4, "%s\n", buf);
	     else
	       logprintf(4, "too large buf\n");
	     return;
	  }
	
	if(message[0] == '\0')
	  {                                                         
	     logprintf(4, "Received bad $OpForceMove command from %s at %s:\n", user->nick, user->hostname);
	     if(strlen(buf) < 3500)
	       logprintf(4, "%s\n", buf);
	     else
	       logprintf(4, "too large buf\n");
	     return;
	  }
     }
   
   if((temp = strstr(buf, "$Msg:")) == NULL)
     {                                                         
	logprintf(4, "Received bad $OpForceMove command from %s at %s:\n", user->nick, user->hostname);
	if(strlen(buf) < 3500)
	  logprintf(4, "%s\n", buf);
	else
	  logprintf(4, "too large buf\n");
	return;
     }
   
   /* If we received the command directly from the user.  */
   if(user->type != FORKED)
     {
	if(check_if_on_user_list(nick) != NULL)
	  logprintf(4, "%s was redirected to %s by %s\n", nick, ip, user->nick);	   
	else
	  {
	     if(user->type == ADMIN)
	       uprintf(user, "\r\n%s wasn't found in this hub.\r\n", nick);
	     return;
	  }
	
	temp += 5;
	
	/* First check if user is connected to this process */
	if((to_user = get_human_user(nick)) != NULL)
	  {	
	     uprintf(to_user, "$To: %s From: %s $<%s> ", 
		     nick, user->nick, user->nick);
	     send_to_user(temp, to_user);
	  }
	else
	  {
	     uprintf(non_human_user_list, "$To: %s From: %s $<%s> ", 
		     nick, user->nick, user->nick);
	     send_to_user(temp, non_human_user_list);
	  }
     }
   
   /* If the user to be redirected is connected to this process.  */
   if((to_user = get_human_user(nick)) != NULL)
     {
	/* And then the ForceMove command */
	uprintf(to_user, "$ForceMove %s|", ip);
	remove_user_from_list(to_user->nick);
	remove_human_from_hash(to_user->nick);
	to_user->type = NON_LOGGED;
	
	/* Remove the users share from the total share.  */
	if(to_user->share > 0)
	  add_total_share(-to_user->share);
	
	sprintf(quit_string, "$Quit %s|", to_user->nick);
	send_to_humans(quit_string, REGULAR | REGISTERED | OP 
		       | OP_ADMIN, to_user);
	send_to_non_humans(quit_string, FORKED, NULL);
#ifdef HAVE_PERL		       
	command_to_scripts("$Script user_disconnected %c%c", '\005', '\005');
	non_format_to_scripts(to_user->nick);
	command_to_scripts("|");		       
#endif		       	
     }
   else	
     /* If the user wasn't in this process, forward to other processes.  */
     send_to_non_humans(buf, FORKED, user);
}

/* Redirect all users to address specified in buf */
void redirect_all(char *buf, struct user_t *user)
{
   char move_string[MAX_HOST_LEN+20];
   
   sprintf(move_string, "$ForceMove %s", buf);
 
   send_to_humans(move_string, REGULAR | REGISTERED | OP, user);
   remove_all(UNKEYED | NON_LOGGED | REGULAR | REGISTERED | OP, 1, 1);
   send_to_non_humans(move_string, FORKED, user);

   /* To scripts. */
#ifdef HAVE_PERL
   command_to_scripts("$Script started_redirecting %c%c", '\005', '\005');
   non_format_to_scripts(buf);
#endif
}

/* Handles the $Up and $UpToo commands, sent from linked hubs */
void up_cmd(char *buf, int port)
{
   int fd;
   int erret;
   FILE *fp;
   char path[MAX_FDP_LEN+1];
   char line[1024];
   struct user_t *user_list;
   struct user_t *user;
   char ip[MAX_HOST_LEN+1];
   char fileip[MAX_HOST_LEN+1];
   int fileport;
   char cmd[11];
   char pass[MAX_ADMIN_PASS_LEN+1];

   snprintf(path, MAX_FDP_LEN, "%s/%s", config_dir, LINK_FILE);
   if(sscanf(buf, "%10s %50s %121[^|]|", cmd, pass, ip) != 3)
     {                                          
	logprintf(4, "Received bad $Up command:\n");
	if(strlen(buf) < 3500)
	  logprintf(4, "%s\n", buf);
	else
	  logprintf(4, "too large buf\n");
	return;
     }
   
   if((strncmp(pass, link_pass, strlen(pass)) != 0) || (strlen(pass) != strlen(link_pass)))
     {
	logprintf(2, "Linked hub sent bad password:\n");
	if(strlen(buf) < 3500)
	  logprintf(2, "%s\n", buf);
	else
	  logprintf(2, "too large buf\n");
	return;
     }
   
   /* Check if hub is already among the users */
   user_list = non_human_user_list;
   while(user_list != NULL)
     {
	if((user_list->type == LINKED) 
	   && (strncmp(ip, user_list->hostname, strlen(user_list->hostname)) == 0)
	   && (strlen(ip) == strlen(user_list->hostname))
	   && (port == user_list->key))
	  { 
	     user_list->timeout = 1;
	     if(strncmp(buf, "$Up ", 4) == 0)
	       uprintf(user_list, "$UpToo %s %s|", link_pass, hub_hostname);
	     return;
	  }	
	user_list = user_list->next;
     }
   
   while(((fd = open(path, O_RDONLY)) < 0) && (errno == EINTR))
     logprintf(1, "Error - In up_cmd()/open(): Interrupted system call. Trying again.\n");
   
   if(fd < 0)
     {
	logprintf(1, "Error - In up_cmd()/open(): ");
	logerror(1, errno);
	return;
     }
   
   /* Set the lock */
   if(set_lock(fd, F_RDLCK) == 0)
     {	
	logprintf(1, "Error - In up_cmd(): Couldn't set lock\n");
	close(fd);
	return;
     }
   
   if((fp = fdopen(fd, "r")) == NULL)
     {	
	logprintf(1, "Error - In unballow()/fdopen(): ");
	logerror(1, errno);
	set_lock(fd, F_UNLCK);
	close(fd);
	return;
     }
   
   while(fgets(line, 1023, fp) != NULL)
     {
	trim_string(line);
	sscanf(line, "%121s %d", fileip, &fileport);
	if((strncmp(ip, fileip, strlen(fileip)) == 0)
	   && (port == fileport) && (strlen(ip) == strlen(fileip))
	   && (max_sockets >= (count_users(0xFFFF)+5)))
	  {  
	     /* Allocate space for the new user */
	     if((user = malloc(sizeof(struct user_t))) == NULL)
	       {		  
		  logprintf(1, "Error - In up_cmd()/malloc(): ");
		  logerror(1, errno);
		  quit = 1;
		  return;
	       }
			       	     
	     strcpy(user->hostname, ip);
	     user->type = LINKED;
	     user->timeout = 1;
	     
	     /* Since key isn't used with linked hubs, it's used for the port here instead */
	     user->key = port;
	     user->buf = NULL;
	     user->outbuf = NULL;
	     
	     /* Add the user to the non-human user list.  */
	     add_non_human_to_list(user);
	     
	     logprintf(2, "Linked hub is up at %s, port %d\n", user->hostname, user->key);
	     
	     /* If it was an $Up , send $UpToo */
	     if(strncmp(buf, "$Up ", 4) == 0)
	       uprintf(user, "$UpToo %s %s|", link_pass, hub_hostname);
	     set_lock(fd, F_UNLCK);
	     
	     while(((erret = fclose(fp)) != 0) && (errno == EINTR))
	       logprintf(1, "Error - In up_cmd()/fclose(): Interrupted system call. Trying again.\n");
	     
	     if(erret != 0)
	       {
		  logprintf(1, "Error - In up_cmd()/fclose(): ");
		  logerror(1, errno);
	       }	

	     return;
	  }
     }
   set_lock(fd, F_UNLCK);
   	
   while(((erret = fclose(fp)) != 0) && (errno == EINTR))
     logprintf(1, "Error - In up_cmd()/fclose(): Interrupted system call. Trying again.\n");
   
   if(erret != 0)
     {
	logprintf(1, "Error - In up_cmd()/fclose(): ");
	logerror(1, errno);
     }
}

/* Returns the host of a user to the admin */
void get_host(char *buf, struct user_t *user, int type)
{
   char command[11];
   char nick[MAX_NICK_LEN+1];
   char temp_host[MAX_HOST_LEN+1];
   struct hostent *host;
   struct in_addr in;
   
   memset(&in, 0, sizeof(struct in_addr));
   if(sscanf(buf, "%10s %50[^|]|", command, nick) != 2)
     {
	logprintf(4, "Received bad $OpForceMove command from %s at %s:\n", user->nick, user->hostname);
	if(strlen(buf) < 3500)
	  logprintf(4, "%s\n", buf);
	else
	  logprintf(4, "too large buf\n");
	return;
     }
   
   get_users_hostname(nick, temp_host);
   
   if(*temp_host == (char)NULL)
     {
	if(user->type == ADMIN)
	  uprintf(user, "\r\nUser %s wasn't found\r\n", nick);
	else
	  uprintf(user, "<Hub-Security> User %s wasn't found|", nick);
	return;
     }   
   
   if(type == HOST)
     {
	if(user->type == ADMIN)
	  uprintf(user, "\r\n%s has hostname: %s\r\n", nick, temp_host);
	else
	  uprintf(user, "<Hub-Security> %s has hostname: %s|", nick, temp_host);
	return;
     }   
	
   else if(type == IP)
     {
	host = gethostbyname(temp_host);
	if(host == NULL)
	  {	     
	     logprintf(4, "Error - In get_host(): Error in gethostbyname()\n");
	     return;
	  }
	in.s_addr = *((long unsigned *)host->h_addr);
	sprintf(temp_host, "%s", inet_ntoa(in));
	if(user->type == ADMIN)
	  uprintf(user, "\r\n%s has ip: %s\r\n", nick, temp_host);
	else
	  uprintf(user, "<Hub-Security> %s has ip: %s|", nick, temp_host);
	
     }   	
}

void send_commands(struct user_t *user)
{
   if((user->type & (OP_ADMIN | OP)) != 0)
     uprintf(user, "<Hub-Security> Commands:\r\n");

   else if(user->type == ADMIN)
     uprintf(user, "\r\nCommands:\r\n");
   if(user->type == ADMIN)
     {	
	uprintf(user, "$adminpass 'password'|\r\n");
	uprintf(user, "Sends the administrations password. This has to be sent before any other\r\ncommands. This command does NOT work in chat for security reasons. A\r\nuser must be registered as an Op Admin before the user can use the\r\nadmin commands in chat.\r\n\r\n");
     }   

   if(user->type == ADMIN)
     uprintf(user, "$set 'variable' 'value'|\r\n");
   else if(user->type == OP_ADMIN)
     uprintf(user, "!set 'variable' 'value'\r\n");
   if((user->type & (ADMIN | OP_ADMIN)) != 0)
     uprintf(user, "Sets a value in the config file. The config file is located in the\r\n.opendchub directory, which is located in the root of your home directory.\r\nThe variables are explained in the config file. The program must be run\r\nonce first to create the config file.\r\nThe motd is placed in a file of it's own. To change the motd, use \"!set motd\".\r\n\r\n");
   
   if(user->type == ADMIN)
     uprintf(user, "$ban 'ip or hostname' 'time'|\r\n");
   else if(((user->permissions & BAN_ALLOW) != 0) && ((user->type & (OP_ADMIN | OP)) != 0))
     uprintf(user, "!ban 'ip or hostname' 'time'\r\n");
   if(((user->type & (ADMIN | OP_ADMIN)) != 0) || ((user->permissions & BAN_ALLOW) != 0))
     uprintf(user, "Adds an entry to the banlist. The entry can be a subnet or a whole ip\r\naddress or a hostname. Hostnames may contain '*' as wildcard. The time is the\r\nduration of the ban and can be 0 for permanent or a value followed by a\r\nperiod (e.g. 10m). Accepted periods are s(seconds), m(minutes, h(hours) and\r\nd(days).\r\n\r\n");
//     uprintf(user, "Adds an entry to the banlist. The entry can be the start of, or a whole ip\r\naddress or part of, or a whole hostname. The time is the duration of the\r\nban and can be 0 for permanent or a value followed by a period (e.g. 10m).\r\nAccepted periods are s(seconds), m(minutes), h(hours) and d(days). The nick\r\nof the banned user can also be provided for informational purposes.\r\n\r\n");
   
   if(user->type == ADMIN)
     uprintf(user, "$nickban 'nick' 'time'|\r\n");
   else if(((user->permissions & BAN_ALLOW) != 0) && ((user->type & (OP_ADMIN | OP)) != 0))
     uprintf(user, "!nickban 'nick' 'time'\r\n");
   if(((user->type & (ADMIN | OP_ADMIN)) != 0) || ((user->permissions & BAN_ALLOW) != 0))
     uprintf(user, "Adds an entry to the nick banlist. The time is the same as for the ban command\r\n\r\n");
   
   if(user->type == ADMIN)
     uprintf(user, "$allow 'ip or hostname'|\r\n");
   else if(((user->permissions & BAN_ALLOW) != 0) && ((user->type & (OP_ADMIN | OP)) != 0))
     uprintf(user, "!allow 'ip or hostname'\r\n");
   if(((user->type & (ADMIN | OP_ADMIN)) != 0) || ((user->permissions & BAN_ALLOW) != 0))
     uprintf(user, "Adds an entry to the allowlist. This file works like the opposite of\r\nbanlist, i.e, the entries in this file are allowed to the hub.\r\n\r\n");
   
   if(user->type == ADMIN)
     uprintf(user, "$getbanlist|\r\n");
   else if(((user->permissions & BAN_ALLOW) != 0) && ((user->type & (OP_ADMIN | OP)) != 0))
     uprintf(user, "!getbanlist\r\n");
   if(((user->type & (ADMIN | OP_ADMIN)) != 0) || ((user->permissions & BAN_ALLOW) != 0))
     uprintf(user, "Displays the banlist file.\r\n\r\n");
		  
   if(user->type == ADMIN)
     uprintf(user, "$getnickbanlist|\r\n");
   else if(((user->permissions & BAN_ALLOW) != 0) && ((user->type & (OP_ADMIN | OP)) != 0))
     uprintf(user, "!getnickbanlist\r\n");
   if(((user->type & (ADMIN | OP_ADMIN)) != 0) || ((user->permissions & BAN_ALLOW) != 0))
     uprintf(user, "Displays the nick banlist file.\r\n\r\n");
		  
   if(user->type == ADMIN)
     uprintf(user, "$getallowlist|\r\n");
   else if(((user->permissions & BAN_ALLOW) != 0) && ((user->type & (OP_ADMIN | OP)) != 0))
     uprintf(user, "!getallowlist\r\n");
   if(((user->type & (ADMIN | OP_ADMIN)) != 0) || ((user->permissions & BAN_ALLOW) != 0))
     uprintf(user, "Displays the allowlist file.\r\n\r\n");
   
   if(user->type == ADMIN)
     uprintf(user, "$unban 'ip or hostname'|\r\n");
   else if(((user->permissions & BAN_ALLOW) != 0) && ((user->type & (OP_ADMIN | OP)) != 0))
     uprintf(user, "!unban 'ip or hostname'\r\n");
   if(((user->type & (ADMIN | OP_ADMIN)) != 0) || ((user->permissions & BAN_ALLOW) != 0))
     uprintf(user, "Removes an entry from the banlist file. The hostname/IP entry in the file must\r\nbe an exact match of the one provided in the command.\r\n\r\n");
   
   if(user->type == ADMIN)
     uprintf(user, "$unnickban 'nick'|\r\n");
   else if(((user->permissions & BAN_ALLOW) != 0) && ((user->type & (OP_ADMIN | OP)) != 0 ))
     uprintf(user, "!unnickban 'nick'\r\n");
   if(((user->type & (ADMIN | OP_ADMIN)) != 0) || ((user->permissions & BAN_ALLOW) != 0))
     uprintf(user, "Removes an entry from the nick banlist file. The nick entry in the file must\r\nbe an exact match of the one provided in the command.\r\n\r\n");
   
   if(user->type == ADMIN)
     uprintf(user, "$unallow 'ip or hostname'|\r\n");
   else if(((user->permissions & BAN_ALLOW) != 0) && ((user->type & (OP_ADMIN | OP)) != 0))
     uprintf(user, "!unallow 'ip or hostname'\r\n");
   if(((user->type & (ADMIN | OP_ADMIN)) != 0) || ((user->permissions & BAN_ALLOW) != 0))
     uprintf(user, "Removes an entry from the allowlist file.\r\n\r\n");
   
   if(user->type == ADMIN)
     uprintf(user, "$addreguser 'nickname' 'password' 'op'|\r\n");
   else if(((user->permissions & USER_ADMIN) != 0) && ((user->type & (OP_ADMIN | OP)) != 0))
     uprintf(user, "!addreguser 'nickname' 'password' 'op'\r\n");
   if(((user->type & (ADMIN | OP_ADMIN)) != 0) || ((user->permissions & USER_ADMIN) != 0))
     uprintf(user, "Adds a user the the regfile. if 'op' is 1, the user is op, which allows user\r\nto use the dedicated op commands, for example $Kick. If 'op' is 2, the user\r\nalso gets priviledges to administer the hub through the chat. If 'op is 0,\r\nthe user is an ordinary registered user with no special priviledges.\r\n\r\n");
   
   if(user->type == ADMIN)
     uprintf(user, "$getreglist|\r\n");
   else if(((user->permissions & USER_ADMIN) != 0) && ((user->type & (OP_ADMIN | OP)) != 0))
     uprintf(user, "!getreglist\r\n");
   if(((user->type & (ADMIN | OP_ADMIN)) != 0) || ((user->permissions & USER_ADMIN) != 0))
     uprintf(user, "Displays the reglist.\r\n\r\n");
   
   if(user->type == ADMIN)
     uprintf(user, "$removereguser 'nickname'|\r\n");
   else if(((user->permissions & USER_ADMIN) != 0) && ((user->type & (OP_ADMIN | OP)) != 0))
     uprintf(user, "!removereguser 'nickname'\r\n");
   if(((user->type & (ADMIN | OP_ADMIN)) != 0) || ((user->permissions & USER_ADMIN) != 0))
     uprintf(user, "Removes a user from the reglist.\r\n\r\n");
   
   if(user->type == ADMIN)
     uprintf(user, "$addlinkedhub 'hubip' 'port'|\r\n");
   else if(user->type == OP_ADMIN)
     uprintf(user, "!addlinkedhub 'hubip' 'port'\r\n");
   if((user->type & (ADMIN | OP_ADMIN)) != 0)
     uprintf(user, "Adds a hub to the linked hub list. The hub is linked with the hubs on this\r\nlist, wich makes it possible for users to search for file and connect to\r\nusers on other hubs. 'port' is the port on which the linked hub is run.\r\n\r\n");
   
   if(user->type == ADMIN)
     uprintf(user, "$getlinklist|\r\n");
   else if(user->type == OP_ADMIN)
     uprintf(user, "!getlinklist\r\n");
   if((user->type & (ADMIN | OP_ADMIN)) != 0)
     uprintf(user, "Displays the linked hubs file.\r\n\r\n");
   
   if(user->type == ADMIN)
     uprintf(user, "$removelinkedhub 'hubip' 'port'|\r\n");
   else if(user->type == OP_ADMIN)
     uprintf(user, "!removelinkedhub 'hubip' 'port'\r\n");
   if((user->type & (ADMIN | OP_ADMIN)) != 0)
     uprintf(user, "Removes a hub from the linked hub list.\r\n\r\n");
   
   if(user->type == ADMIN)
     uprintf(user, "$getconfig|\r\n");
   else if(user->type == OP_ADMIN)
     uprintf(user, "!getconfig\r\n");
   if((user->type & (ADMIN | OP_ADMIN)) != 0)
     uprintf(user, "Displays the config file.\r\n\r\n");
   
   if(user->type == ADMIN)
     uprintf(user, "$getmotd|\r\n");
   else if(user->type == OP_ADMIN)
     uprintf(user, "!getmotd\r\n");
   if((user->type & (ADMIN | OP_ADMIN)) != 0)
     uprintf(user, "Displays the motd file.\r\n\r\n");
   
   if(user->type == ADMIN)
    uprintf(user, "$quitprogram|\r\n");
   else if(user->type == OP_ADMIN)
     uprintf(user, "!quitprogram\r\n");
   if((user->type & (ADMIN | OP_ADMIN)) != 0)
     uprintf(user, "Terminates the program. Has the same effect as sending term signal to the\r\nprocess, which also makes the hub shutting down cleanly.\r\n\r\n");
   
   if(user->type == ADMIN)
     uprintf(user, "$exit|\r\n");
   else if(user->type == OP_ADMIN)
     uprintf(user, "!exit\r\n");
   if((user->type & (ADMIN | OP_ADMIN)) != 0)
     uprintf(user, "Disconnects from the hub.\r\n\r\n");
   
   if(user->type == ADMIN)
     uprintf(user, "$redirectall 'ip or hostname'|\r\n");
   else if(user->type == OP_ADMIN)
     uprintf(user, "!redirectall 'ip or hostname'\r\n");
   if((user->type & (ADMIN | OP_ADMIN)) != 0)
     uprintf(user, "Redirects all users to 'ip or hostname'.\r\n\r\n");
   
   if(user->type == ADMIN)
     uprintf(user, "$gethost 'nick'|\r\n");
   else if(((user->permissions & USER_INFO) != 0) && ((user->type & (OP_ADMIN | OP)) != 0))
     uprintf(user, "!gethost 'nick'\r\n");
   if(((user->type & (ADMIN | OP_ADMIN)) != 0) || ((user->permissions & USER_INFO) != 0))
     uprintf(user, "Displays the hostname of user with nickname 'nick'.\r\n\r\n");
   
   if(user->type == ADMIN)
     uprintf(user, "$getip 'nick'|\r\n");
   else if(((user->permissions & USER_INFO) != 0) && ((user->type & (OP_ADMIN | OP)) != 0))
     uprintf(user, "!getip 'nick'\r\n");
   if(((user->type & (ADMIN | OP_ADMIN)) != 0) || ((user->permissions & USER_INFO) != 0))
     uprintf(user, "Displays the ip of user with nickname 'nick'.\r\n\r\n");
   
   if(user->type == ADMIN)
     uprintf(user, "$massmessage 'message'|\r\n");
   else if(((user->permissions & MASSMESSAGE) != 0) && ((user->type & (OP_ADMIN | OP)) != 0))
     uprintf(user, "!massmessage 'message'\r\n");
   if(((user->type & (ADMIN | OP_ADMIN)) != 0) || ((user->permissions & MASSMESSAGE) != 0))
     uprintf(user, "Sends a private message to all logged in users.\r\n\r\n");
   
   if(user->type == ADMIN)
     uprintf(user, "$reloadscripts|\r\n");
   else if(user->type == OP_ADMIN)
     uprintf(user, "!reloadscripts\r\n");
   if((user->type & (ADMIN | OP_ADMIN)) != 0)
     uprintf(user, "Reloads the scripts in the script directory.\r\n\r\n");
   
  if(user->type == ADMIN)
    uprintf(user, "$addperm 'nick' 'permission'|\r\n");
  else if(user->type == OP_ADMIN)
    uprintf(user, "!addperm 'nick' 'permission'\r\n");
  if((user->type & (ADMIN | OP_ADMIN)) != 0)
    uprintf(user, "Adds the permission (one of BAN_ALLOW, USER_INFO, MASSMESSAGE, USER_ADMIN)\r\nto the operator with nickname 'nick'.\r\n\r\n");
   
  if(user->type == ADMIN)
    uprintf(user, "$removeperm 'nick' 'permission'|\r\n");
  else if(user->type == OP_ADMIN)
    uprintf(user, "!removeperm 'nick' 'permission'\r\n");
  if((user->type & (ADMIN | OP_ADMIN)) != 0)
    uprintf(user, "Removes the permission (one of BAN_ALLOW, USER_INFO, MASSMESSAGE, USER_ADMIN)\r\nfrom the operator with nickname 'nick'.\r\n\r\n");
   
  if(user->type == ADMIN)
    uprintf(user, "$showperms 'nick'|\r\n");
  else if(user->type == OP_ADMIN)
    uprintf(user, "!showperms 'nick'\r\n");
  if((user->type & (ADMIN | OP_ADMIN)) != 0)
    uprintf(user, "Shows the permissions (BAN_ALLOW, USER_INFO, MASSMESSAGE, USER_ADMIN)\r\ncurrently granted to the operator with nickname 'nick'.\r\n\r\n");
   
   if(user->type == ADMIN)
     uprintf(user, "$commands|\r\n");
   else if((user->type & (OP_ADMIN | OP)) != 0)
     uprintf(user, "!commands\r\n");
   uprintf(user, "Displays all available admin commands.\r\n\r\n");

   if(user->type == ADMIN)
     {
	uprintf(user, "$GetNickList|\r\nReturns a list of all users connected to the hub in the form:\r\n$NickList 'user1'$$'user2'$$...'usern'$$||OpList 'op1'$$'op2'$$...'opn'||\r\n\r\n");
	uprintf(user, "$GetINFO 'nickname' Administrator|\r\nDisplays the user info of user with nick 'nickname'.\r\n\r\n");
	uprintf(user, "$To: 'nickname' From: Administrator $'message string'|\r\nSends a private message from administrator to user.\r\n\r\n");
	uprintf(user, "<Administrator> 'chat string'|\r\nThis is the only command that does not start with the '$'. It sends a\r\nmessage to the public chat. Note that the nickname of the administrator is\r\n\"Administrator\". It can't be changed.\r\n\r\n");
	uprintf(user, "$Kick 'nickname'|\r\nKicks the user with nick 'nickname'\r\n\r\n");
	uprintf(user, "$OpForceMove $Who:'nick':$Where:'host or ip'$Msg:'message'|\r\nRedirects user with 'nick' to the hostname or ip and displays the\r\nmessage 'message' to the redirected user. This is the only admin command\r\nthat is case sensitive.\r\n");
     }
   if((user->type & (OP_ADMIN | OP)) != 0)
     send_to_user("|", user);
}

void send_mass_message(char *buffy, struct user_t *user)
{
   char *buf, *bufp;   
   char *sendbuf;
   char temp_nick[MAX_NICK_LEN+1];
   char temp_host[MAX_HOST_LEN+1];
   int spaces=0, entries=0;
   int i;
   
   if((sendbuf = malloc(sizeof(char) * (50 + MAX_NICK_LEN + strlen(buffy)))) == NULL)
     {
	logprintf(1, "Error - in send_mass_message()/malloc(): ");
	logerror(1, errno);
	quit = 1;
	return;
     }
   
   sem_take(user_list_sem);
   
   /* Attach to the shared segment */
   if((buf = shmat(get_user_list_shm_id(), NULL, 0))
      == (char *)-1)
     {	
	logprintf(1, "Error - In send_mass_message()/shmat(): ");
	logerror(1, errno);
	sem_give(user_list_sem);
	quit = 1;
	return;
     }
   
   if(sscanf(buf, "%d %d", &spaces, &entries) != 2)
     {	
	logprintf(1, "Error - In send_mass_message(): Couldn't get number of entries\n");
	shmdt(buf);
	sem_give(user_list_sem);
	quit = 1;
	return;
     }
   
   bufp = buf + 30;
   
   for(i = 1; i <= spaces; i++)
     {
	if(*bufp != '\0')
	  {	     
	     sscanf(bufp, "%50s %120s", temp_nick, temp_host);
	     sprintf(sendbuf, "$To: %s From: Hub-Mass-Message $<Hub-Mass-Message> %s", temp_nick, buffy);
	     to_from(sendbuf, user);
	  }
	bufp += USER_LIST_ENT_SIZE;
     }
   
   shmdt(buf);
   sem_give(user_list_sem);
   
   free(sendbuf);
   
   /* Send to scripts */
#ifdef HAVE_PERL
   command_to_scripts("$Script mass_message %c%c", '\005', '\005');
   non_format_to_scripts(buffy);
#endif
}

/* Remove all expired temporary bans.  */
void remove_expired(void)
{
   char path[MAX_FDP_LEN+1];
   time_t now_time;

   now_time = time(NULL);

   snprintf(path, MAX_FDP_LEN, "%s/%s", config_dir, BAN_FILE);
   remove_exp_from_file(now_time, path);
   snprintf(path, MAX_FDP_LEN, "%s/%s", config_dir, ALLOW_FILE);
   remove_exp_from_file(now_time, path);
   snprintf(path, MAX_FDP_LEN, "%s/%s", config_dir, NICKBAN_FILE);
   remove_exp_from_file(now_time, path);
}

int show_perms(struct user_t *user, char *buf)
{
   char command[21];
   char nick[MAX_NICK_LEN+1];
   int perms;

   if(sscanf(buf, "%20s %50[^|]|", command, nick) != 2)
     return 2;

   if(nick[0] == '\0')
     return 2;

   if(check_if_registered(nick) != 2)
     return 3;

   perms = get_permissions(nick);

   if((user->type & (OP | OP_ADMIN)) != 0)
     uprintf(user, "<Hub-Security> Permissions for %s:", nick);
   else
     uprintf(user, "\r\nPermissions for %s:", nick);

   if(perms == 0)
     uprintf(user, "  None");
   else
     {
	if((perms & BAN_ALLOW) != 0)
	  uprintf(user, "\r\nBAN_ALLOW");
	if((perms & USER_INFO) != 0)
	  uprintf(user, "\r\nUSER_INFO");
	if((perms & MASSMESSAGE) != 0)
	  uprintf(user, "\r\nMASSMESSAGE");
	if((perms & USER_ADMIN) != 0)
	  uprintf(user, "\r\nUSER_ADMIN");
     }
   if((user->type & (OP | OP_ADMIN)) != 0)
     uprintf(user, "|");
   else
     uprintf(user, "\r\n");

   return 1;
}
