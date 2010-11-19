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
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#if HAVE_MALLOC_H
# include <malloc.h>
#endif
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#if HAVE_UNISTD_H
# include <unistd.h>
#endif
#if HAVE_FCNTL_H
# include <fcntl.h>
#endif
#include <signal.h>
#include <sys/un.h>
#include <errno.h>
#ifdef HAVE_CRYPT_H
# include <crypt.h>
#endif
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
#ifdef HAVE_SYSLOG_H
# include <syslog.h>
#endif
#ifdef SWITCH_USER
# include <sys/capability.h>
# include <sys/prctl.h>
# include <pwd.h>
# include <grp.h>
#endif
#include <sys/shm.h>
#include <sys/sem.h>
#include <sys/ipc.h>

#include "main.h"
#include "network.h"
#include "commands.h"
#include "utils.h"
#include "fileio.h"
#include "userlist.h"
#ifdef HAVE_PERL
# include "perl_utils.h"
#endif

#ifndef SIGCHLD
# define SIGCHLD SIGCLD
#endif
   
/* Set default variables, used if config does not exist or is bad */
int set_default_vars(void)
{
   users_per_fork = 1000;
   min_share = 0;
   max_users = 1000;
   hublist_upload = 1;
   registered_only = 0;
   ban_overrides_allow = 0;
   check_key = 0;
   reverse_dns = 0;
   redirect_host[0] = '\0';
   admin_port = 0xD1C0;  /* Easy to remember :) */
   admin_localhost = 0;
   searchcheck_exclude_internal = 1;
   searchcheck_exclude_all = 0;
   kick_bantime = 5;
   searchspam_time = 5;
   max_email_len = 50;
   max_desc_len = 100;
   crypt_enable = 1;
   printf("Enter port number to listen for connections. \nPorts below 1024 is only for root: ");
   scanf("%u", &listening_port);
   if(listening_port == 0)
     {
	printf("Bad port number\n");
	exit(EXIT_FAILURE);
     }
   printf("Listening Port set to %u\n\n", listening_port);
   sprintf(public_hub_host, "vandel405.dynip.com");
   min_version[0] = '\0';
   sprintf(hub_name, "Open DC Hub");
   sprintf(hub_description, "A Unix/Linux Direct Connect Hub");
   if((hub_full_mess = realloc(hub_full_mess, sizeof(char) * 50)) == NULL)
     {
	logprintf(1, "Error - In set_default_vars()/realloc(): ");
	logerror(1, errno);
	quit = 1;
	return 0;
     }
   sprintf(hub_full_mess, "Sorry, this hub is full at the moment");
   sprintf(default_pass, "");
   printf("Please, supply an admin pass for hub: ");
   scanf("%50s", admin_pass);
   printf("Your admin pass is set to %s\n\n", admin_pass);
   printf("Please, supply a password for hub linking: ");
   scanf("%50s", link_pass);
   printf("Your Hub linking pass is set to %s\n\n", link_pass);
   return 1;
}

/* When all users have left a forked process, that process should be terminated */
void kill_forked_process(void)
{
   int erret;
   
   set_listening_pid(0);
   
   remove_all(0xFFFF, 1, 1);
   
   if(listening_socket != -1) 
     {	
	while(((erret =  close(listening_socket)) != 0) && (errno == EINTR))
	  logprintf(1, "Error - In kill_forked_process()/close(): Interrupted system call. Trying again.\n");	
	
	if(erret != 0)
	  {	
	     logprintf(1, "Error - In kill_forked_process()/close(): ");
	     logerror(1, errno);
	  }
     }
   
   if(admin_listening_socket != -1)
     {	
	while(((erret =  close(admin_listening_socket)) != 0) && (errno == EINTR))
	  logprintf(1, "Error - In kill_forked_process()/close(): Interrupted system call. Trying again.\n");	
	
	if(erret != 0)
	  {	
	     logprintf(1, "Error - In kill_forked_process()/close(): ");
	     logerror(1, errno);
	  }  
     }
   
   exit(EXIT_SUCCESS);
}


/* Accept connection from newly created forked process */
void new_forked_process(void)
{
   struct user_t *user;
   struct sockaddr_un remote_addr;
   int len, flags;
   
   memset(&remote_addr, 0, sizeof(struct sockaddr_un));
   /* Allocate space for the new user */
   if((user = malloc(sizeof(struct user_t))) == NULL)
     {	
	logprintf(1, "Error - In new_forked_process()/malloc(): ");
	logerror(1, errno);
	quit = 1;
	return;
     }      
   
   /* Get a new socket for the connected user */
   len = sizeof(struct sockaddr_un);
   while(((user->sock = accept(listening_unx_socket,
			       (struct sockaddr *)&remote_addr, &len)) < 0)
	 && (errno == EINTR))
     logprintf(1, "Error - In new_forked_process()/accept(): Interrupted system call. Trying again.\n");	
   
   if(user->sock < 0)
     {	
	logprintf(1, "Error - In new_forked_process()/accept(): ");
	logerror(1, errno);
	free(user);
	return;
     }
   
   if((flags = fcntl(user->sock, F_GETFL, 0)) < 0)
     {  
	logprintf(1, "Error - In new_forked_process()/in fcntl(): ");
	logerror(1, errno);
	close(user->sock);
	free(user);
	return;
     } 
   
   /* Non blocking mode */
   if(fcntl(user->sock, F_SETFL, flags | O_NONBLOCK) < 0)
     {
	logprintf(1, "Error - In new_forked_process()/in fcntl(): ");
	logerror(1, errno);
	close(user->sock);
	free(user);
	return;
     }
   
   
   user->type = FORKED;
   user->rem = 0;
   user->buf = NULL;
   user->outbuf = NULL;
   sprintf(user->hostname, "forked_process");   
   memset(user->nick, 0, MAX_NICK_LEN+1);
   
   /* Add the user at the first place in the list.  */
   add_non_human_to_list(user);
   
   logprintf(5, "Got new unix connection on sock %d\n", user->sock);
}
   

/* Create a new process */
void fork_process(void)
{
   int sock;
   int len;
   int erret;
   struct sockaddr_un remote_addr;
   struct user_t *user;
   int flags;

   memset(&remote_addr, 0, sizeof(struct sockaddr_un));
   if((pid = fork()) == -1)
     {
	logprintf(1, "Fork failed, exiting process\n");
	logerror(1, errno);
	quit = 1;
	return;
     }
   
   /* If we are the parent */
   if(pid > 0)
     {
	/* All users are removed from the parent */
	remove_all(UNKEYED | NON_LOGGED | REGULAR | REGISTERED | OP 
		   | OP_ADMIN, 1, 1);
	logprintf(5, "Forked new process, childs pid is %d and parents pid is %d\n", pid, getpid());
	/* And set current pid of process */
	pid = getpid();
     }
   
   /* And if we are the child */
   else
     {
	/* Close the listening sockets */
	while(((erret =  close(listening_unx_socket)) != 0) && (errno == EINTR))
	  logprintf(1, "Error - In fork_process()/close(): Interrupted system call. Trying again.\n");	
	
	if(erret != 0)
	  {	
	     logprintf(1, "Error - In fork_process()/close(): ");
	     logerror(1, errno);
	  }
	
	while(((erret =  close(listening_udp_socket)) != 0) && (errno == EINTR))
	  logprintf(1, "Error - In fork_process()/close(): Interrupted system call. Trying again.\n");	
	
	if(erret != 0)
	  {	
	     logprintf(1, "Error - In fork_process()/close(): ");
	     logerror(1, errno);
	  }
	
	/* Set the alarm */
	alarm(ALARM_TIME);
	
	/* And remove all connections to forked process. We only want 
	 * connections between parent and child, not between children. Also
	 * remove connections to other hubs, we let the parent take care of
	 * those.*/
	remove_all(SCRIPT | LINKED | FORKED, 0, 0);
	
	/* If some other process already has opened the socket, we'll exit.  */
	if(set_listening_pid((int)getpid()) <= 0)
	  exit(EXIT_SUCCESS);
	
	/* Open the human listening sockets.  */
	if((listening_socket = get_listening_socket(listening_port, 0)) == -1)
	  {
	     logprintf(1, "Error - In fork_process(): Couldn't open listening socket\n");
	     quit = 1;
	  }
	
	if((admin_listening_socket = get_listening_socket(admin_port, admin_localhost)) == -1)
	  {
	     logprintf(1, "Admin listening socket disabled\n");
	  }	
	
	/* And connect to parent process */
	if((sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) 
	  {
	     logprintf(1, "Error - In fork_process()/socket(): ");
	     logerror(1, errno);
	     quit = 1;
	     return;
	  }		
	
	remote_addr.sun_family = AF_UNIX;
	strcpy(remote_addr.sun_path, un_sock_path);
	len = strlen(remote_addr.sun_path) + sizeof(remote_addr.sun_family) + 1;
	if(connect(sock, (struct sockaddr *)&remote_addr, len) == -1)
	  {
	     logprintf(1, "Error - In fork_process()/connect(): ");
	     logerror(1, errno);
	     quit = 1;
	     return;
	  }
	
	if((user = malloc(sizeof(struct user_t))) == NULL)
	  {	     
	     logprintf(1, "Error - In fork_process()/malloc(): ");
	     logerror(1, errno);
	     quit = 1;
	     return;
	  }
	
	user->sock = sock;
	user->type = FORKED;
	user->rem = 0;
	user->buf = NULL;
	user->outbuf = NULL;
	memset(user->nick, 0, MAX_NICK_LEN+1);
	sprintf(user->hostname, "parent_process");

	if((flags = fcntl(user->sock, F_GETFL, 0)) < 0)
	  {     
	     logprintf(1, "Error - In fork_process()/in fcntl(): ");
	     logerror(1, errno);
	     close(user->sock);
	     free(user);
	     return;
	  }
	
	/* Non blocking mode */
	if(fcntl(user->sock, F_SETFL, flags | O_NONBLOCK) < 0)
	  {
	     logprintf(1, "Error - In fork_process()/in fcntl(): ");
	     logerror(1, errno);
	     close(user->sock);
	     free(user);
	     return;
	  }
	
	
	/* Add the user at the first place in the list */
	add_non_human_to_list(user);
     }
}

/* This function is used to move the listening socket to a process that has
 * room for more users. If no process have room, a new is forked.  */
void switch_listening_process(char *buf, struct user_t *user)
{
   int nbr_of_users;
   int forknbr = 0;
   struct user_t *non_human;
   int nbr_of_forked = 0;
   
   if(pid > 0)
     nbr_of_forked = count_users(FORKED);
   
   non_human = non_human_user_list;
   
   /* If a process has closed the listening sockets.  */
   if((pid > 0) && (strncmp(buf, "$ClosedListen", 13) == 0))
     {
	if(nbr_of_forked == 1)
	  {
	     do_fork = 1;
	     return;
	  }	
	current_forked = 1;
	while((non_human != NULL) 
	      && (non_human->type != FORKED)) 
	  non_human = non_human->next;
	send_to_user("$OpenListen|", non_human);
	current_forked++;
     }
   else if(strncmp(buf, "$OpenListen", 11) == 0)
     {
	/* Check if we want to accept new clients in this process.  */
	nbr_of_users = count_users(UNKEYED | NON_LOGGED | REGULAR 
				   | REGISTERED | OP | OP_ADMIN | ADMIN 
				   | NON_LOGGED_ADM);
	
	if((nbr_of_users < users_per_fork) 
	   && (nbr_of_users < (max_sockets-5)))
	  {
	     if(listening_socket == -1)
	       {
		  if(set_listening_pid((int)getpid()) > 0)
		    {
		       /* Open the listening sockets.  */
		       if((listening_socket = get_listening_socket(listening_port, 0)) == -1)
			 logprintf(1, "Error - In switch_listening_process(): Couldn't open listening socket\n");
		       
		       admin_listening_socket = get_listening_socket(admin_port, admin_localhost);
		    }	
	       }
	  }
	else
	  send_to_user("$RejListen|", user);
     }
   
   /* If a process that couldn't take the listening sockets.  */
   else if((pid > 0) && (strncmp(buf, "$RejListen", 10) == 0))
     {
	if(current_forked > nbr_of_forked)
	  do_fork = 1;
	else
	  {	     
	     while(non_human != NULL)
	       {
		  if(non_human->type == FORKED)
		    {		       
		       forknbr++;
		       if(forknbr == current_forked)
			 {		       		   
			    send_to_user("$OpenListen|", non_human);
			    current_forked++;
			    return;
			 }		  
		    }	     
		  non_human = non_human->next;
	       }
	     /* If we get here, which we usually shouldn't, we didn't find a
	      * process to host the listening sockets, so we will have to
	      * fork.  */
	     do_fork = 1;
	  }	
     }
}


/* Create a process for uploading to public hub list */
void do_upload_to_hublist(void)
{
   int nbrusers;
   int erret;
   
   nbrusers = count_all_users();
   
   if((pid = fork()) == -1)
     {
	logprintf(1, "Error - Couldn't fork new process in do_upload_to_hublist()\n");
	logerror(1, errno);
	return;
     }
   if(pid > 0)
     pid = getpid();
   else
     {
	pid = -2;
	remove_all(0xFFFF, 0, 0);
	
	while(((erret =  close(listening_unx_socket)) != 0) && (errno == EINTR))
	  logprintf(1, "Error - In do_upload_to_hublist()/close(): Interrupted system call. Trying again.\n");	
	
	if(erret != 0)
	  {	
	     logprintf(1, "Error - In do_upload_to_hublist()/close(): ");
	     logerror(1, errno);
	  }
	
	while(((erret =  close(listening_udp_socket)) != 0) && (errno == EINTR))
	  logprintf(1, "Error - In do_upload_to_hublist()/close(): Interrupted system call. Trying again.\n");	
	
	if(erret != 0)
	  {	
	     logprintf(1, "Error - In do_upload_to_hublist()/close(): ");
	     logerror(1, errno);
	  }
	
	upload_to_hublist(nbrusers);
     }
   upload = 0;
}

 
/* Removes all users of specified type.  */
void remove_all(int type, int send_quit, int remove_from_list)
{
   struct sock_t *human_user;
   struct user_t *non_human;
   struct sock_t *next_human;
   struct user_t *next_non_human;
   
   human_user = human_sock_list;
   non_human = non_human_user_list;
   
   /* First non-humans.  */
   while(non_human != NULL)
     {
	next_non_human = non_human->next;

	if((non_human->type & type) != 0)
	  remove_user(non_human, send_quit, remove_from_list);
	
	non_human = next_non_human;
     }   
   while(human_user != NULL)
     {
	next_human = human_user->next;

	if((human_user->user->type & type) != 0)
	  remove_user(human_user->user, send_quit, remove_from_list);
	
	human_user = next_human;
     }
}

void term_signal(int z)
{
   quit = 1;
}

/* This will execute every ALARM_TIME seconds, it checks timeouts and uploads 
 * to public hublist */
void alarm_signal(int z)
{
   struct user_t *non_human;
   struct sock_t *human_user;
   
   if((debug != 0) && (pid > 0))
     logprintf(2, "Got alarm signal\n");
   
   /* Send the hub_timer sub to the scripts.  */
#ifdef HAVE_PERL
   if(pid > 0)
     command_to_scripts("$Script hub_timer|");
#endif
   
   /* Check timeouts */
   non_human = non_human_user_list;
   while(non_human != NULL)
     {
	if((non_human->timeout == 0) && (non_human->type == LINKED))
	  {
	     logprintf(2, "Linked hub at %s, port %d is offline\n", non_human->hostname, non_human->key);
	     non_human->rem = REMOVE_USER;	 	     
	  }
	non_human = non_human->next;
     }
   
   human_user = human_sock_list;
   while(human_user != NULL)
     {	
	if((human_user->user->type & 
	    (UNKEYED | NON_LOGGED | NON_LOGGED_ADM)) != 0)
	  {
	     logprintf(2, "Timeout for non logged in user at %s, removing user\n", human_user->user->hostname);
	     human_user->user->rem = REMOVE_USER | SEND_QUIT | REMOVE_FROM_LIST;
	  }
	human_user = human_user->next;
     }
   
   /* And reset all timeout values */
   non_human = non_human_user_list;
   while(non_human != NULL)
     {
	if(non_human->type == LINKED)
	  non_human->timeout = 0;
	non_human = non_human->next;
     }
   
   /* And make clear for upload to public hub list */
   if(pid > 0)
     {
	if(hublist_upload != 0)
	  upload = 1;
	do_write = 1;
	do_send_linked_hubs = 1;
	do_purge_user_list = 1;
     }
   else
     {
	upload = 0;
	do_write = 0;
	do_purge_user_list = 0;
     }

   remove_expired();

   alarm(ALARM_TIME);
}

void init_sig(void)
{  
   struct sigaction sv;  
   
   memset(&sv, 0, sizeof(struct sigaction));
   sv.sa_flags = 0;
   sigemptyset(&sv.sa_mask);
#ifdef SA_NOCLDWAIT
   sv.sa_flags |= SA_NOCLDWAIT;
#endif
#ifdef SA_NOCLDSTOP
   sv.sa_flags |= SA_NOCLDSTOP;
#endif
   
   sv.sa_handler = SIG_IGN;
   /* Don't want broken pipes to kill the hub.  */
   sigaction(SIGPIPE, &sv, NULL);
   
   /* ...or any defunct child processes.  */
   sigaction(SIGCHLD, &sv, NULL);
   
   sv.sa_handler = term_signal;
   
   /* Also, shut down properly.  */
   sigaction(SIGTERM, &sv, NULL);
   sigaction(SIGINT, &sv, NULL);
   
   sv.sa_handler = alarm_signal;
   
   /* And set handler for the alarm call.  */
   sigaction(SIGALRM, &sv, NULL);   
}

/* Send info about one user to another. If all is 1, send to all */
void send_user_info(struct user_t *from_user, char *to_user_nick, int all)
{
   char *send_buf;
   struct user_t *to_user;
   int to_nick_len;
   
   (all != 0) ? (to_nick_len = 5) : (to_nick_len = strlen(to_user_nick)+1);
   
   if((send_buf = malloc(sizeof(char) * (9 + to_nick_len 
		 + strlen(from_user->nick) + 1
	         + ((from_user->desc == NULL) ? 0 : strlen(from_user->desc)) + 4 + 10 
	         + ((from_user->email == NULL) ? 0 : strlen(from_user->email)) + 20 + 1))) == NULL)
     {
	logprintf(1, "Error - In send_user_info()/malloc(): ");
	logerror(1, errno);
	quit = 1;
	return;
     }
   
   if(all != 0)
     sprintf(send_buf, "$MyINFO $ALL ");
   else
     sprintf(send_buf, "$MyINFO $%s ", to_user_nick);
   
   sprintfa(send_buf, "%s", from_user->nick);
   sprintfa(send_buf, " ");
   if(from_user->desc != NULL)
     sprintfa(send_buf, "%s", from_user->desc);
   sprintfa(send_buf, "$ $");
   switch(from_user->con_type)
     {
      case 1:
	sprintfa(send_buf, "28.8Kbps");
	break;
      case 2:
	sprintfa(send_buf, "33.6Kbps");
	break;
      case 3:
	sprintfa(send_buf, "56Kbps");
	break;
      case 4:
	sprintfa(send_buf, "Satellite");
	break;
      case 5:
	sprintfa(send_buf, "ISDN");
	break;
      case 6:
	sprintfa(send_buf, "DSL");
	break;
      case 7:
	sprintfa(send_buf, "Cable");
	break;
      case 8:
	sprintfa(send_buf, "LAN(T1)");
	break;
      case 9:
	sprintfa(send_buf, "LAN(T3)");
	break;
// @Ciuly: added some other connection types
      case 10:
	sprintfa(send_buf, "Wireless");
        break;
      case 11:
	sprintfa(send_buf, "Modem");
        break;
      case 12:
	sprintfa(send_buf, "Netlimiter");
        break;
// end @Ciuly
// Start fix for 1027168 by Ciuly	
      default:
        sprintfa(send_buf, "Unknown");
        break;
// End fix for 1027168
     }
   sprintfa(send_buf, "%c", from_user->flag);
   sprintfa(send_buf, "$");
   if(from_user->email != NULL)
      sprintfa(send_buf, "%s", from_user->email);
   sprintfa(send_buf, "$%lld", from_user->share);
   sprintfa(send_buf, "$|");

   /* The $Script user represents all scripts, so send the string to all 
    * running scripts.  */
   if((pid > 0) && (strncmp(to_user_nick, "$Script", 7) == 0))
     send_to_non_humans(send_buf, SCRIPT, NULL);
   else if((to_user = get_human_user(to_user_nick)) != NULL)
     send_to_user(send_buf, to_user);
   else
     send_to_non_humans(send_buf, FORKED, NULL);
   free(send_buf);
}

/* Sends different hub messages to user */
void hub_mess(struct user_t *user, int mess_type)
{
   char *send_string;

   send_string = NULL;
   switch(mess_type)
     {
	/* If a user just connected */
      case INIT_MESS:
	if((send_string = malloc(sizeof(char) * 110)) == NULL)
	  {
	     logprintf(1, "Error - In hub_mess()/malloc(): ");
	     logerror(1, errno);
	     quit = 1;
	     return;
	  }

	sprintf(send_string, "$HubName %s|", hub_name);
	sprintfa(send_string, "<Hub-Security> This hub is running version %s of Open DC Hub.|", VERSION);
	break;
	
	/* If the hub is full, tell user */
      case HUB_FULL_MESS:
	if((send_string = malloc(sizeof(char) 
				 * (15 + strlen(hub_full_mess) + 3))) == NULL)
	  {
	     logprintf(1, "Error - In hub_mess()/malloc(): ");
	     logerror(1, errno);
	     quit = 1;
	     return;
	  }
	sprintf(send_string, "<Hub-Security> %s|", 
		 hub_full_mess);
	break;
	
      case BAN_MESS:
	if((send_string = malloc(sizeof(char) * 50)) == NULL)
	  {
	     logprintf(1, "Error - In hub_mess()/malloc(): ");
	     logerror(1, errno);
	     quit = 1;
	     return;
	  }
	
	sprintf(send_string, "<Hub-Security> Your IP or Hostname is banned|");
	break;
	
      case GET_PASS_MESS:
	if((send_string = malloc(sizeof(char) * 100)) == NULL)
	  {
	     logprintf(1, "Error - In hub_mess()/malloc(): ");
	     logerror(1, errno);
	     quit = 1;
	     return;
	  }
	
	sprintf(send_string, "<Hub-Security> Your nickname is registered, please supply a password.|$GetPass|");
	break;

      case GET_PASS_MESS2:
	if((send_string = malloc(sizeof(char) * 100)) == NULL)
	  {
	     logprintf(1, "Error - In hub_mess()/malloc(): ");
	     logerror(1, errno);
	     quit = 1;
	     return;
	  }

	sprintf(send_string, "<Hub-Security> Password required to enter hub.|$GetPass|");
	break;
	
      case LOGGED_IN_MESS:
	/* Construct the reply string */
	if((send_string = malloc(sizeof(char) * (60 + strlen(user->nick)))) == NULL)
	  {
	     logprintf(1, "Error - In hub_mess()/malloc(): ");
	     logerror(1, errno);
	     quit = 1;
	     return;
	  }
	sprintf(send_string, "<Hub-Security> Logged in.|$Hello %s|", user->nick); 
	break;
	
      case OP_LOGGED_IN_MESS:
	if((send_string = malloc(sizeof(char) * (15 + strlen(user->nick)))) == NULL)
	  {
	     logprintf(1, "Error - In hub_mess()/malloc(): ");
	     logerror(1, errno);
	     quit = 1;
	     return;
	  }
	sprintf(send_string, "$LogedIn %s|", user->nick); 
	break;
	
      case BAD_PASS_MESS:
	/* Construct the reply string */
	if((send_string = malloc(sizeof(char) * 60)) == NULL)
	  {
	     logprintf(1, "Error - In hub_mess()/malloc(): ");
	     logerror(1, errno);
	     quit = 1;
	     return;
	  }
	sprintf(send_string, "$BadPass|<Hub-Security> That password was incorrect.|"); 
	break;
	
      case HELLO_MESS:
	/* Construct the reply string */
	if((send_string = malloc(sizeof(char) * (strlen(user->nick) + 12))) == NULL)
	  {
	     logprintf(1, "Error - In hub_mess()/malloc(): ");
	     logerror(1, errno);
	     quit = 1;
	     return;
	  }
	sprintf(send_string, "$Hello %s|", user->nick); 
	break;
	
      case INIT_ADMIN_MESS:
	/* Construct the reply string */
	if((send_string = malloc(sizeof(char) * 200)) == NULL)
	  {
	     logprintf(1, "Error - In hub_mess()/malloc(): ");
	     logerror(1, errno);
	     quit = 1;
	     return;
	  }
	sprintf(send_string, "\r\nOpen DC Hub, version %s, administrators port.\r\nAll commands begin with \'$\' and end with \'|\'.\r\nPlease supply administrators passord.\r\n", VERSION);
	break;	
     }
	
   /* Send the constructed string */
   if(send_string != NULL)
     send_to_user(send_string, user);
   free(send_string);
}

/* This function handles every command in the received packet one by one */
/* Returns 0 if user should be removed */
int handle_command(char *buf, struct user_t *user)
{
   int ret;
   char *temp;
   char tempstr[MAX_HOST_LEN+1]; 
  
   temp = NULL;
   while(buf != NULL)
     {
	/* Check if it's a '$' or a '<' first in the command string */
	if((strchr(buf, '$') != NULL) && (strchr(buf, '<') == NULL))
	  temp = strchr(buf, '$');
	else if((strchr(buf, '$') == NULL) && (strchr(buf, '<') != NULL))
	  temp = strchr(buf, '<');
	else if((strchr(buf, '$') == NULL) && (strchr(buf, '<') == NULL))
	  {
	     /* This is what happends every time a command doesn't fit in one
	      * single package. */
	     return 1;
	  }
	
	else
	  (strchr(buf, '$') < strchr(buf, '<'))
	  ? (temp = strchr(buf, '$'))  /* The '$' is first */
	    : (temp = strchr(buf, '<')); /* The '<' is first */
	
	buf = temp;
	temp = NULL;
	/* First check if it's a whole command */
	if(strchr(buf, '|') != NULL)
	  {
	     /* Copy command to temporary buf so we don't get more sent to the
	      * function than neccessary */
	     if((temp = malloc(sizeof(char) * (cut_string(buf, '|') + 3))) == NULL)
	       {
		  logprintf(1, "Error - In handle_command()/malloc(): ");
		  logerror(1, errno);
		  quit = 1;
		  return -1;
	       }
             strncpy(temp, buf, cut_string(buf, '|') + 1);
	     if(cut_string(buf, '|') > 0)
	       temp[cut_string(buf, '|')+1] = '\0';
	     
	     /* The Key command */
	     if(strncmp(temp, "$Key ", 5) == 0)
	       {
		  if(user->type == UNKEYED)
		    {
		       if(validate_key(buf, user) == 0)
			 {
			    logprintf(1, "User at %s provided bad $Key, removing user\n", user->hostname);
			    free(temp);
			    return 0;
			 }
		    }
	       }
	     
	     /* The ValidateNick command */
	     else if(strncmp(temp, "$ValidateNick ", 14) == 0)
	       {
		  /* Only for non logged in users. If client wants to change
		   * nick, it first has to disconnect.  */
		  /* Also allowed for scripts to register their nick in the
		   * nicklist.  */
		  if((user->type == NON_LOGGED) 
		     || ((user->type == SCRIPT) && (pid > 0)))
		    {
		       if(validate_nick(temp, user) == 0)
			 {
			    free(temp);
			    return 0;
			 }
		    }
	       }
	     
	     /* The Version command */
	     else if(strncmp(temp, "$Version ", 9) == 0)
	       {
		  if(user->type != ADMIN)
		    {
		       if(version(temp, user) == 0)
			 {
			    free(temp);
			    return 0;
			 }
		    }		  
	       }
	     
	     /* The GetNickList command */
	     else if(strncasecmp(temp, "$GetNickList", 12) == 0)
	       {
		  send_nick_list(user);
	       }
	     
	     /* The MyINFO command */
	     else if(strncmp(temp, "$MyINFO $", 9) == 0)
	       {
		  if(user->type != ADMIN)
		    {
		       if(my_info(temp, user) == 0)
		       {
			    free(temp);
			    return 0;
			 }
		    }
	       }
	     
	     /* The GetINFO command */
	     else if(strncasecmp(temp, "$GetINFO ", 9) == 0)
	       {
		  /* Only for logged in users */
		  if((user->type & (UNKEYED | NON_LOGGED | LINKED)) == 0)
		    get_info(temp, user);
	       }
	     
	     /* The To: From: command */
	     else if(strncmp(temp, "$To: ", 5) == 0)
	       {
		  /* Only for logged in users */
		  if((user->type & (UNKEYED | NON_LOGGED | SCRIPT | LINKED)) == 0)
		    to_from(temp, user);
	       }
	     
	     /* The ConnectToMe command */
	     else if(strncmp(temp, "$ConnectToMe ", 13) == 0)
	       {
		  if((user->type & (REGULAR | REGISTERED | OP | OP_ADMIN 
				   | FORKED)) != 0)
		    connect_to_me(temp, user);
	       }
	     
	     /* The RevConnectToMe command */
	     else if(strncmp(temp, "$RevConnectToMe ", 16) == 0)
	       {
		  if((user->type & (REGULAR | REGISTERED | OP | OP_ADMIN 
				   | FORKED)) != 0)
		    rev_connect_to_me(temp, user);
	       }
	     
	     /* The Search command */
	     else if(strncmp(temp, "$Search ", 8) == 0)
	       {
		  if((user->type & (REGULAR | REGISTERED | OP | OP_ADMIN 
				   | FORKED | SCRIPT)) != 0)
		    search(temp, user);
	       }
	     
	     /* The SR command */
	     else if(strncmp(temp, "$SR ", 4) == 0)
	       {
		  if((user->type & (REGULAR | REGISTERED | OP | OP_ADMIN 
				   | FORKED)) != 0)
		    sr(temp, user);
	       }
	     
	     /* The MyPass command */
	     else if(strncmp(temp, "$MyPass ", 8) == 0)
	       {
		  if(user->type == NON_LOGGED)
		    {
		       if(my_pass(temp + 8, user) == 0)
			 {
			    free(temp);
			    return 0;
			 }
		    }
	       }
	     
	     /* The kick command */
	     else if(strncasecmp(temp, "$Kick ", 6) == 0)
	       {
		  if((user->type & (OP | OP_ADMIN | ADMIN | FORKED | SCRIPT)) != 0)
		    {
		       kick(temp, user, 1);
		    }
		  else
		    logprintf(2, "%s tried to kick without having priviledges\n", user->nick);
	       }
	     
	     /* The OpForceMove command */
	     else if(strncmp(temp, "$OpForceMove ", 13) == 0)
	       {
		  if((user->type & (OP | OP_ADMIN | ADMIN | FORKED)) != 0)
		    {
		       op_force_move(temp, user);
		    }
		  else
		    logprintf(2, "%s tried to redirect without having priviledges\n", user->nick);
	       }
	     
	     /* The chat command, starts with <nick> */
	     else if(*temp == '<')
	       {
		  if((user->type & (SCRIPT | UNKEYED | LINKED | NON_LOGGED)) == 0)
		    chat(temp, user);
	       }
	     
	     /* Commands that should be forwarded from forked processes */
	     else if((strncmp(temp, "$Hello ", 7) == 0)
		     || (strncmp(temp, "$Quit ", 6) == 0)
		     || (strncmp(temp, "$OpList ", 8) == 0))
	       {
		  if(user->type == FORKED)
		    {
		       if(strncmp(temp, "$OpList ", 8) == 0)
			 /* The oplist ends with two '|' */
			 strcat(temp, "|");
		       send_to_non_humans(temp, FORKED, user);
		       send_to_humans(temp, REGULAR | REGISTERED | OP 
				      | OP_ADMIN, user);       
		    }
	       }
	     
	     /* Internal commands for mangement through telnet port and 
	      * communication between processes */
	     else if((strncmp(temp, "$ClosedListen", 13) == 0)
		     && (user->type == FORKED) && (pid > 0))
	       {
		  switch_listening_process(temp, user);
	       }	     
	     
	     else if((strncmp(temp, "$OpenListen", 11) == 0)
		     && (user->type == FORKED) && (pid == 0))
	       {
		  switch_listening_process(temp, user);		 
	       }
	     
	     else if((strncmp(temp, "$RejListen", 10) == 0)
		     && (user->type == FORKED) && (pid > 0))
	       {
		  switch_listening_process(temp, user);
	       }
	     
	     else if((strncmp(temp, "$DiscUser", 9) == 0)
		     && (user->type == FORKED))
	       {
		  disc_user(temp, user);
	       }	     	     	    	     
	     	     	     
	     else if((strncasecmp(temp, "$ForceMove ", 11) == 0)
		     && (user->type == FORKED))
	       {		  
		  redirect_all(temp + 11, user);
	       }	     
	     
	     else if((strncasecmp(temp, "$QuitProgram", 12) == 0) 
		     && ((user->type == FORKED) || (user->type == ADMIN) 
			 || (user->type == SCRIPT)))
	       {
		  if(user->type == ADMIN)
		    uprintf(user, "\r\nShutting down hub...\r\n");
		  quit = 1;
	       }
	     
	     else if(strncasecmp(temp, "$Exit", 5) == 0)
	       {
		  if(user->type == ADMIN)
		    {
		       logprintf(1, "Got exit from admin at %s, hanging up\n", user->hostname);
		       free(temp);
		       return 0;
		    }
	       }
	     
	     else if((strncasecmp(temp, "$RedirectAll ", 13) == 0) && (user->type == ADMIN))
	       {
		  uprintf(user, "\r\nRedirecting all users...\r\n");
		  logprintf(1, "Admin at %s redirected all users\n", user->hostname);
		  redirect_all(temp+13, user);
	       }
	     
	     else if((strncasecmp(temp, "$AdminPass", 10) == 0) && (user->type == NON_LOGGED_ADM))
	       {
		  if(check_admin_pass(temp, user) == 0)
		    {
		       logprintf(2, "User from %s provided bad Admin Pass\n", user->hostname);
		       free(temp);
		       return 0;
		    }
	       }
	     
	     else if(strncasecmp(temp, "$Set ", 5) == 0)
	       {
		  if((user->type & (FORKED | SCRIPT | ADMIN)) != 0)
		    set_var(temp, user); 
	       }
	     
	     else if(strncasecmp(temp, "$Ban ", 5) == 0)
	       {
		  if((user->type & (ADMIN | SCRIPT)) != 0)
		    {
		       ret = ballow(temp+5, BAN, user);
		       if(user->type == ADMIN)
			 {			    
			    if(ret == -1)
			      {
				 send_to_user("\r\nCouldn't add entry to ban list\r\n", user);
				 logprintf(4, "Error - Failed adding entry to ban list\n");
			      }
			    else if(ret == 0)
			      {
				 send_to_user("\r\nEntry is already on the list\r\n", user);
			      }
			    else
			      {
				 send_to_user("\r\nAdded entry to ban list\r\n", user);
				 sscanf(temp+5, "%120[^|]", tempstr);
				 logprintf(3, "Admin at %s added %s to banlist\n", user->hostname, tempstr);
			      }
			 }		       
		    }	 
	       }
	     else if(strncasecmp(temp, "$Allow ", 7) == 0)
	       {
		  if((user->type & (ADMIN | SCRIPT)) != 0)
		    {
		       ret = ballow(temp+7, ALLOW, user);
		       if(user->type == ADMIN)
			 {			    
			    if(ret == -1)
			      {
				 send_to_user("\r\nCouldn't add entry to allow list\r\n", user);
				 logprintf(4, "Error - Failed adding entry to allow list\n");
			      }
			    else if(ret == 0)
			      {
				 send_to_user("\r\nEntry is already on the list\r\n", user);
			      }
			    else
			      {
				 send_to_user("\r\nAdded entry to allow list\r\n", user);
				 sscanf(temp+7, "%120[^|]", tempstr);
				 logprintf(3, "Admin at %s added %s to allow list\n", user->hostname, tempstr);
			      }
			 }		       
		    }	 
	       }
	     else if(strncasecmp(temp, "$Unban ", 7) == 0)
	       {
		  if((user->type & (ADMIN | SCRIPT)) != 0)
		    {
		       ret = unballow(temp+7, BAN);
		       if(user->type == ADMIN)
			 {			    
			    if(ret == -1)
			      {
				 send_to_user("\r\nCouldn't remove entry from ban list\r\n", user);
				 logprintf(1, "Error - Failed removing entry from ban list\n");
			      }
			    else if(ret == 0)
			      {
				 send_to_user("\r\nEntry wasn't found in list\r\n", user);
			      }
			    else
			      {
				 send_to_user("\r\nRemoved entry from ban list\r\n", user);
				 sscanf(temp+7, "%120[^|]", tempstr);
				 logprintf(3, "Admin at %s removed %s from ban list\n", user->hostname, tempstr);
			      }
			 }	 
		    }		  
	       }
	     else if(strncasecmp(temp, "$Unallow ", 9) == 0)
	       {
		  if((user->type & (ADMIN | SCRIPT)) != 0)
		    {
		       ret = unballow(temp+9, ALLOW);
		       if(user->type == ADMIN)
			 {			    
			    if(ret == -1)
			      {
				 send_to_user("\r\nCouldn't remove entry from allow list\r\n", user);
				 logprintf(1, "Error - Failed removing entry from allow list\n");
			      }
			    else if(ret == 0)
			      {
				 send_to_user("\r\nEntry wasn't found in list\r\n", user);
			      }
			    else
			      {
				 send_to_user("\r\nRemoved entry from allow list\r\n", user);
				 sscanf(temp+9, "%120[^|]", tempstr);
				 logprintf(3, "Admin at %s removed %s from allow list\n", user->hostname, tempstr);
			      }
			 }	 
		    }		  
	       }
	     else if(strncasecmp(temp, "$GetBanList", 11) == 0)
	       {
		  if(user->type == ADMIN)
		    {
		       uprintf(user, "\r\n");
		       send_user_list(BAN, user);
		       uprintf(user, "\r\n");
		    }
	       }
	     else if(strncasecmp(temp, "$GetAllowList", 13) == 0)
	       {
		  if(user->type == ADMIN)
		    {
		       uprintf(user, "\r\n");
		       send_user_list(ALLOW, user);
		       uprintf(user, "\r\n");
		    }
	       }
	     else if(strncasecmp(temp, "$GetRegList", 11) == 0)
	       {
		  if(user->type == ADMIN)
		    {
		       uprintf(user, "\r\n");
		       send_user_list(REG, user);
		       uprintf(user, "\r\n");
		    }
	       }
	     else if(strncasecmp(temp, "$GetConfig", 10) == 0)
	       {
		  if(user->type == ADMIN)
		    {
		       uprintf(user, "\r\n");
		       send_user_list(CONFIG, user);
		       uprintf(user, "\r\n");
		    }
	       }
	     else if(strncasecmp(temp, "$GetMotd", 8) == 0)
	       {
		  if(user->type == ADMIN)
		    {
		       uprintf(user, "\r\n");
		       send_motd(user);
		       send_to_user("\r\n", user);
		    }
	       }
	     else if(strncasecmp(temp, "$GetLinkList", 12) == 0)
	       {
		  if(user->type == ADMIN)
		    {
		       uprintf(user, "\r\n");
		       send_user_list(LINK, user);
		       uprintf(user, "\r\n");
		    }
	       }
	     else if(strncasecmp(temp, "$AddRegUser ", 12) == 0)
	       {
		  if((user->type & (ADMIN | SCRIPT)) != 0)
		    {
		       ret = add_reg_user(temp, user);
		       if(user->type == ADMIN)
			 {			    
			    if(ret == -1)
			      send_to_user("\r\nCouldn't add user to reg list\r\n", user);
			    else if(ret == 2)
			      send_to_user("\r\nBad format for $AddRegUser. Correct format is:\r\n$AddRegUser <nickname> <password> <opstatus>|\r\n", user);
			    else if(ret == 3)
			      send_to_user("\r\nThat nickname is already registered\r\n", user);
			    else
			      {			    
				 send_to_user("\r\nAdded user to reglist\r\n", user);
				 logprintf(3, "Admin at %s added entry to reglist\n", user->hostname);
			      }		       
			 }
		    }
	       }	     
	     else if(strncasecmp(temp, "$RemoveRegUser ", 15) == 0)
	       {
		  if((user->type & (ADMIN | SCRIPT)) != 0)
		    {
		       ret = remove_reg_user(temp+15, user);
		       if(user->type == ADMIN)
			 {			     
			    if(ret == 0)
			      send_to_user("\r\nUser wasn't found in reg list\r\n", user);
			    else if(ret == -1)
			      send_to_user("\r\nCouldn't remove user from reg list\r\n", user);
			    else
			      {			    
				 send_to_user("\r\nRemoved user from reglist\r\n", user);
				 logprintf(3, "Admin at %s removed entry from reglist\n", user->hostname);
			      }		       			    
			 }
		    }
	       }		  
	     else if(strncasecmp(temp, "$AddLinkedHub ", 14) == 0)
	       {
		  if((user->type & (ADMIN | SCRIPT)) != 0)
		    {
		       ret = add_linked_hub(temp);
		       if(user->type == ADMIN)
			 {			    
			    if(ret == -1)
			      send_to_user("\r\nCouldn't add hub to link list\r\n", user);
			    else if(ret == 2)
			      send_to_user("\r\nBad format for $AddLinkedHub. Correct format is:\r\n$AddLinkedHub <ip> <port>|\r\n", user);
			    else if(ret == 3)
			      send_to_user("\r\nThat hub is already in the linklist\r\n", user);
			    else
			      {			    
				 send_to_user("\r\nAdded hub to linklist\r\n", user);
				 logprintf(3, "Admin at %s added entry to linklist\n", user->hostname);
			      }
			 }		       		       
		    }
	       }
	     else if(strncasecmp(temp, "$RemoveLinkedHub ", 17) == 0)
	       {
		  if((user->type & (ADMIN | SCRIPT)) != 0)
		    {
		       ret = remove_linked_hub(temp+17);
		       if(user->type == ADMIN)
			 {			    
			    if(ret == 0)
			      send_to_user("\r\nHub wasn't found in link list\r\n", user);
			    else if(ret == -1)
			      send_to_user("\r\nCouldn't remove hub from link list\r\n", user);
			    else if(ret == 2)
			      send_to_user("\r\nBad format for $RemoveLinkedHub. Correct format is:\r\n$RemoveLinkedHub <ip> <port>|\r\n", user);
			    else
			      {			    
				 send_to_user("\r\nRemoved hub from linklist\r\n", user);
				 logprintf(3, "Admin at %s removed entry from linklist\n", user->hostname);
			      }		       
			 }
		    }		  
	       }
	     else if(strncmp(temp, "$MultiSearch ", 13) == 0)
	       {
		  if((user->type & (FORKED | REGULAR | REGISTERED | OP | OP_ADMIN)) != 0)
		    multi_search(temp, user);
	       }
	     else if(strncmp(temp, "$MultiConnectToMe ", 18) == 0)
	       {
		  if((user->type & (FORKED | REGULAR | REGISTERED | OP | OP_ADMIN)) != 0)
		    multi_connect_to_me(temp, user);
	       }
	     else if(strncasecmp(temp, "$GetHost ", 9) == 0)
	       {
		  if(user->type == ADMIN)
		    get_host(temp, user, HOST);
	       }	     
	     else if(strncasecmp(temp, "$GetIP ", 7) == 0)
	       {
		  if(user->type == ADMIN)
		    get_host(temp, user, IP);
	       }	     
	     else if(strncasecmp(temp, "$Commands", 9) == 0)
	       {
		  if(user->type == ADMIN)
		    send_commands(user);
	       }
	     else if(strncasecmp(temp, "$MassMessage ", 13) == 0)
	       {
		  if(user->type == ADMIN)
		    {
		       uprintf(user, "\r\nSent Mass Message\r\n");
		       send_mass_message(temp + 13, user);
		    }		  
	       }
	     else if(strncasecmp(temp, "$AddPerm ", 9) == 0)
	       {
		  if((user->type & (ADMIN | FORKED | SCRIPT)) != 0)
		    {
		       ret = add_perm(temp, user);
		       if(user->type == ADMIN)
			 {
			    if(ret == -1)
			      uprintf(user, "\r\nCouldn't add permission to user\r\n");
			    else if(ret == 2)
			      uprintf(user, "\r\nBad format for $AaddPerm. Correct format is:\r\n$AddPerm <nick> <permission>|\r\nand permission is one of: BAN_ALLOW, USER_INFO, MASSMESSAGE, USER_ADMIN\r\n");
			    else if(ret == 3)
			      uprintf(user, "\r\nUser already has that permission.\r\n");
			    else if(ret == 4)
			      uprintf(user, "\r\nUser is not an operator.\r\n");
			    else
			      {
				 uprintf(user, "\r\nAdded permission to user.\r\n");
				 logprintf(3, "Administrator at %s added permission to user\n", user->hostname);
			      }		       
			 }		  
		    }		  
	       }
	     else if(strncasecmp(temp, "$RemovePerm ", 12) == 0)
	       {
		  if((user->type & (ADMIN | FORKED | SCRIPT)) != 0)
		    {
		       ret = remove_perm(temp, user);
		       if(user->type == ADMIN)
			 {
			    if(ret == -1)
			      uprintf(user, "\r\nCouldn't remove permission from user.\r\n");
			    else if(ret == 2)
			      uprintf(user, "\r\nBad format for $RemovePerm. Correct format is:\r\n$RemovePerm <nick> <permission>|\r\nand permission is one of: BAN_ALLOW, USER_INFO, MASSMESSAGE, USER_ADMIN\r\n");
			    else if(ret == 3)
			      uprintf(user, "\r\nUser does not have that permission.\r\n");
			    else if(ret == 4)
			      uprintf(user, "\r\nUser is not an operator.\r\n");
			    else
			      {
				 uprintf(user, "\r\nRemoved permission from user.\r\n");
				 logprintf(3, "Administrator at %s removed permission from user\n", user->hostname);
			      }		       
			 }		  
		    }		  
	       }
	     else if(strncasecmp(temp, "$ShowPerms ", 11) == 0)
	       {
		  if(user->type == ADMIN)
		    {
		       if((ret = show_perms(user, temp)) == 2)
			 uprintf(user, "\r\nBad format for $ShowPerms. Correct format is:\r\n$ShowPerms <nick>|");
		       else if(ret == 3)
			 uprintf(user, "\r\nUser is not an operator.\r\n");		       
		    }		  
	       }
	     else if(strncasecmp(temp, "$ShowPerms ", 11) == 0)
	       {
		  if(user->type == ADMIN)
		    {
		       if((ret = show_perms(user, temp)) == 2)
			 uprintf(user, "\r\nBad format for $ShowPerms. Correct format is:\r\n$ShowPerms <nick>|");
		       else if(ret == 3)
			 uprintf(user, "\r\nUser is not an operator.\r\n");		       
		    }		  
	       }
	     else if(strncasecmp(temp, "$NickBan ", 9) == 0)
	       {
		  if((user->type & (ADMIN | SCRIPT)) != 0)
		    {
		       ret = ballow(temp+9, NICKBAN, user);
		       if(user->type == ADMIN)
			 {		       
			    if(ret == -1)
			      {			      
				 uprintf(user, "\r\nCouldn't add entry to nickban list\r\n");
				 logprintf(4, "Error - Failed adding entry to nickban list\n");
			      }		  
			    else if(ret == 2)
			      uprintf(user, "\r\nEntry is already on the list\r\n");
			    else
			      {			      
				 uprintf(user, "\r\nAdded entry to nickban list\r\n");
				 sscanf(temp+9, "%120[^|]", tempstr);
				 logprintf(3, "Administrator at %s added %s to nickban list\n", user->hostname, tempstr);
			      }		  
			 }	
		    }		     
	       }
	     else if(strncasecmp(temp, "$GetNickBanList", 15) == 0)
	       {
		  if(user->type == ADMIN)
		    {		       
		       uprintf(user, "\r\nNickban list:\r\n");
		       send_user_list(NICKBAN, user);
		       uprintf(user, "\r\n");
		    }
	       }
	     else if(strncasecmp(temp, "$UnNickBan ", 11) == 0)
	       {
		  if((user->type & (ADMIN | SCRIPT)) != 0)
		    {
		       ret = unballow(temp+11, NICKBAN);
		       if(user->type == ADMIN)
			 {		       
			    if(ret == -1)
			      {			      
				 uprintf(user, "\r\nCouldn't remove entry from nickban list\r\n");
				 logprintf(4, "Error - Failed adding entry to nickban list\n");
			      }		  
			    else if(ret == 2)
			      uprintf(user, "\r\nEntry wasn't found in list\r\n");
			    else
			      {			      
				 uprintf(user, "\r\nRemoved entry from nickban list\r\n");
				 sscanf(temp+9, "%120[^|]", tempstr);
				 logprintf(3, "Administrator at %s removed %s from nickban list\n", user->hostname, tempstr);
			      }		  
			 }		      	
		    }
	       }	     	     
	     /* Commands from script processes */
#ifdef HAVE_PERL		  
	     else if(strncasecmp(temp, "$NewScript", 10) == 0)
	       {
		  if(user->type == FORKED)
		    {		       
		       user->type = SCRIPT;
		       sprintf(user->hostname, "script_process");
		       sprintf(user->nick, "script process");
		    }		  
	       }
	     else if(strncmp(temp, "$Script ", 8) == 0)
	       {		  
		  if(pid > 0)
		    {
		       if(user->type == FORKED)
			 non_format_to_scripts(temp);
		    }
		  else
		    {		       
		       if(user->type == SCRIPT)
			 sub_to_script(temp + 8);		     
		    }
	       }
	     else if(strncasecmp(temp, "$ReloadScripts", 14) == 0)
	       {
		  if((user->type & (ADMIN | FORKED)) != 0)
		    {	
		       if(user->type == ADMIN)
			 uprintf(user, "\r\nReloading scripts...\r\n");
		       if(pid > 0)
			 script_reload = 1;
		       
		       else
			 send_to_non_humans(temp, FORKED, user);
		    }
	       }
	     else if(strncasecmp(temp, "$ScriptToUser ", 14) == 0)
	       {
		  if((user->type & (SCRIPT | FORKED)) != 0)
		    script_to_user(temp, user);
	       }
	     else if(strncasecmp(temp, "$DataToAll ", 11) == 0)
	       {
		  if(user->type == SCRIPT)
		    {
		       send_to_non_humans(temp, FORKED, user);		      
		       send_to_humans(temp + 11, REGULAR | REGISTERED | OP | OP_ADMIN, user);
		    }
		  else if(user->type == FORKED)
		    send_to_humans(temp + 11, REGULAR | REGISTERED | OP | OP_ADMIN, user);
	       }
#endif
	  }
	
	/* Send to scripts */
#ifdef HAVE_PERL
	if(((user->type & (REGULAR | REGISTERED | OP | OP_ADMIN)) != 0)
	   && (temp != NULL) && (strlen(temp) > 2) 
	   && (strncasecmp(temp, "$ReloadScripts", 14) != 0))
	  {	     
	     command_to_scripts("$Script data_arrival %c%c%s%c%c", 
				'\005', '\005', user->nick, '\005', '\005');
	     non_format_to_scripts(temp);
	  }	
#endif
	
	if((buf = strchr(buf, '|')) != NULL)
	  buf++; 

	if(temp != NULL)
	  free(temp);
     } 
   return 1;
}

/* Add a user who connected */
int new_human_user(int sock)
{
   struct user_t *user;
   struct sockaddr_in client;
   int namelen;
   int yes = 1;
   int i = 0;
   int banret, allowret;
   int socknum;
   int erret;
   int flags;
   
   memset(&client, 0, sizeof(struct sockaddr_in));
   
   /* Get a socket for the connected user.  */
   namelen = sizeof(client);
   while(((socknum = accept(sock, (struct sockaddr *)&client, 
	     &namelen)) == -1) && ((errno == EAGAIN) || (errno == EINTR)))
     {
	i++;
	usleep(500);
	/* Giving up after half a second */
	if(i == 1000)
	  return -1;
     }
   
   /* Allocate space for the new user */
   if((user = malloc(sizeof(struct user_t))) == NULL)
     {	
	logprintf(1, "Error - In new_human_user()/malloc(): ");
	logerror(1, errno);
	quit = 1;
	return -1;
     }   
   
   /* Set the sock of the user.  */
   user->sock = socknum;

   /* Reset the last search time */
   user->last_search = 0;
   
   /* Avoid dead peers */
   if(setsockopt(user->sock, SOL_SOCKET, SO_KEEPALIVE, &yes,
		 sizeof(int)) == -1)
     {
	logprintf(1, "Error - In new_human_user()/set_sock_opt(): ");
	logerror(1, errno);
	close(user->sock);
	free(user);
	return -1;
     }
   
   if((flags = fcntl(user->sock, F_GETFL, 0)) < 0)
     {	
	logprintf(1, "Error - In new_human_user()/in fcntl(): ");
	logerror(1, errno);
	close(user->sock);
	free(user);
	return -1;
     }
   
   /* Non blocking mode */
   if(fcntl(user->sock, F_SETFL, flags | O_NONBLOCK) < 0)
     {
	logprintf(1, "Error - In new_human_user()/in fcntl(): ");
	logerror(1, errno);
	close(user->sock);
	free(user);
	return -1;
     }   
   
   /* Set users ip */
   user->ip = client.sin_addr.s_addr;
   
   /* Set users hostname if reverse_dns is set.  */
   if(reverse_dns != 0)
     strcpy(user->hostname, hostname_from_ip(user->ip));
   else
     strcpy(user->hostname, inet_ntoa(client.sin_addr));
   
   /* Send to scripts */
#ifdef HAVE_PERL
   command_to_scripts("$Script attempted_connection %c%c%s|", '\005', '\005', user->hostname);
#endif
   
   /* Set user vars to 0/NULL */
   user->type = NON_LOGGED;   
   memset(user->nick, 0, MAX_NICK_LEN+1);
   memset(user->version, 0, MAX_VERSION_LEN+1);
   user->email = NULL;
   user->desc = NULL;
   user->con_type = 0;
   user->flag = 0;
   user->share = 0;
   user->timeout = 0;
   user->buf = NULL;
   user->outbuf = NULL;
   user->rem = 0;
   user->last_search = (time_t)0;
   
   sprintf(user->nick, "Non_logged_in_user");
   
   /* Check if hub is full */
   if(sock == listening_socket)
     {
	if((count_all_users()) >= max_users)
	  {
	     hub_mess(user, HUB_FULL_MESS);
	     if(!((redirect_host == NULL) || ((int)redirect_host[0] <= 0x20)))
	       {
		  uprintf(user, "$ForceMove %s|", redirect_host);
	       }
	     
	     while(((erret =  close(user->sock)) != 0) && (errno == EINTR))
	       logprintf(1, "Error - In new_human_user()/close(): Interrupted system call. Trying again.\n");	
	     
	     if(erret != 0)
	       {	
		  logprintf(1, "Error - In new_human_user()/close(): ");
		  logerror(1, errno);
	       }   
	    
	     free(user);
	     return 1;
	  }
     }
   
   /* Check if user is banned */
   if(sock != admin_listening_socket) 
     {	
	banret = check_if_banned(user, BAN);
	allowret = check_if_allowed(user);   
	
	if(ban_overrides_allow == 0)
	  {
	     if((allowret != 1) && (banret == 1))
	       {	     
		  hub_mess(user, BAN_MESS);
		  logprintf(4, "User %s from %s (%s) denied\n",  user->nick, user->hostname, inet_ntoa(client.sin_addr));
		  while(((erret =  close(user->sock)) != 0) && (errno == EINTR))
		    logprintf(1, "Error - In new_human_user()/close(): Interrupted system call. Trying again.\n");	
		  
		  if(erret != 0)
		    {	
		       logprintf(1, "Error - In new_human_user()/close(): ");
		       logerror(1, errno);
		    }  
		  
		  free(user);
		  return 1;
	       }	
	  }
	
	else
	  {	
	     if((allowret != 1) || (banret == 1))
	       {	     
		  hub_mess(user, BAN_MESS);
		  logprintf(4, "User %s from %s (%s) denied\n",  user->nick, user->hostname, inet_ntoa(client.sin_addr));
		  while(((erret =  close(user->sock)) != 0) && (errno == EINTR))
		    logprintf(1, "Error - In new_human_user()/close(): Interrupted system call. Trying again.\n");	
		  
		  if(erret != 0)
		    {	
		       logprintf(1, "Error - In new_human_user()/close(): ");
		       logerror(1, errno);
		    }  
		  
		  free(user);
		  return 1;
	       }	
	  }
	
	if((banret == -1) || (allowret == -1))
	  {	
	     while(((erret =  close(user->sock)) != 0) && (errno == EINTR))
	       logprintf(1, "Error - In new_human_user()/close(): Interrupted system call. Trying again.\n");	
	     
	     if(erret != 0)
	       {	
		  logprintf(1, "Error - In new_human_user()/close(): ");
		  logerror(1, errno);
	       }  
	     free(user);
	     return -1;
	  }   
     }
           
   /* Add sock struct of the user.  */
   add_socket(user);
   
   if(sock == listening_socket)
     logprintf(4, "New connection on socket %d from user at %s\n", user->sock, user->hostname);
   else if(sock == admin_listening_socket)
     logprintf(4, "New admin connection on socket %d from user at %s\n", user->sock, user->hostname);

   /* If it's a regular user.  */
   if(sock == listening_socket)
     {
	if(check_key != 0)
	  user->type = UNKEYED;
	send_lock(user);
	hub_mess(user, INIT_MESS);
     }
   else if(sock == admin_listening_socket)
     {
	user->type = NON_LOGGED_ADM;
	hub_mess(user, INIT_ADMIN_MESS);
     }   
   
   if((count_users(UNKEYED | NON_LOGGED | REGULAR | REGISTERED | OP | OP_ADMIN
		   | ADMIN | NON_LOGGED_ADM) >= users_per_fork)
      || (max_sockets <= count_users(0xFFFF)+10))
     {
	set_listening_pid(0);	
	while(((erret =  close(listening_socket)) != 0) && (errno == EINTR))
	  logprintf(1, "Error - In new_human_user()/close(): Interrupted system call. Trying again.\n");	
	
	if(erret != 0)
	  {	
	     logprintf(1, "Error - In new_human_user()/close(): ");
	     logerror(1, errno);
	  }
	
	while(((erret =  close(admin_listening_socket)) != 0) && (errno == EINTR))
	  logprintf(1, "Error - In new_human_user()/close(): Interrupted system call. Trying again.\n");	
	
	if(erret != 0)
	  {	
	     logprintf(1, "Error - In new_human_user()/close(): ");
	     logerror(1, errno);
	  }  
	
	listening_socket = -1;
	admin_listening_socket = -1;
	send_to_user("$ClosedListen|", non_human_user_list);
     }   
	
   return 0;
}

/* Add a non-human user to the linked list.  */
void add_non_human_to_list(struct user_t *user)
{
   /* Add the user at the first place in the list */
   user->next = non_human_user_list;
   non_human_user_list = user;
}

/* Remove a non-human user.  */
void remove_non_human(struct user_t *our_user)
{
   int erret;
   struct user_t *user, *last_user;
  
   user = non_human_user_list;
   last_user = NULL;
   
   while(user != NULL)
     {
	if(user == our_user)
	  {	    
	     if(our_user->type != LINKED) 
	       {
		  while(((erret =  close(user->sock)) != 0) && (errno == EINTR))
		    logprintf(1, "Error - In remove_non_human()/close(): Interrupted system call. Trying again.\n");	
		  
		  if(erret != 0)
		    {	
		       logprintf(1, "Error - In remove_non_human()/close(): ");
		       logerror(1, errno);
		    }  
	       }
	     
	     if(last_user == NULL)
	       non_human_user_list = user->next;
	     else
	       last_user->next = user->next;
	     if(our_user->type != LINKED)
	       {
		  if(our_user->buf != NULL)
		    free(our_user->buf);
		  if(our_user->outbuf != NULL)
		    free(our_user->outbuf);
	       }
	     	  
	     free(our_user);	     
	     
	     return;
	  }
	last_user = user;
	user = user->next;
     }
}

/* Add a human user to the hashtable.  */
void add_human_to_hash(struct user_t *user)
{
   int hashv;
   
   hashv = get_hash(user->nick);
   
   /* Adds the user first in the linked list of the specified hash value.  */
   user->next = human_hash_table[hashv];
   human_hash_table[hashv] = user;
}

/* Returns a human user from a certain nick.  */
struct user_t* get_human_user(char *nick)
{
   struct user_t *user;
   
   user = human_hash_table[get_hash(nick)];
 
   while((user != NULL) 
	 && !((strncasecmp(user->nick, nick, strlen(nick)) == 0) 
	      && (strlen(nick) == strlen(user->nick))))
     user = user->next;
   
   return user;
}

/* Removes a human user from hashtable.  */
void remove_human_from_hash(char *nick)
{
   struct user_t *user, *last_user;
   int hashv;
   
   hashv = get_hash(nick);
   user = human_hash_table[hashv];
   last_user = NULL;
   
   while(user != NULL)
     {
	if((strncmp(user->nick, nick, strlen(nick)) == 0)
	   && (strlen(nick) == strlen(user->nick)))
	  {
	     if(last_user == NULL)
	       human_hash_table[hashv] = user->next;
	     else
	       last_user->next = user->next;

	     return;
	  }
	last_user = user;
	user = user->next;
     }
}

/* Removes a human user.  */
void remove_human_user(struct user_t *user)
{
   int erret;
   
   /* Remove the user from the hashtable.  */
   if((user->type & (REGULAR | REGISTERED | OP | OP_ADMIN | ADMIN)) != 0)
     remove_human_from_hash(user->nick);
    

   /* When a logged in user in a non script process leaves, the user should
    * be removed from the list and the users share should be subtracted from 
    * the total share.  */
   if((user->nick != NULL) 
      && ((user->type & (REGULAR | REGISTERED | OP | OP_ADMIN)) != 0) 
      && (pid == 0))
     {	
	if(user->share > 0)
	  add_total_share(-user->share);
     }
   
   while(((erret =  close(user->sock)) != 0) && (errno == EINTR))
     logprintf(1, "Error - In remove_human_user()/close(): Interrupted system call. Trying again.\n");	
   
   if(erret != 0)
     {	
	logprintf(1, "Error - In remove_human_user()/close(): ");
	logerror(1, errno);
     }  
   
   if(user->buf != NULL)
     {	     
	free(user->buf);
	user->buf = NULL;
     }   
   if(user->outbuf != NULL)
     {		     
	free(user->outbuf);
	user->outbuf = NULL;
     }   
   if(user->email != NULL)
     {		     
	free(user->email);
	user->email = NULL;
     }   
   if(user->desc != NULL)
     {		     
	free(user->desc);
	user->desc = NULL;
     }      
   
   /* Remove the socket struct of the user.  */
   remove_socket(user);
   
   
#ifdef HAVE_PERL
   if((user->type & (REGULAR | REGISTERED | OP | OP_ADMIN)) != 0)
     {	
	command_to_scripts("$Script user_disconnected %c%c", '\005', '\005');
	non_format_to_scripts(user->nick);
	command_to_scripts("|");
     }   
#endif 
      
   /* And free the user.  */
   free(user);
      
   if((count_users(UNKEYED | NON_LOGGED | REGULAR | REGISTERED | OP 
		   | OP_ADMIN | ADMIN) == 0) && (pid == 0)
      && (listening_socket == -1))
     kill_forked_process();
}

/* Removes a user. Sends the $quit string if send_quit is non-zero and removes
 * the user from the userlist if remove_from_list is non-zero.  */
void remove_user(struct user_t *our_user, int send_quit, int remove_from_list)
{
   char quit_string[MAX_NICK_LEN+10];
   
   if(send_quit != 0)
     {
	if((our_user->type & (REGULAR | REGISTERED | OP | OP_ADMIN)) != 0)
	  {
	     sprintf(quit_string, "$Quit %s|", our_user->nick);
	     send_to_non_humans(quit_string, FORKED, NULL);
	     send_to_humans(quit_string, REGULAR | REGISTERED | OP | OP_ADMIN,
			    our_user);
	  }
	else if((our_user->type == SCRIPT) 
		&& (strncmp(our_user->nick, "script process", 14) != 0))
	   {
	     sprintf(quit_string, "$Quit %s|", our_user->nick);
	     send_to_non_humans(quit_string, FORKED, NULL);
	     send_to_humans(quit_string, REGULAR | REGISTERED | OP | OP_ADMIN,
			    our_user);
	  }
     }   
   
   if((remove_from_list != 0)
      && (our_user->type & (REGULAR | REGISTERED | OP | OP_ADMIN | SCRIPT)) 
      != 0)
     remove_user_from_list(our_user->nick);
   
   if((our_user->type & (UNKEYED | NON_LOGGED | REGULAR | REGISTERED | OP 
			| OP_ADMIN | ADMIN | NON_LOGGED_ADM)) != 0)
     remove_human_user(our_user);
   else
     remove_non_human(our_user);
}

/* Removes all users who have the rem variable set to non-zero */
void clear_user_list(void)
{
   struct user_t *non_human;
   struct user_t *next_non_human;
   struct sock_t *human_user;
   struct sock_t *next_human_user;
   
   non_human = non_human_user_list;
   human_user = human_sock_list;
   
   while(non_human != NULL)
     {
	next_non_human = non_human->next;
	if(non_human->rem != 0)
	  remove_user(non_human, non_human->rem & SEND_QUIT, 
		      non_human->rem & REMOVE_FROM_LIST);
	
	non_human = next_non_human;
     }
   
   while(human_user != NULL) 
     {
	next_human_user = human_user->next;
	if(human_user->user->rem != 0)
	  remove_user(human_user->user, human_user->user->rem & SEND_QUIT,
		      human_user->user->rem & REMOVE_FROM_LIST);
	
	human_user = next_human_user;
     }
}

/********************************************************/
/* Get action from a connected socket  */
/* Returns -1 on error,                */
/* 0 on connection closed,             */
/* 1 on received message               */
int socket_action(struct user_t *user)
{
   int buf_len;
   char *command_buf;
   char buf[MAX_MESS_SIZE + 1];
   int i = 0;
   
   command_buf = NULL;
   
   /* Error or connection closed? */
   while(((buf_len = recv(user->sock, buf, MAX_MESS_SIZE, 0)) == -1) 
	 && ((errno == EAGAIN) || (errno == EINTR)))
     {
	i++;
	usleep(500);
	/* Giving up after half a second */
	if(i == 1000)
	  break;	  		
     }

   if(buf_len <= 0)
     {	
	/* Connection closed */
	if(buf_len == 0)
	  {
	     /* If it was a human user.  */
	     if((user->type & (SCRIPT | LINKED | FORKED)) == 0)
	       {		       
		  if((int)user->nick[0] > 0x20)
		    logprintf(1, "%s from %s at socket %d hung up\n", user->nick, user->hostname, user->sock);
		  else
		    logprintf(1, "User at socket %d from %s hung up\n", user->sock, user->hostname);
		  user->rem = REMOVE_USER | SEND_QUIT | REMOVE_FROM_LIST;		  		
	       }
	     else
	       {
		  /* If the parent process disconnected, exit this process.  */
		  if(pid <= 0)
		    {
		       if(count_users(SCRIPT | FORKED) == 1)
			 kill_forked_process();
		    }

		  user->rem = REMOVE_USER | SEND_QUIT | REMOVE_FROM_LIST;
		  
		  /* If it was a forked process, check if we have a listening
		   * process. I we don't, we fork.  */
		  if((user->type == FORKED) && (get_listening_pid() == 0) 
		     && (pid > 0)) 
		    do_fork = 1;
	       }
	     return 0;
	  } 
	else if(errno == ECONNRESET)
	  {
	     if((user->type & (SCRIPT | LINKED | FORKED)) == 0)
	       {		  
		  if((int)user->nick[0] > 0x20)
		    logprintf(1, "%s from %s at socket %d hung up (Connection reset by peer)\n", user->nick, user->hostname, user->sock);
		  else
		    logprintf(1, "User at socket %d from %s hung up (Connection reset by peer)\n", user->sock, user->hostname);
		  user->rem = REMOVE_USER | SEND_QUIT | REMOVE_FROM_LIST;
	       }	     
	     else
	       user->rem = REMOVE_USER | SEND_QUIT | REMOVE_FROM_LIST;
	     return 0;	       
	  }
	else if(errno == ETIMEDOUT)
	  {
	     if((user->type & (SCRIPT | LINKED | FORKED)) == 0)
	       {		  
		  if((int)user->nick[0] > 0x20)
		    logprintf(1, "%s from %s at socket %d hung up (Connection timed out)\n", user->nick, user->hostname, user->sock);
		  else
		    logprintf(1, "User at socket %d from %s hung up (Connection timed out)\n", user->sock, user->hostname);
		  user->rem = REMOVE_USER | SEND_QUIT | REMOVE_FROM_LIST;
	       }	     
	     else
	       user->rem = REMOVE_USER | SEND_QUIT | REMOVE_FROM_LIST;
	     return 0;
	  }
	else if(errno == EHOSTUNREACH)
	  {
	     if((user->type & (SCRIPT | LINKED | FORKED)) == 0)
	       {		  
		  if((int)user->nick[0] > 0x20)
		    logprintf(1, "%s from %s at socket %d hung up (No route to host)\n", user->nick, user->hostname, user->sock);
		  else
		    logprintf(1, "User at socket %d from %s hung up (No route to host)\n", user->sock, user->hostname);
		  user->rem = REMOVE_USER | SEND_QUIT | REMOVE_FROM_LIST;
	       }
	     else
	       user->rem = REMOVE_USER | SEND_QUIT | REMOVE_FROM_LIST;
	     return 0;	       
	  }
	else
	  {
	     logprintf(4, "Error - In get_socket_action()/socket_action()/recv() when receiving from %s: ", user->hostname);
	     logerror(4, errno);
	     return -1;
	  }
     } 
   else 
     {
	/* Set the char after the last received one in buf to null in case the memory
	 * position was set to something else than null before */
	buf[buf_len] = '\0';
	
	/* If the inbuf is empty */
	if(user->buf == NULL)
	  {
	     if((command_buf = malloc(sizeof(char) * (buf_len + 1))) == NULL)
	       {
		  logprintf(1, "Error - In socket_action()/malloc(): ");
		  logerror(1, errno);
		  quit = 1;
		  return -1;
	       }
	     strcpy(command_buf, buf);
	     if(strchr(command_buf, '|') != NULL)
	       {
		  if(handle_command(command_buf, user) == 0)
		    {
		       user->rem = REMOVE_USER | SEND_QUIT | REMOVE_FROM_LIST;
		       free(command_buf);
		       return 0;
		    }
	       }
	     
	     /* If the string doesn't contain the '|' at all */
	     if(strchr(buf, '|') == NULL)
	       {
		  if((user->buf = malloc(sizeof(char) * (buf_len + 1))) == NULL)
		    {
		       logprintf(1, "Error - In socket_action()/malloc(): ");
		       logerror(1, errno);
		       quit = 1;
		       free(command_buf);
		       return -1;
		    }
		  strcpy(user->buf, buf);
	       }
	     else
	       /* If the string continues after the last '|' */
	       {
		  if((user->buf = malloc(sizeof(char) * strlen(strrchr(buf, '|')))) == NULL)
		    {
		       logprintf(1, "Error - In socket_action()/malloc(): ");
		       logerror(1, errno);
		       quit = 1;
		       free(command_buf);
		       return -1;
		    }
		  strcpy(user->buf, strrchr(buf, '|') + 1);
	       }
	  }
	else
	  /* We have something in the inbuf */
	  {
	     if((command_buf = malloc(sizeof(char) * (buf_len + strlen(user->buf) + 1))) == NULL)
	       {
		  logprintf(1, "Error - In socket_action()/malloc(): ");
		  logerror(1, errno);
		  quit = 1;
		  return -1;
	       }
	     strcpy(command_buf, user->buf);
	     strcat(command_buf, buf);
	     if(strchr(command_buf, '|') != NULL)
	       {
		  if(handle_command(command_buf, user) == 0)
		    {
		       user->rem = REMOVE_USER | SEND_QUIT | REMOVE_FROM_LIST;
		       free(command_buf);
		       return 0;
		    }
	       }
	     
	     /* If the string doesn't contain a '|' */
	     if(strchr(buf, '|') == NULL)
	       {
		  if((user->buf = realloc(user->buf, sizeof(char) 
		      * (buf_len + strlen(user->buf) + 1))) == NULL)
		    {
		       logprintf(1, "Error - In socket_action()/realloc(): ");
		       logerror(1, errno);
		       quit = 1;
		       free(command_buf);
		       return -1;
		    }
		  strcat(user->buf,  buf);
		  
		  /* The buf shouldn't be able to grow too much. If it gets 
		   * really big, it's probably due to some kind of attack */
		  if(strlen(user->buf) >= MAX_BUF_SIZE)
		    {
		       if(user->rem == 0)
			 logprintf(1, "User from %s had too big buf, kicking user\n", user->hostname);
		       user->rem = REMOVE_USER | SEND_QUIT | REMOVE_FROM_LIST;
		    }
	       }	     
	     
	     /* If the string continues after the last '|' */
	     else if(strlen(strrchr(buf, '|')) > 1)
	       {
		  if((user->buf = realloc(user->buf, sizeof(char) 
			   * strlen(strrchr(buf, '|')))) == NULL)
		    {
		       logprintf(1, "Error - In socket_action()/realloc(): ");
		       logerror(1, errno);
		       quit = 1;
		       free(command_buf);
		       return -1;
		    }
		  strcpy(user->buf, strrchr(buf, '|') + 1);
   
		  /* The buf shouldn't be able to grow too much. If it gets 
		   * really big, it's probably due to some kind of attack.  */
		  if(strlen(user->buf) >= MAX_BUF_SIZE)
		    {
		       if(user->rem == 0)
			 logprintf(1, "User from %s had to big buf, kicking user\n", user->hostname);
		       user->rem = REMOVE_USER | SEND_QUIT | REMOVE_FROM_LIST;
		    }
	       }
	     
	  
	     /* The string ends with the '|' */
	     else
	       {	
		  free(user->buf);
		  user->buf = NULL;	
	       }
	  }
	
	logprintf(5, "PID: %d Received command from %s, type 0x%X: %s\n", 
		    (int)getpid(), user->hostname, user->type, command_buf);

	if(command_buf != NULL)
	  free(command_buf);

	return 1;
     }
}

/* Handles udp packages. */
int udp_action(void)
{
   int mess_len;
   int sin_len;
   char message[4096];
   struct sockaddr_in sin;
   struct user_t *user_list;
   struct hostent *ex_user;
   int i=0;
   
   memset(&sin, 0, sizeof(struct sockaddr_in));
   sin_len = sizeof(struct sockaddr);
   
   while(((mess_len = recvfrom(listening_udp_socket, message, sizeof(message), 0,
	    (struct sockaddr *)&sin, &sin_len)) == -1) 
	 && ((errno == EAGAIN) || (errno == EINTR)))
     {
	i++;
	usleep(500);
	/* Giving up after half a second */
	if(i == 1000)
	  break;
     }
   
   if(mess_len <= 0)
     {	
	logprintf(4, "Error - In udp_action()/recvfrom(): ");
	logerror(4, errno);
	return -1;
     }     
   
   message[mess_len] = '\0';
   
   /* Check if user is in the list */
   user_list = non_human_user_list;
   while(user_list != NULL)
     {
	if(user_list->type == LINKED)
	  {
	     ex_user = gethostbyname(user_list->hostname);
	     if((((struct in_addr *)ex_user->h_addr_list[0])->s_addr == sin.sin_addr.s_addr) && (user_list->key == ntohs(sin.sin_port)))
	       {
		  if(strncmp(message, "$Search ", 8) == 0)
		    search(message, user_list);
		  else if(strncmp(message, "$ConnectToMe ", 13) == 0)
		    connect_to_me(message, user_list);
	       }
	  }
	user_list = user_list->next;
     }	
   
   if((strncmp(message, "$Up ", 4) == 0) || (strncmp(message, "$UpToo ", 7) == 0))
     up_cmd(message, ntohs(sin.sin_port));
   
   logprintf(5, "Received udp packet from %s, port %d:\n%s\n", 
	       inet_ntoa(sin.sin_addr), ntohs(sin.sin_port), message);
   
   /* Send event to scripts */
#ifdef HAVE_PERL
   command_to_scripts("$Script multi_hub_data_chunk_in %c%c", '\005', '\005');
   non_format_to_scripts(message);
#endif
   
   return 1;
}
  

/* Takes password and encrypts it. http://www.gnu.org/manual/glibc-2.2.5/html_node/crypt.html */ 
void encrypt_pass(char* password)
{
  unsigned long seed[2];
  char salt[] = "$1$........";
  
  const char *const seedchars = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
  
  int i;

  seed[0] = time(NULL);								/* Maybe using /dev/urandom. */
  seed[1] = getpid() ^ (seed[0] >> 14 & 0x30000);

  /* Turn it into printable characters from `seedchars'. */
  for (i = 0; i < 8; i++)
    salt[3+i] = seedchars[(seed[i/5] >> (i%5)*6) & 0x3f];
  if(crypt_enable != 0)
    strcpy(password, crypt(password, salt));
}

 

/**********************************************************/
/* Main function */
int main(int argc, char *argv[])
{
   int ret;
   int erret;
   int x;
#ifdef SWITCH_USER
   struct passwd *userinfo;
   struct group *groupinfo;
   int got_user = 0;
   int got_group = 0;
   cap_t cap;
   int cap_failed = 0;
   cap_value_t caps[1];
   caps[0] = CAP_NET_BIND_SERVICE;
#endif

   max_sockets = getdtablesize();
   
#ifndef HAVE_POLL
# ifdef FD_SETSIZE
   if(max_sockets > FD_SETSIZE)
     max_sockets = FD_SETSIZE;
# endif
#endif
   
   /* Init some variables */
   listening_socket = -1;
   admin_listening_socket = -1;
   debug = 0;
   do_send_linked_hubs = 0;
   do_purge_user_list = 0;
   do_fork = 0;
   upload = 0;
   quit = 0;
   script_reload = 0;
   verbosity = 4;
   redir_on_min_share = 1;
   hub_full_mess = NULL;
   non_human_user_list = NULL;
   human_sock_list = NULL;
   memset(logfile, 0, MAX_FDP_LEN+1);
   syslog_enable = 0;
   syslog_switch = 0;
   searchcheck_exclude_internal = 0;
   searchcheck_exclude_all = 0;
   kick_bantime = 0;
   searchspam_time = 0;
   working_dir[0] = '\0';
   max_email_len = 50;
   max_desc_len = 100;
   crypt_enable = 1;
   current_forked = 1;
   	
   /* Parse arguments to program */
   for (x = 0; x < argc; x++)
     {
	/* Debug mode */
	if ((strcmp(argv[x], "-d")) == 0)
	  debug = 1;
#ifdef SWITCH_USER
	else if ((strcmp(argv[x], "-u")) == 0)
	  {
	     x++;
	     userinfo = getpwnam(argv[x]);
	     if(userinfo == NULL)
	       {
		  printf("Couldn't locate user: %s\n", argv[x]);
		  perror("getpwnam");
		  exit(EXIT_FAILURE);
	       }
	     dchub_user = userinfo->pw_uid;
	     got_user = 1;
	     if(got_group == 0)
		dchub_group = userinfo->pw_gid;
	  }
	else if ((strcmp(argv[x], "-g")) == 0)
	  {
	     x++;
	     groupinfo = getgrnam(argv[x]);
	     if(groupinfo == NULL)
	       {
		  printf("Couldn't locate group: %s\n", argv[x]);
		  perror("getgrnam");
		  exit(EXIT_FAILURE);
	       }
	     dchub_group = groupinfo->gr_gid;
	     got_group = 1;
	  }
#endif
	/* Print help and exit*/
	else if ((strcmp(argv[x], "-h")) == 0)
	  {
	     printf("\nOpen DC Hub, version %s\n", VERSION);
	     printf("  -d           : Debug mode. Also prevents Open DC Hub from making itself a\n                 background daemon.\n");
	     printf("  -h           : Print this help and exit.\n");
	     printf("  --version    : Print version.\n");
	     printf("  -l <logfile> : Set logfile.\n");
	     printf("  -s           : Use syslog instead of a logfile.\n");
	     printf("  -w <path>    : Set the path to the working directory.\n");
#ifdef SWITCH_USER
	     printf("  -u <user>    : User to switch to run as.\n");
	     printf("  -g <group>   : Group to switch to run as.\n");
#endif
	     exit(EXIT_SUCCESS);
	}
	/* Set logfile */
	else if ((strcmp(argv[x], "-l")) == 0)
	  {
	     x++;
	     /* Check if argv[x] is usable as logfile.  */
	     if((ret = open(argv[x], O_RDWR | O_CREAT, 0600)) >= 0)
	       {
		  /* Set logfile. */
		  strncpy(logfile,argv[x],MAX_FDP_LEN);
		  printf("Using logfile: %s\n", logfile);
		  close(ret);
		}
	     else
	       {
		  printf("Couldn't open logfile: %s\n", argv[x]);
		  perror("open");
		  exit(EXIT_FAILURE);
	       }	     
	  }
	else if ((strcmp(argv[x], "-s")) == 0)
	  {
	     syslog_switch = 1;
	     openlog(SYSLOG_IDENT, LOG_ODELAY, LOG_USER);
	  }
	else if ((strcmp(argv[x], "-w")) == 0)
	  {
	     x++;
	     strncpy(working_dir, argv[x], MAX_FDP_LEN);
	     if((ret = access(working_dir, F_OK)) < 0)
	       {
		  printf("Directory does not exist: %s\n", argv[x]);
		  perror("access");
		  exit(EXIT_FAILURE);
	       }
	  }
	else if ((strcmp(argv[x], "--version"))== 0)
	  {
	     printf("Open DC Hub %s\n", VERSION);
	     exit(EXIT_SUCCESS);
	  }	
     }
#ifdef SWITCH_USER
   if (got_user)
     {
        if ((geteuid() == 0) && ((cap = cap_init()) != NULL))
	  {
	     if (prctl(PR_SET_KEEPCAPS, 1))
		cap_failed = 1;
	     else if (setgroups(0, NULL) == -1)
		cap_failed = 1;
	     else if ((setegid(dchub_group) == -1)
		      || (seteuid(dchub_user) == -1))
		cap_failed = 1;
	     else if (cap_set_flag(cap, CAP_EFFECTIVE, 1, caps, CAP_SET) == -1)
		cap_failed = 1;
	     else if (cap_set_flag(cap, CAP_PERMITTED, 1, caps, CAP_SET) == -1)
		cap_failed = 1;
	     else if (cap_set_flag(cap, CAP_INHERITABLE, 1, caps, CAP_SET) == -1)
		cap_failed = 1;
	     else if (cap_set_proc(cap) == -1)
		cap_failed = 1;
	     else if ((setresgid(dchub_group, dchub_group, dchub_group) == -1) ||
		      (setresuid(dchub_user, dchub_user, dchub_user) == -1))
		cap_failed = 1;
	     else if (setuid(0) == 0)
		cap_failed = 1;
	     cap_free(cap);
	  }
	else
	   cap_failed = 1;

	if(cap_failed != 0)
	  {
	     perror("Error in switching user\n");
	     exit(EXIT_FAILURE);
	  }
     }
   else
     {
	dchub_user = getuid();
	dchub_group = getgid();
     }
#endif
   
   
   /* This is only a list of addresses to users, not users, so it won't be that
    * space consuming although this will use more memory than a linked list.
    * It's simply faster operation on behalf of more memory usage. */
   if((human_hash_table = calloc(max_sockets + 1, sizeof(struct user_t *))) == NULL)
     {
	printf("Couldn't initiate human_hash_table.\n");
	perror("calloc");
	exit(EXIT_FAILURE);
     }
   
   if(init_dirs() == 0)
     return 1;
   
   logprintf(1, "***Started Open DC Hub version %s***\n", VERSION);
   hub_start_time = time(NULL);
   if(read_config() == -1)
     {
	if(set_default_vars() == 0)
	  {
	     logprintf(1, "Failed setting config variables! Exiting\n");
	     exit(EXIT_FAILURE);
	  }
	if(write_config_file() == -1)
	  {
	     logprintf(1, "Failed writing config file! Exiting\n");
	     exit(EXIT_FAILURE);
	  }
	logprintf(1, "Created config file\n");
     }
#ifdef HAVE_SYSLOG_H
   if((syslog_enable != 0) && (syslog_switch == 0))
     {
	logprintf(1, "***Switching to syslog***\n");
	openlog(SYSLOG_IDENT, LOG_ODELAY, LOG_USER);
     }
#endif
   if((ret = write_motd("Welcome to the hub. Enjoy your stay.", 0)) == -1)
     {
	logprintf(1, "Failed creating motd file! Exiting\n");
	exit(EXIT_FAILURE);
     }
   else if(ret == 1)
     logprintf(1, "Created motd file\n");
   
   create_banlist();
   create_nickbanlist();
   create_allowlist();
   create_reglist();
   create_linklist();
   create_op_permlist();
   if((int)hub_hostname[0] <= 0x20)
     if(set_hub_hostname() == -1)     
       return 1;

   /* Test if we can open the listening socket.  */
   if((listening_socket = get_listening_socket(listening_port, 0)) == -1)
     {
	printf("Bind failed.\nRemember, to use a listening port below 1024, you need to be root.\nAlso, make sure that you don't have another instance of the program\nalready running.\n");
	close(listening_unx_socket);
	close(listening_udp_socket);
	return 1;
     }
   
   while(((erret =  close(listening_socket)) != 0) && (errno == EINTR))
     logprintf(1, "Error - main()/close(): Interrupted system call. Trying again.\n");	
   
   if(erret != 0)
     {	
	logprintf(1, "Error - main/close(): ");
	perror("close");
	return 1;
     }
   
   listening_socket = -1;
   
   if((listening_unx_socket = get_listening_unx_socket()) == -1)     
     return 1;
   
   if((listening_udp_socket = get_listening_udp_socket(listening_port)) == -1)
     {
	printf("Bind failed.\nRemember, to use a listening port below 1024, you need to be root.\nAlso, make sure that you don't have another instance of the program\nalready running.\n");
	close(listening_unx_socket);
	return 1;     
     }
   
   /* Tell user that hub is running */
   printf("Hub is up and running. Listening for user connections on port %u\n", listening_port);
   if(admin_port != 0) {
     printf("and listening for admin connections on ");
     if(admin_localhost == 1) {
       printf("localhost port %u\n", admin_port);
     } else {
       printf("port %u\n", admin_port);
     }
   }
   
   /* With -d, for debug, we will run in console so skip this part. */
   if(debug == 0)
      {
	 /* Make program a daemon */
	 pid = fork();
	 if(pid < 0)
	   {
	      perror("fork");
	      exit(EXIT_FAILURE);
	   }
	 if(pid > 0)
	   exit(EXIT_SUCCESS);
	 if(setsid() < 0)
	   {
	      perror("setsid");
	      exit(EXIT_FAILURE);
	   }
	   
	 if(close(STDIN_FILENO) != 0)
	   {
	      logprintf(1, "Error - When closing STDIN_FILENO, exiting\n");
	      exit(EXIT_FAILURE);
	   }
	 if(close(STDOUT_FILENO) != 0)
	   {
	      logprintf(1, "Error - When closing STDOUT_FILENO, exiting\n");
	      exit(EXIT_FAILURE);
	   }
	 if(close(STDERR_FILENO) != 0)
	   {
	      logprintf(1, "Error - When closing STDERR_FILENO, exiting\n");
	      exit(EXIT_FAILURE);
	   }
      }
   
   /* Set pid */
   pid = getpid();
   
    /* Initialize the semaphores.  */
   if(init_sem(&total_share_sem) ==  -1)
     {
	logprintf(1, "Couldn't initialize the total share semaphore.\n");
	exit(EXIT_FAILURE);
     }
   
   if(init_sem(&user_list_sem) ==  -1)
     {
	logprintf(1, "Couldn't initialize the user list semaphore.\n");
	exit(EXIT_FAILURE);
     }
   
   if(init_share_shm() == -1)
     {
	logprintf(1, "Couldn't initialize the total share shared memory segment.\n");
	semctl(total_share_sem, 0, IPC_RMID, NULL);
	semctl(user_list_sem, 0, IPC_RMID, NULL);
     }
   
    if(init_user_list() == -1)
     {
	logprintf(1, "Couldn't initialize the user list.\n");
	semctl(total_share_sem, 0, IPC_RMID, NULL);
	semctl(user_list_sem, 0, IPC_RMID, NULL);
     }
	
   init_sig();

   /* Send initial alarm */
   if((kill(pid, SIGALRM)) < 0)
     {
	return 1;
     }

   /* Init perl scripts */
#ifdef HAVE_PERL	
   if(perl_init() == 0)
     logprintf(1, "Error - Perl initialization failed.\n");
   else if(pid <= 0)
     sub_to_script("started_serving|");
   
#endif 
   
   /* Fork process which holds the listening sockets.  */
   if(pid > 0)
     fork_process();
   
   while(quit == 0)
     {
	if(pid > 0)
	  {
	     if((upload != 0) && (hublist_upload != 0))
	       do_upload_to_hublist();
	     if(do_write != 0)
	       {
		  write_config_file();
		  do_write = 0;
	       }
	     if(do_send_linked_hubs != 0)
	       {  
		  send_linked_hubs();
		  do_send_linked_hubs = 0;
	       }
	     if(do_purge_user_list != 0)
	       {
		  purge_user_list();
		  do_purge_user_list = 0;
	       }	     
#ifdef HAVE_PERL
	     if(script_reload != 0)
	       {
		  perl_init();
		  script_reload = 0;
	       }
#endif
	  }
	get_socket_action();
	clear_user_list();
	if((do_fork == 1) && (pid > 0))
	  {	     
	     fork_process();
	     do_fork = 0;
	  }	
     }
   quit_program();
   remove_all(0xFFFF, 0, 0);
   return 0;
}
