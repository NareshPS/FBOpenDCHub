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

#include <EXTERN.h>
#include <perl.h>

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
#include <sys/shm.h>

#include "main.h"
#include "network.h"
#include "perl_utils.h"
#include "xs_functions.h"
#include "fileio.h"
#include "utils.h"
#include "userlist.h"

static PerlInterpreter *my_perl = NULL;

/* Allocates and initializes the perlinterpreter and loads the scripts. */
/* Returns 1 on success and 0 on failure */
int perl_init(void)
{
   char path[MAX_FDP_LEN+1];
   char *script_list[256];
   char *myargv[] = {"", NULL};
   int i, k, len;
   int sock;
   struct sockaddr_un remote_addr;
   char temp_nick[MAX_NICK_LEN+1];
   char temp_host[MAX_HOST_LEN+1];
   char *buf, *bufp;
   int spaces=0, entries=0;
   int l;
   int erret;
   int flags;
   
   memset(&remote_addr, 0, sizeof(struct sockaddr_un));

   /* First kill off scripts that is already running.  */
   remove_all(SCRIPT, 1, 1);
   
   /* Reads the script names in the script directory */
   snprintf(path, MAX_FDP_LEN, "%s/%s", config_dir, SCRIPT_DIR);
   i = my_scandir(path, script_list);
   
   if(i == 0)
     return 1;
   
   k = i-1;
   
   for(i = 0; i <= k; i++)
     {	
	myargv[1] = script_list[i];
	if((pid = fork()) == -1)
	  {	
	     logprintf(1, "Fork failed, exiting process\n");
	     logerror(1, errno);
	     quit = 1;
	     return 0;;
	  }
	
	/* If we are the parent */   
	if(pid > 0)
	  {
	     logprintf(3, "Forked new script parsing process for script %s, childs pid is %d and parents pid is %d\n", script_list[i], pid, getpid());
	     pid = getpid();
	  }
	
	/* And if we are the child */
	else
	  {
	     pid = -1;
	     
	     /* Close the listening sockets */
	     while(((erret =  close(listening_unx_socket)) != 0) && (errno == EINTR))
	       logprintf(1, "Error - In perl_init()/close(): Interrupted system call. Trying again.\n");
	     
	     if(erret != 0)
	       {		  
		  logprintf(1, "Error - In perl_init()/close(): ");
		  logerror(1, errno);
	       }
	     
	     while(((erret =  close(listening_udp_socket)) != 0) && (errno == EINTR))
	       logprintf(1, "Error - In perl_init()/close(): Interrupted system call. Trying again.\n");
	     
	     if(erret != 0)
	       {		  
		  logprintf(1, "Error - In perl_init()/close(): ");
		  logerror(1, errno);
	       }
	     
	     /* Set the alarm */
	     alarm(ALARM_TIME);
	     
	     /* And connect to parent process */
	     if((sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
	       {		  
		  logprintf(1, "Error - In perl_init()/socket(): ");
		  logerror(1, errno);
		  free(script_list[i]);
		  exit(EXIT_FAILURE);
	       }
	     
	     remote_addr.sun_family = AF_UNIX;
	     strcpy(remote_addr.sun_path, un_sock_path);
	     len = strlen(remote_addr.sun_path) + sizeof(remote_addr.sun_family) + 1;
	     if(connect(sock, (struct sockaddr *)&remote_addr, len) == -1)
	       {	     
		  logprintf(1, "Error - In perl_init()/connect(): ");
		  logerror(1, errno);
		  free(script_list[i]);
		  exit(EXIT_FAILURE);
	       }
	     
	     if((flags = fcntl(sock, F_GETFL, 0)) < 0)
	       {
		  logprintf(1, "Error - In new_human_user()/in fcntl(): ");
		  logerror(1, errno);
		  close(sock);
		  return -1;
	       }
	     
	     /* Non blocking mode */
	     if(fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0)
	       {
		  logprintf(1, "Error - In new_human_user()/in fcntl(): ");
		  logerror(1, errno);
		  close(sock);
		  return -1;
	       }	     
	     
	     /* The parent process will be a special kind of user */
	     /* Allocate space for the new user. Since the process
	      * should be empty on users and no one is to be added, 
	      * we use non_human_user_list.  */

	     /* Allocate space for the new user */
	     if((non_human_user_list = malloc(sizeof(struct user_t))) == NULL)
	       {		  
		  logprintf(1, "Error - In parl_init()/malloc(): ");
		  logerror(1, errno);
		  quit = 1;
		  free(script_list[i]);
		  exit(EXIT_FAILURE);
	       }	     	     
	          	
	     non_human_user_list->sock = sock;	
	     non_human_user_list->rem = 0;	
	     non_human_user_list->type = SCRIPT;
	     non_human_user_list->buf = NULL;
	     non_human_user_list->outbuf = NULL;
	     non_human_user_list->next = NULL;
	     non_human_user_list->email = NULL;
	     non_human_user_list->desc = NULL;
	     memset(non_human_user_list->nick, 0, MAX_NICK_LEN+1);
	     sprintf(non_human_user_list->nick, "parent process");
	     sprintf(non_human_user_list->hostname, "parent_process");
	     send_to_user("$NewScript|", non_human_user_list);
	     
	     /* Remove all users.  */	    
	     remove_all(~SCRIPT, 0, 0);
	     
	     /* Initialize the perl interpreter for this process */
	     if((my_perl = perl_alloc()) == NULL) 
	       {	
		  logprintf(1, "perl_alloc() failed\n");
		  free(script_list[i]);
		  exit(EXIT_FAILURE);
	       }
	     
	     perl_construct(my_perl);
	     if(perl_parse(my_perl, xs_init, 2, myargv, NULL))
	       {
		  logprintf(1, "Parse of %s failed.\n", script_list[i]);
		  free(script_list[i]);
		  exit(EXIT_FAILURE);
	       }
	     
	     if(perl_run(my_perl))
	       {
		  logprintf(1, "Couldn't run perl script %s.\n", script_list[i]);
		  free(script_list[i]);
		  exit(EXIT_FAILURE);
	       }
	     
	     /* Run the scripts main sub if it exists.  */
	       {		  
		  dSP;
		  ENTER;
		  SAVETMPS;
		  PUSHMARK(SP);
		  PUTBACK;
		  call_pv("main", G_DISCARD|G_EVAL);
		  SPAGAIN;
		  PUTBACK;
		  FREETMPS;
		  LEAVE;   
	       }

	     free(script_list[i]);
	     
	     /* Get info of all users.  */
	     if(i == 0)
	       {				  		
		  sem_take(user_list_sem);
		  
		  /* Attach to the shared segment */
		  if((buf = (char *)shmat(get_user_list_shm_id(), NULL, 0))
		     == (char *)-1)
		    {		       
		       logprintf(1, "Error - In perl_init()/shmat(): ");
		       logerror(1, errno);
		       sem_give(user_list_sem);
		       quit = 1;
		       return -1;
		    }
		  
		  if(sscanf(buf, "%d %d", &spaces, &entries) != 2)
		    {		       
		       logprintf(1, "Error - In perl_init(): Couldn't get number of entries\n");
		       shmdt(buf);
		       sem_give(user_list_sem);
		       quit = 1;
		       return -1;
		    }		  		  
		  
		  bufp = buf + 30;
		  
		  for(l = 1; l <= spaces; l++)
		    {		       
		       if(*bufp != '\0')
			 {			    
			    sscanf(bufp, "%50s %120s", temp_nick, temp_host);
			    uprintf(non_human_user_list, 
				    "$GetINFO %s $Script|", temp_nick);
			 }		       
		       
		       bufp += USER_LIST_ENT_SIZE;
		    }
		  shmdt(buf);
		  sem_give(user_list_sem);		 
	       }	     
	     return 1;
	  }
	free(script_list[i]);
     }
   return 1;
}

/* This function takes a string and sends it to all script parsing pocesses. */
void command_to_scripts(const char *format, ...)
{
   static char buf[0xFFFF];
   struct user_t *user;
   
   if(format)
     {	
	va_list args;
	va_start(args, format);
	vsnprintf(buf, 0xFFFE, format, args);
	va_end(args);
     }
   
   user = non_human_user_list;

   /* If we are the parent, send directly to script processes */
   if(pid > 0)
     {
	while(user != NULL)
	  {
	     if(user->type == SCRIPT)
	       send_to_user(buf, user);
	     user = user->next;
	  }
     }
   
   /* If we are child, send to parent first */
   else
     {
	while(user != NULL)
	  {	     
	     if(user->type == FORKED)
	       send_to_user(buf, user);
	     user = user->next;
	  }	
     }
}

/* Sends a string to scripts.  */
void non_format_to_scripts(char *buf)
{
   struct user_t *user;
   
   user = non_human_user_list;
   
   /* If we are the parent, send directly to script processes */
   if(pid > 0)
     {	
	while(user != NULL)
	  {
	     if(user->type == SCRIPT)
	       send_to_user(buf, user);
	     user = user->next;
	  }
     }
   
   /* If we are child, send to parent first */
   else
     {
	while(user != NULL)
	  {	     
	     if(user->type == FORKED)
	       send_to_user(buf, user);
		     
	     user = user->next;
	  }	
     }  
}

/* Takes a string, sent with command_to_script, and sends it to the script 
 * itself, i.e, we are in the script parsing process */
void sub_to_script(char *buf)
{
   char subname[31];          /* Name of the Perl sub */
   char *arg1 = NULL;         /* First argument to the sub */
   char *arg2 = NULL;         /* Second argument to the sub */
   char *arg3 = NULL;         /* Third argument to the sub */
   char *temp;
   char temp_nick[MAX_NICK_LEN+1];
   struct user_t *temp_user;
   int i;
   
   if(sscanf(buf, "%30[^| ]", subname) != 1)
     {
	logprintf(1, "Got incomplete command to to_script()\n");
	return;
     }

   /* user_info is a special case, since it isn't sent to the scripts, it's
    * only used to set variables of the user in the script parsing process.  */
   if(!strncmp(subname, "user_info", 9))
     {
	sscanf(buf + 10, "%50s", temp_nick);
	/* If the user isn't already here, allocate a new user.  */
	if((temp_user = get_human_user(temp_nick)) == NULL)
	  {	     
	     if((temp_user = malloc(sizeof(struct user_t))) == NULL)
	       {		  
		  logprintf(1, "Error - In sub_to_script()/malloc(): ");
		  logerror(1, errno);
		  quit = 1;
		  return;
	       }
	     
	     temp_user->email = NULL;
	     temp_user->desc = NULL;
	     temp_user->buf = NULL;
	     temp_user->outbuf = NULL;
	  }
	else
	  {
	     remove_human_from_hash(temp_user->nick);
	     
	     if(temp_user->email != NULL)
	       free(temp_user->email);
	     temp_user->email = NULL;
	     
	     if(temp_user->desc != NULL)
	       free(temp_user->desc);
	     temp_user->desc = NULL;
	     
	     if(temp_user->buf != NULL)
	       free(temp_user->buf);
	     temp_user->buf = NULL;
	     
	     if(temp_user->outbuf != NULL)
	       free(temp_user->outbuf);
	     temp_user->outbuf = NULL;
	  }
	
	temp_user->type = NON_LOGGED;
	memset(temp_user->version, 0, MAX_VERSION_LEN+1);	    
	temp_user->con_type = 0;
	temp_user->flag = 0;
	temp_user->share = 0;
	temp_user->timeout = 0;
	
	temp_user->rem = 0;
	temp_user->key = 0;
	temp_user->last_search = (time_t)0;
	
	/* The sock won't be used in the script, so set it to 0.  */
	temp_user->sock = 0;
	
	/* Set the nick.  */
	strcpy(temp_user->nick, temp_nick);	     
	
	/* Add to hashtable.  */
	add_human_to_hash(temp_user);		     
   
	sscanf(buf + 10, "%50s %lu %120s %d %30[^ |]", temp_user->nick, 
	       &temp_user->ip, temp_user->hostname, &temp_user->type, 
	       temp_user->version);	
	return;
     }
   
   /* First argument */
   if(((i = cut_string(buf, '\005')) != -1)  /* Do we have a first argument? */
      && (*(buf+i+1) == '\005'))
     {
	temp = buf + i + 2;
	if(!(((i = cut_string(temp, '\005')) != -1) /* Do we not have a second argument? */
	     && (*(temp+i+1) == '\005')))
	  {	     
	     if((arg1 = malloc(sizeof(char) * (cut_string(temp, '|') + 2))) == NULL)
	       {
		  logprintf(1, "Error - In sub_to_script()/malloc(): ");
		  logerror(1, errno);
		  quit = 1;
		  return;
	       }
	     memset(arg1, 0, cut_string(temp, '|') + 1);
	     strncpy(arg1, temp, cut_string(temp, '|'));
	  }
	else /* We have a second argument. */
	  {	     	
	     if((arg1 = malloc(sizeof(char) * (cut_string(temp, '\005') + 2))) == NULL)
	       {
		  logprintf(1, "Error - In sub_to_script()/malloc(): ");
		  logerror(1, errno);
		  quit = 1;
		  return;
	       }
	     memset(arg1, 0, cut_string(temp, '\005') + 1);
	     strncpy(arg1, temp, cut_string(temp, '\005'));
	  
	     /* Second argument */
	     temp = temp + cut_string(temp, '\005') + 2;	 
	     if(!(((i = cut_string(temp, '\005')) != -1) /* Do we not have a third argument? */
		&& (*(temp+i+1) == '\005')))
	       {
		  if((arg2 = malloc(sizeof(char) * (cut_string(temp, '|') + 2))) == NULL)
		    {
		       logprintf(1, "Error - In sub_to_script()/malloc(): ");
		       logerror(1, errno);
		       quit = 1;
		       return;
		    }
		  memset(arg2, 0, cut_string(temp, '|') + 2);
		  strncpy(arg2, temp, cut_string(temp, '|'));
	       }
	     else /* We have a third argument */
	       {
		  if((arg2 = malloc(sizeof(char) * (cut_string(temp, '\005') + 2))) == NULL)
		    {
		       logprintf(1, "Error - In sub_to_script()/malloc(): ");
		       logerror(1, errno);
		       quit = 1;
		       return;
		    }
		  memset(arg2, 0, cut_string(temp, '\005') + 2);
		  strncpy(arg2, temp, cut_string(temp, '\005') + 1);

		  /* Third argument */
		  temp = temp + cut_string(temp, '\005') + 1;	 
		  if((arg3 = malloc(sizeof(char) * (cut_string(temp, '|') + 2))) == NULL)
		    {
		       logprintf(1, "Error - In sub_to_script()/malloc(): ");
		       logerror(1, errno);
		       quit = 1;
		       return;
		    }
		  memset(arg3, 0, cut_string(temp, '|') + 2);
		  strncpy(arg3, temp, cut_string(temp, '|'));
	       }
	  }
     }

   /* And call the sub.  */
     {
	dSP;
	
	ENTER;
	SAVETMPS;
	
	PUSHMARK(SP);	

      	/* These subs take three arguments:  */ 
	if(!strncmp(subname, "added_temp_ban", 14))
	  {
	     XPUSHs(sv_2mortal(newSVpvn(arg1, strlen(arg1))));
	     XPUSHs(sv_2mortal(newSVuv(atol(arg2))));
	     if(arg3 != NULL)
	       XPUSHs(sv_2mortal(newSVpvn(arg3, strlen(arg3))));
	  }
	else if(!strncmp(subname, "added_temp_allow", 16))
	  {
	     XPUSHs(sv_2mortal(newSVpvn(arg1, strlen(arg1))));
	     XPUSHs(sv_2mortal(newSVuv(atol(arg2))));
	     if(arg3 != NULL)
	       XPUSHs(sv_2mortal(newSVpvn(arg3, strlen(arg3))));
	  }
      	/* These subs take two arguments:  */ 
	else if(!strncmp(subname, "data_arrival", 12))
	  {
	     XPUSHs(sv_2mortal(newSVpvn(arg1, strlen(arg1))));
	     /* We'll have to add the pipe here, since we actually want it in 
	      * this argument. It looks a bit ugly, but it seems to be the best
	      * way since the pipe can't be used internally between processes.
	      * Maybe Open DC Hub shouldn't be using the flawed Direct Connect
	      * protocol between processes, but thats a _big_ todo...  */
	     strcat(arg2, "|");
	     XPUSHs(sv_2mortal(newSVpvn(arg2, strlen(arg2))));
	  }
	else if(!strncmp(subname, "added_multi_hub", 15))
	  {
	     XPUSHs(sv_2mortal(newSVpvn(arg1, strlen(arg1))));
	     XPUSHs(sv_2mortal(newSViv(atoi(arg2))));
	  }
	else if(!strncmp(subname, "added_perm_ban", 14))
	  {
	     XPUSHs(sv_2mortal(newSVpvn(arg1, strlen(arg1))));
	     if(arg2 != NULL)
	       XPUSHs(sv_2mortal(newSVpvn(arg2, strlen(arg2))));
	  }
	else if(!strncmp(subname, "added_perm_allow", 16))
	  {
	     XPUSHs(sv_2mortal(newSVpvn(arg1, strlen(arg1))));
	     if(arg2 != NULL)
	       XPUSHs(sv_2mortal(newSVpvn(arg2, strlen(arg2))));
	  }
	else if(!strncmp(subname, "added_perm_nickban", 18))
	  {
	     XPUSHs(sv_2mortal(newSVpvn(arg1, strlen(arg1))));
	  }
	else if(!strncmp(subname, "added_temp_nickban", 18))
	  {
	     XPUSHs(sv_2mortal(newSVpvn(arg1, strlen(arg1))));
	     XPUSHs(sv_2mortal(newSVuv(atol(arg2))));
	  }
	else if(!strncmp(subname, "kicked_user", 11))
	  {
	     XPUSHs(sv_2mortal(newSVpvn(arg1, strlen(arg1))));
	     XPUSHs(sv_2mortal(newSVpvn(arg2, strlen(arg2))));
	  }
	
	/* If it isn't the ones with no arguments or the ones with two, 
	 * it has one argument.  */
	else if(strncmp(subname, "started_serving", 15))
	  if(strncmp(subname, "hub_timer", 9))
	    XPUSHs(sv_2mortal(newSVpvn(arg1, strlen(arg1))));
	PUTBACK;
	
	call_pv(subname, G_DISCARD|G_EVAL);
	
	FREETMPS;
	LEAVE;
     }
   
   /* If it was user_disconnected, remove the user.  */
   if(!strncmp(subname, "user_disconnected", 17))
     {
	if((temp_user = get_human_user(arg1)) != NULL)
	  {
	     if(temp_user->buf != NULL)
	       {
		  free(temp_user->buf);
		  temp_user->buf = NULL;
	       }
	     if(temp_user->outbuf != NULL)
	       {
		  free(temp_user->outbuf);
		  temp_user->outbuf = NULL;
	       }
	     if(temp_user->email != NULL)
	       {
		  free(temp_user->email);
		  temp_user->email = NULL;
	       }
	     if(temp_user->desc != NULL)
	       {
		  free(temp_user->desc);
		  temp_user->desc = NULL;
	       }
	     remove_human_from_hash(temp_user->nick);
	     
	  }
     }
   
   if(arg1 != NULL)
     free(arg1);
   if(arg2 != NULL)
     free(arg2);
}

/* Sends data from a script to a user.  */
void script_to_user(char *buf, struct user_t *user)
{
   char command[21];
   char nick[MAX_NICK_LEN+1];
   struct user_t *to_user;
   
   sscanf(buf, "%20s %50s", command, nick);
   
   if((to_user = get_human_user(nick)) != NULL)
     send_to_user(buf + 14 + strlen(nick) + 1, to_user);
   else
     send_to_non_humans(buf, FORKED, user);
}   
   

#endif /* #ifdef HAVE_PERL  */
