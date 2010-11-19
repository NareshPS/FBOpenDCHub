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
#include <string.h>
#if HAVE_MALLOC_H
# include <malloc.h>
#endif
#include <ctype.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#if HAVE_CRYPT_H
# include <crypt.h>
#endif
#if HAVE_UNISTD_H
# include <unistd.h>
#endif
#if HAVE_FCNTL_H
# include <fcntl.h>
#endif
#include <sys/stat.h>
#include <sys/types.h>
#include <stdarg.h>
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
#include <errno.h>
#include <dirent.h>
#ifdef HAVE_SYSLOG_H
# include <syslog.h>
#endif
#ifdef SWITCH_USER
# include <pwd.h>
#endif

#include "main.h"
#include "utils.h"
#include "fileio.h"
#include "network.h"
#ifdef HAVE_PERL
# include "perl_utils.h"
#endif

#ifndef HAVE_STRTOLL
# ifdef HAVE_STRTOQ
#  define strtoll(X, Y, Z) (long long)strtoq(X, Y, Z)
# endif
#endif

/* Reads config file */
int read_config(void)
{
   int i, j;
   int fd;
   int erret;
   FILE *fp;
   char path[MAX_FDP_LEN+1];
   char line[1024];
   
   snprintf(path, MAX_FDP_LEN, "%s/%s", config_dir, CONFIG_FILE);
   
   while(((fd = open(path, O_RDONLY)) < 0) && (errno == EINTR))
     logprintf(1, "Error - In read_config()/open(): Interrupted system call. Trying again.\n");   
   
   if(fd < 0)
     {
	logprintf(1, "Error - In read_config()/open(): ");
	logerror(1, errno);
	return -1;	
     }
   	
   /* Set the lock */
   if(set_lock(fd, F_RDLCK) == 0)
     {
	logprintf(1, "Error - In read_config(): Couldn't set file lock\n");
	close(fd);
	return -1;
     }
   
   
   if((fp = fdopen(fd, "r")) == NULL)
     {
	logprintf(1, "Error - In read_config()/fdopen(): ");
	logerror(1, errno);
	set_lock(fd, F_UNLCK);
	close(fd);
	return -1;
     }
   
   while(fgets(line, 1023, fp) != NULL)
     {
	trim_string(line);
	
	j = strlen(line);
	if(j != 0)
	  {
	     /* Jump to next char which isn't a space */
	     i = 0;
	     while(line[i] == ' ')
	       i++;
	     
	     /* Name of the hub */
	     if(strncmp(line + i, "hub_name", 8) == 0)
	       {
		  if(strchr(line + i, '"') == NULL)
		    {
		       set_lock(fd, F_UNLCK);
		       while(((erret = fclose(fp)) != 0) && (errno == EINTR))
			 logprintf(1, "Error - In read_config()/fclose(): Interrupted system call. Trying again.\n");
		       
		       if(erret != 0)
			 {
			    logprintf(1, "Error - In read_config()/fclose(): ");
			    logerror(1, errno);
			    return -1;
			 }
		       
		       return -1;
		    }
		  strncpy(hub_name, strchr(line + i, '"') + 1, MAX_HUB_NAME);
		  if(*(hub_name + strlen(hub_name) - 1) == '"')
		    *(hub_name + strlen(hub_name) - 1) = '\0';
	       }
	     
	     /* Maximum hub users */
	     else if(strncmp(line + i, "max_users", 9) == 0)
	       {
		  while(!isdigit((int)line[i]))
		    i++;
		  max_users = atoi(line + i);
	       }
	     /* Number of users when fork occurs */
	     else if(strncmp(line + i, "users_per_fork", 14) == 0)
	       {
		  while(!isdigit((int)line[i]))
		    i++;
		  users_per_fork = atoi(line + i);
	       }
	     
	     /* The message displayed if hub is full */
	     else if(strncmp(line + i, "hub_full_mess", 13) == 0)
	       {
		  /* The string has to begin with a '"' at the same line */
		  if(strchr(line + i, '"') == NULL)
		    {
		       set_lock(fd, F_UNLCK);
		       		       
		       while(((erret = fclose(fp)) != 0) && (errno == EINTR))
			 logprintf(1, "Error - In read_config()/fclose(): Interrupted system call. Trying again.\n");
		       
		       if(erret != 0)
			 {
			    logprintf(1, "Error - In read_config()/fclose(): ");
			    logerror(1, errno);
			    return -1;
			 }
		       
		       return -1;
		    }
		  if((hub_full_mess = malloc(sizeof(char) 
		       * (strlen(line+i+1) + 1))) == NULL)
		    {
		       logprintf(1, "Error - In read_config()/malloc(): ");
		       logerror(1, errno);
		       quit = 1;
		       set_lock(fd, F_UNLCK);
		       fclose(fp);
		       return -1;
		    }
		  strcpy(hub_full_mess, strchr(line + i, '"') + 1);
		  while((line[strlen(line) - 1] != '"') && (fgets(line, 1023, fp) != NULL))
		    {		
		       trim_string(line);
		       if((hub_full_mess = realloc(hub_full_mess, sizeof(char) 
			* (strlen(hub_full_mess) + strlen(line) + 3))) == NULL)
			 {
			    logprintf(1, "Error - In read_config()/realloc(): ");
			    logerror(1, errno);
			    quit = 1;
			    set_lock(fd, F_UNLCK);
			    fclose(fp);
			    return -1;
			 }
		       sprintfa(hub_full_mess, "\r\n%s", line);
		    }
		  if(*(hub_full_mess + strlen(hub_full_mess) - 1) == '"')
		     *(hub_full_mess + strlen(hub_full_mess) - 1) = '\0';
	       }
	     
	     /* Description of hub. Sent to public hub list */
	     else if(strncmp(line + i, "hub_description", 15) == 0)
	       {
		  if(strchr(line + i, '"') == NULL)
		    {
		       set_lock(fd, F_UNLCK);
		       
		       while(((erret = fclose(fp)) != 0) && (errno == EINTR))
			 logprintf(1, "Error - In read_config()/fclose(): Interrupted system call. Trying again.\n");
		       
		       if(erret != 0)
			 {
			    logprintf(1, "Error - In read_config()/fclose(): ");
			    logerror(1, errno);
			    return -1;
			 }
		       
		       return -1;
		    }
		  strncpy(hub_description, strchr(line + i, '"') + 1, MAX_HUB_DESC);
		  if(*(hub_description + strlen(hub_description) - 1) == '"')
		    *(hub_description + strlen(hub_description) - 1) = '\0';
	       }
	     
	     /* Minimum share to allow a user access */
	     else if(strncmp(line + i, "min_share", 9) == 0)
	       {
		  while(!isdigit((int)line[i]))
		    i++;
		  min_share = strtoll(line + i, (char **)NULL, 10);
	       }
	     
	     /* Password for admin to log in via telnet */
	     else if(strncmp(line + i, "admin_pass", 10) == 0)
	       {
		  if(strchr(line + i, '"') == NULL)
		    {
		       set_lock(fd, F_UNLCK);
		         while(((erret = fclose(fp)) != 0) && (errno == EINTR))
			 logprintf(1, "Error - In read_config()/fclose(): Interrupted system call. Trying again.\n");
		       
		       if(erret != 0)
			 {
			    logprintf(1, "Error - In read_config()/fclose(): ");
			    logerror(1, errno);
			    return -1;
			 }
		       
		       return -1;
		    }
		  strncpy(admin_pass, strchr(line + i, '"') + 1, MAX_ADMIN_PASS_LEN);
		  if(*(admin_pass + strlen(admin_pass) - 1) == '"')
		    *(admin_pass + strlen(admin_pass) - 1) = '\0';
	       }

             /* Password for admin to log in via telnet */
             else if(strncmp(line + i, "default_pass", 12) == 0)
               {
                  if(strchr(line + i, '"') == NULL)
                    {
                       set_lock(fd, F_UNLCK);
                         while(((erret = fclose(fp)) != 0) && (errno == EINTR))
                         logprintf(1, "Error - In read_config()/fclose(): Interrupted system call. Trying again.\n");

                       if(erret != 0)
                         {
                            logprintf(1, "Error - In read_config()/fclose(): ");
                            logerror(1, errno);
                            return -1;
                         }

                       return -1;
                    }
                  strncpy(default_pass, strchr(line + i, '"') + 1, MAX_ADMIN_PASS_LEN);
                  if(*(default_pass + strlen(default_pass) - 1) == '"')
                    *(default_pass + strlen(default_pass) - 1) = '\0';
               }
	     
	     /* Password for hub linking */
	     else if(strncmp(line + i, "link_pass", 9) == 0)
	       {
		  if(strchr(line + i, '"') == NULL)
		    {
		       set_lock(fd, F_UNLCK);
		       while(((erret = fclose(fp)) != 0) && (errno == EINTR))
			 logprintf(1, "Error - In read_config()/fclose(): Interrupted system call. Trying again.\n");
		       
		       if(erret != 0)
			 {
			    logprintf(1, "Error - In read_config()/fclose(): ");
			    logerror(1, errno);
			    return -1;
			 }
		       
		       return -1;
		    }
		  strncpy(link_pass, strchr(line + i, '"') + 1, MAX_ADMIN_PASS_LEN);
		  if(*(link_pass + strlen(link_pass) - 1) == '"')
		    *(link_pass + strlen(link_pass) - 1) = '\0';
	       }
	     
	     /* The port the hub is listening on */
	     else if(strncmp(line + i, "listening_port", 14) == 0)
	       {
		  while(!isdigit((int)line[i]))
		    i++;
		  listening_port = (unsigned int)(atoi(line + i));
	       }
	     
	     /* Listening port for admin connections */
	      else if(strncmp(line + i, "admin_port", 10) == 0)
	       {
		  while(!isdigit((int)line[i]))
		    i++;
		  admin_port = atoi(line + i);
	       }
	     
	     /* Listening host for admin connections on localhost */
	     else if (strncmp(line + i, "admin_localhost", 15) == 0)
	       {
	          while(!isdigit((int)line[i]))
		    i++;
		  admin_localhost = atoi(line + i);
	       }

	     /* Public hub list host */
	     else if(strncmp(line + i, "public_hub_host", 15) == 0)
	       {
		  if(strchr(line + i, '"') == NULL)
		    {
		       set_lock(fd, F_UNLCK);
		       while(((erret = fclose(fp)) != 0) && (errno == EINTR))
			 logprintf(1, "Error - In read_config()/fclose(): Interrupted system call. Trying again.\n");
		       
		       if(erret != 0)
			 {
			    logprintf(1, "Error - In read_config()/fclose(): ");
			    logerror(1, errno);
			    return -1;
			 }
		       
		       return -1;
		    }
		  strncpy(public_hub_host, strchr(line + i, '"') + 1, 121);
		  if(*(public_hub_host + strlen(public_hub_host) - 1) == '"')
		    *(public_hub_host + strlen(public_hub_host) - 1) = '\0';
	       }
	     
	     /* Hostname to upload to public hublist */
	     else if(strncmp(line + i, "hub_hostname", 12) == 0)
	       {
		  if(strchr(line + i, '"') == NULL)
		    {
		       set_lock(fd, F_UNLCK);
		       
		       while(((erret = fclose(fp)) != 0) && (errno == EINTR))
			 logprintf(1, "Error - In read_config()/fclose(): Interrupted system call. Trying again.\n");
		       
		       if(erret != 0)
			 {
			    logprintf(1, "Error - In read_config()/fclose(): ");
			    logerror(1, errno);
			    return -1;
			 }
		       
		       return -1;
		    }
		  strncpy(hub_hostname, strchr(line + i, '"') + 1, 121);
		  if(*(hub_hostname + strlen(hub_hostname) - 1) == '"')
		    *(hub_hostname + strlen(hub_hostname) - 1) = '\0';
	       }
	     
	     /* Minimum client version */
	     else if(strncmp(line + i, "min_version", 11) == 0)
	       {
		  if(strchr(line + i, '"') == NULL)
		    {
		       set_lock(fd, F_UNLCK);
		       
		       while(((erret = fclose(fp)) != 0) && (errno == EINTR))
			 logprintf(1, "Error - In read_config()/fclose(): Interrupted system call. Trying again.\n");
		       
		       if(erret != 0)
			 {
			    logprintf(1, "Error - In read_config()/fclose(): ");
			    logerror(1, errno);
			    return -1;
			 }
		       
		       return -1;
		    }
		  strncpy(min_version, strchr(line + i, '"') + 1, 30);
		  if(*(min_version + strlen(min_version) - 1) == '"')
		    *(min_version + strlen(min_version) - 1) = '\0';
	       }
	     
	     /* 1 if hub should upload description to public hublist */
	      else if(strncmp(line + i, "hublist_upload", 14) == 0)
	       {
		  while(!isdigit((int)line[i]))
		    i++;
		  hublist_upload = atoi(line + i);
	       }
	     
	     /*  Host to redirect users if hub is full */
	     else if(strncmp(line + i, "redirect_host", 13) == 0)
	       {
		  if(strchr(line + i, '"') == NULL)
		    {
		       redirect_host[0] = '\0';
		       set_lock(fd, F_UNLCK);
		       
		       while(((erret = fclose(fp)) != 0) && (errno == EINTR))
			 logprintf(1, "Error - In read_config()/fclose(): Interrupted system call. Trying again.\n");
		       
		       if(erret != 0)
			 {
			    logprintf(1, "Error - In read_config()/fclose(): ");
			    logerror(1, errno);
			    return -1;
			 }
		       
		       return 1;
		    }
		  strncpy(redirect_host, strchr(line + i, '"') + 1, 121);
		  if(*(redirect_host + strlen(redirect_host) - 1) == '"')
		    *(redirect_host + strlen(redirect_host) - 1) = '\0';
	       }
	     
	     /* 1 for registered only mode */
	     else if(strncmp(line + i, "registered_only", 15) == 0)
	       {
		  while(!isdigit((int)line[i]))
		    i++;
		  registered_only = atoi(line + i);
	       }
	     
	      /* 1 for ban to override allow */
	     else if(strncmp(line + i, "ban_overrides_allow", 19) == 0)
	       {
		  while(!isdigit((int)line[i]))
		    i++;
		  ban_overrides_allow = atoi(line + i);
	       }
	     
	     /* 1 for validation of clients Keys */
	     else if(strncmp(line + i, "check_key", 9) == 0)
	       {
		  while(!isdigit((int)line[i]))
		    i++;
		  check_key = atoi(line + i);
	       }
	     
	       /* 1 for Reverse DNS lookups */
	     else if(strncmp(line + i, "reverse_dns", 11) == 0)
	       {
		  while(!isdigit((int)line[i]))
		    i++;
		  reverse_dns = atoi(line + i);
	       }
	     
	     /* 5 for all possible logging, 0 for no logging at all */
	     else if(strncmp(line + i, "verbosity", 9) == 0)
	       {
		  while(!isdigit((int)line[i]))
		    i++;
		  verbosity = atoi(line + i);
	       }
	     /* 1 if user should be redirected if he doesn't share enough */
	     else if(strncmp(line + i, "redir_on_min_share", 18) == 0)
	       {
		  while(!isdigit((int)line[i]))
		    i++;
		  redir_on_min_share = atoi(line + i);
	       }
	     /* 1 if logging should go to syslog instead */
	     else if(strncmp(line + i, "syslog_enable", 13) == 0)
	       {
		  while(!isdigit((int)line[i]))
		    i++;
		  syslog_enable = atoi(line + i);
	       }
	     /* 1 if search IP check should ignore internal IP addresses */
	     else if(strncmp(line + i, "searchcheck_exclude_internal", 28) == 0)
	       {
		  while(!isdigit((int)line[i]))
		    i++;
		  searchcheck_exclude_internal = atoi(line + i);
	       }
	     /* 1 if search IP check should be skipped altogether */
	     else if(strncmp(line + i, "searchcheck_exclude_all", 23) == 0)
	       {
		  while(!isdigit((int)line[i]))
		    i++;
		  searchcheck_exclude_all = atoi(line + i);
	       }
	     /* Number of minutes user should be banned for when kicked */
	     else if(strncmp(line + i, "kick_bantime", 12) == 0)
	       {
		  while(!isdigit((int)line[i]))
		    i++;
		  kick_bantime = atoi(line + i);
	       }
	     /* Min number of seconds between searches */
	     else if(strncmp(line + i, "searchspam_time", 15) == 0)
	       {
		  while(!isdigit((int)line[i]))
		    i++;
		  searchspam_time = atoi(line + i);
	       }
	     /* Max length of email addresses */
	     else if(strncmp(line + i, "max_email_len", 13) == 0)
	       {
		  while(!isdigit((int)line[i]))
		    i++;
		  max_email_len = atoi(line + i);
	       }
	     /* Max length of user descriptions */
	     else if(strncmp(line + i, "max_desc_len", 12) == 0)
	       {
		  while(!isdigit((int)line[i]))
		    i++;
		  max_desc_len = atoi(line + i);
	       }
	     /* Enable encrypted passwords? */
	     else if(strncmp(line + i, "crypt_enable", 12) == 0)
	       {
		  while(!isdigit((int)line[i]))
		    i++;
		 crypt_enable = atoi(line + i);
	       }
	  }
     }
   set_lock(fd, F_UNLCK);
   
   while(((erret = fclose(fp)) != 0) && (errno == EINTR))
     logprintf(1, "Error - In read_config()/fclose(): Interrupted system call. Trying again.\n");
   
   if(erret != 0)
     {
	logprintf(1, "Error - In read_config()/fclose(): ");
	logerror(1, errno);
	return -1;
     }
   
   return 1;
}

/* Creates banlist if it does not exist */
void create_banlist(void)
{
   FILE *fp;
   int fd;
   int erret;
   char path[MAX_FDP_LEN+1];
   
   snprintf(path, MAX_FDP_LEN, "%s/%s", config_dir, BAN_FILE);
   
   while(((fd = open(path, O_RDONLY)) < 0) && (errno == EINTR))
     logprintf(1, "Error - In create_banlist()/open(): Interrupted system call. Trying again.\n"); 
   
   if(fd >= 0)
     {
	/* Banlist already exists */
	close(fd);
	return;
     }
   
   while(((fd = open(path, O_RDWR | O_CREAT, 0600)) < 0) && (errno == EINTR))
     logprintf(1, "Error - In create_banlist()/open(): Interrupted system call. Trying again.\n");
   
   if(fd < 0)
     {
	logprintf(1, "Error - In create_banlist()/open(): ");
	logerror(1, errno);
	return;
     }
   
   /* Set the lock */
   if(set_lock(fd, F_WRLCK) == 0)
     {
	logprintf(1, "Error - In create_ban_list(): Couldn't set lock\n");
	close(fd);
	return;
     }
   
   if((fp = fdopen(fd, "a")) == NULL)
     {
	logprintf(1, "Error - In create_ban_list()/fdopen(): ");
	logerror(1, errno);
	set_lock(fd, F_UNLCK);
	close(fd);
	return;
     }
   
   logprintf(1, "Created banlist\n");
   set_lock(fd, F_UNLCK);
   
   while(((erret = fclose(fp)) != 0) && (errno == EINTR))
     logprintf(1, "Error - In create_banlist()/fclose(): Interrupted system call. Trying again.\n");
   
   if(erret != 0)
     {
	logprintf(1, "Error - In create_banlist()/fclose(): ");
	logerror(1, errno);
     }
}

/* Creates nickbanlist if it does not exist */
void create_nickbanlist(void)
{
   FILE *fp;
   int fd;
   int erret;
   char path[MAX_FDP_LEN+1];
   
   snprintf(path, MAX_FDP_LEN, "%s/%s", config_dir, NICKBAN_FILE);
   
   while(((fd = open(path, O_RDONLY)) < 0) && (errno == EINTR))
     logprintf(1, "Error - In create_nickbanlist()/open(): Interrupted system call. Trying again.\n"); 
   
   if(fd >= 0)
     {
	/* Nickbanlist already exists */
	close(fd);
	return;
     }
   
   while(((fd = open(path, O_RDWR | O_CREAT, 0600)) < 0) && (errno == EINTR))
     logprintf(1, "Error - In create_nickbanlist()/open(): Interrupted system call. Trying again.\n");
   
   if(fd < 0)
     {
	logprintf(1, "Error - In create_nickbanlist()/open(): ");
	logerror(1, errno);
	return;
     }
   
   /* Set the lock */
   if(set_lock(fd, F_WRLCK) == 0)
     {
	logprintf(1, "Error - In create_nickbanlist(): Couldn't set lock\n");
	close(fd);
	return;
     }
   
   if((fp = fdopen(fd, "a")) == NULL)
     {
	logprintf(1, "Error - In create_nickbanlist()/fdopen(): ");
	logerror(1, errno);
	set_lock(fd, F_UNLCK);
	close(fd);
	return;
     }
   
   logprintf(1, "Created nickbanlist\n");
   set_lock(fd, F_UNLCK);
   
   while(((erret = fclose(fp)) != 0) && (errno == EINTR))
     logprintf(1, "Error - In create_nickbanlist()/fclose(): Interrupted system call. Trying again.\n");
   
   if(erret != 0)
     {
	logprintf(1, "Error - In create_nickbanlist()/fclose(): ");
	logerror(1, errno);
     }
}

/* Creates allowlist if it does not exist */
void create_allowlist(void)
{
   FILE *fp;
   int fd;
   int erret;
   char path[MAX_FDP_LEN+1];
   
   snprintf(path, MAX_FDP_LEN, "%s/%s", config_dir, ALLOW_FILE);
   
   while(((fd = open(path, O_RDONLY)) < 0) && (errno == EINTR))
     logprintf(1, "Error - In create_allowlist()/open(): Interrupted system call. Trying again.\n"); 
   
   if(fd >= 0)
     {
	/* Allowlist already exists */
	close(fd);
	return;
     }
   
   while(((fd = open(path, O_RDWR | O_CREAT, 0600)) < 0) && (errno == EINTR))
     logprintf(1, "Error - In create_allowlist()/open(): Interrupted system call. Trying again.\n");
   
   if(fd < 0)
     {
	logprintf(1, "Error - In create_allowlist()/open(): ");
	logerror(1, errno);
	return;
     }
   
   /* Set the lock */
   if(set_lock(fd, F_WRLCK) == 0)
     {
	logprintf(1, "Error - In create_allowlist(): Couldn't set file lock\n");
	close(fd);
	return;
     }
   
   if((fp = fdopen(fd, "a")) == NULL)
     {
	logprintf(1, "Error - In create_allowlist()/fdopen(): ");
	logerror(1, errno);
	set_lock(fd, F_UNLCK);
	close(fd);
	return;
     }
   
   logprintf(1, "Created allowlist\n");
   set_lock(fd, F_UNLCK);
   while(((erret = fclose(fp)) != 0) && (errno == EINTR))
     logprintf(1, "Error - In create_allowlist()/fclose(): Interrupted system call. Trying again.\n");
   
   if(erret != 0)
     {
	logprintf(1, "Error - In create_allowlist()/fclose(): ");
	logerror(1, errno);
     }
}

/* Creates reglist if it does not exist */
void create_reglist(void)
{
   FILE *fp;
   int fd;
   int erret;
   char path[MAX_FDP_LEN+1];
   
   snprintf(path, MAX_FDP_LEN, "%s/%s", config_dir, REG_FILE);
   
   while(((fd = open(path, O_RDONLY)) < 0) && (errno == EINTR))
     logprintf(1, "Error - In create_reglist()/open(): Interrupted system call. Trying again.\n"); 
   
   if(fd >= 0)
     {
	/* Reglist already exists */
	close(fd);
	return;
     }
   
   while(((fd = open(path, O_RDWR | O_CREAT, 0600)) < 0) && (errno == EINTR))
     logprintf(1, "Error - In create_reglist()/open(): Interrupted system call. Trying again.\n");
   
   if(fd < 0)
     {
	logprintf(1, "Error - In create_reglist()/open(): ");
	logerror(1, errno);
	return;
     }
   
   /* Set the lock */
   if(set_lock(fd, F_WRLCK) == 0)
     {
	logprintf(1, "Error - In create_reglist(): Couldn't set file lock\n");
	close(fd);
	return;
     }
   
   if((fp = fdopen(fd, "a")) == NULL)
     {
	logprintf(1, "Error - In create_reglist()/fdopen(): ");
	logerror(1, errno);
	set_lock(fd, F_UNLCK);
	close(fd);
	return;
     }

   logprintf(1, "Created reg list\n");
   set_lock(fd, F_UNLCK);
   while(((erret = fclose(fp)) != 0) && (errno == EINTR))
     logprintf(1, "Error - In create_reglist()/fclose(): Interrupted system call. Trying again.\n");
   
   if(erret != 0)
     {
	logprintf(1, "Error - In create_reglist()/fclose(): ");
	logerror(1, errno);
     }
}

/* Creates op_permlist if it does not exist */
void create_op_permlist(void)
{
   FILE *fp;
   int fd;
   int erret;
   char path[MAX_FDP_LEN+1];
   
   snprintf(path, MAX_FDP_LEN, "%s/%s", config_dir, OP_PERM_FILE);
   
   while(((fd = open(path, O_RDONLY)) < 0) && (errno == EINTR))
     logprintf(1, "Error - In create_op_permlist()/open(): Interrupted system call. Trying again.\n"); 
   
   if(fd >= 0)
     {
	/* Op permlist already exists */
	close(fd);
	return;
     }
   
   while(((fd = open(path, O_RDWR | O_CREAT, 0600)) < 0) && (errno == EINTR))
     logprintf(1, "Error - In create_op_permlist()/open(): Interrupted system call. Trying again.\n");
   
   if(fd < 0)
     {
	logprintf(1, "Error - In create_op_permlist()/open(): ");
	logerror(1, errno);
	return;
     }
   
   /* Set the lock */
   if(set_lock(fd, F_WRLCK) == 0)
     {
	logprintf(1, "Error - In create_op_permlist(): Couldn't set file lock\n");
	close(fd);
	return;
     }
   
   if((fp = fdopen(fd, "a")) == NULL)
     {
	logprintf(1, "Error - In create_op_permlist()/fdopen(): ");
	logerror(1, errno);
	set_lock(fd, F_UNLCK);
	close(fd);
	return;
     }

   logprintf(1, "Created op perm list\n");
   set_lock(fd, F_UNLCK);
   
   while(((erret = fclose(fp)) != 0) && (errno == EINTR))
     logprintf(1, "Error - In create_op_permlist()/fclose(): Interrupted system call. Trying again.\n");
   
   if(erret != 0)
     {
	logprintf(1, "Error - In create_op_permlist()/fclose(): ");
	logerror(1, errno);
     }
}

/* Creates linklist if it does not exist */
void create_linklist(void)
{
   FILE *fp;
   int fd;
   int erret;
   char path[MAX_FDP_LEN+1];
   
   snprintf(path, MAX_FDP_LEN, "%s/%s", config_dir, LINK_FILE);
   
   while(((fd = open(path, O_RDONLY)) < 0) && (errno == EINTR))
     logprintf(1, "Error - In create_linklist()/open(): Interrupted system call. Trying again.\n"); 
   
   if(fd >= 0)
     {
	/* Linklist already exists */
	close(fd);
	return;
     }
   
   while(((fd = open(path, O_RDWR | O_CREAT, 0600)) < 0) && (errno == EINTR))
     logprintf(1, "Error - In create_linklist()/open(): Interrupted system call. Trying again.\n");
   
   if(fd < 0)
     {
	logprintf(1, "Error - In create_linklist()/open(): ");
	logerror(1, errno);
	return;
     }
   
   /* Set the lock */
   if(set_lock(fd, F_WRLCK) == 0)
     {
	logprintf(1, "Error - In create_linklist(): Couldn't set file lock\n");
	close(fd);
	return;
     }
   
   if((fp = fdopen(fd, "a")) == NULL)
     {
	logprintf(1, "Error - In create_linklist()/fdopen(): ");
	logerror(1, errno);
	set_lock(fd, F_UNLCK);
	close(fd);
	return;
     }
   
   logprintf(1, "Created link list\n");
   set_lock(fd, F_UNLCK);
   
   while(((erret = fclose(fp)) != 0) && (errno == EINTR))
     logprintf(1, "Error - In create_linklist()/fclose(): Interrupted system call. Trying again.\n");
   
   if(erret != 0)
     {
	logprintf(1, "Error - In create_linklist()/fclose(): ");
	logerror(1, errno);
     }
}

/* Returns 1 if user is on the banlist.  */
int check_if_banned(struct user_t *user, int type)
{
   int i, j;
   int fd;
   int erret;
   FILE *fp;
   char path[MAX_FDP_LEN+1];
   char line[1024];
   char ban_host[MAX_HOST_LEN+1];
   char *string_ip = NULL;
   unsigned long userip = 0;
   unsigned long fileip = 0;
   int byte1, byte2, byte3, byte4, mask;
   time_t ban_time;
   time_t now_time;
   
   if(type == BAN)
	snprintf(path, MAX_FDP_LEN, "%s/%s", config_dir, BAN_FILE);
   else if(type == NICKBAN)
	snprintf(path, MAX_FDP_LEN, "%s/%s", config_dir, NICKBAN_FILE);
   else
	return -1;
   	
   while(((fd = open(path, O_RDONLY)) < 0) && (errno == EINTR))
     logprintf(1, "Error - In check_if_banned()/open(): Interrupted system call. Trying again.\n");   
   
   if(fd < 0)
     {
	logprintf(1, "Error - In check_if_banned()/open(): ");
	logerror(1, errno);
	return -1;	
     }
   
   /* Set the lock */
   if(set_lock(fd, F_RDLCK) == 0)
     {
	logprintf(1, "Error - In check_if_banned(): Couldn't set file lock\n");
	close(fd);
	return -1;
     }   
   
   if((fp = fdopen(fd, "r")) == NULL)
     {
	logprintf(1, "Error - In check_if_banned()/fdopen(): ");
	logerror(1, errno);
	set_lock(fd, F_UNLCK);
	close(fd);
	return -1;
     }
   
   now_time = time(NULL);
   
   if(type == BAN)
     {	
	if((string_ip = ip_to_string(user->ip)) == NULL)
	  {
	     set_lock(fd, F_UNLCK);
	     
	     while(((erret = fclose(fp)) != 0) && (errno == EINTR))
	       logprintf(1, "Error - In check_if_banned()/fclose(): Interrupted system call. Trying again.\n");
	     
	     if(erret != 0)
	       {
		  logprintf(1, "Error - In check_if_banned()/fclose(): ");
		  logerror(1, errno);
		  return -1;
	       }
   
	     return 0;
	  }
	userip = ntohl(user->ip);
     }
   
   while(fgets(line, 1023, fp) != NULL)
     {
	trim_string(line);
	ban_time = 0;
	
	j = strlen(line);
	if(j != 0)
	  {
	     /* Jump to next char which isn't a space */
	     i = 0;
	     while(line[i] == ' ')
	       i++;
	     
	     sscanf(line+i, "%120s %lu", ban_host, &ban_time);
	     if(type == BAN)
	       {		  
		  /* Check if it's part of user's ip */
		  /* First, check if it's a subnet.  */
		  if((sscanf(ban_host, "%d.%d.%d.%d/%d", 
			     &byte1, &byte2, &byte3, &byte4, &mask) == 5)
		     && (mask > 0) && (mask <= 32))
		    {
		       fileip = (byte1<<24) | (byte2<<16) | (byte3<<8) | byte4;
		       if((((0xFFFF << (32-mask)) & userip) 
			   == ((0xFFFF << (32-mask)) & fileip))
			  && ((ban_time == 0) || (ban_time > now_time)))
			 {
			    set_lock(fd, F_UNLCK);
			    
			    while(((erret = fclose(fp)) != 0) && (errno == EINTR))
			      logprintf(1, "Error - In check_if_banned()/fclose(): Interrupted system call. Trying again.\n");
			    
			    if(erret != 0)
			      {
				 logprintf(1, "Error - In check_if_banned()/fclose(): ");
				 logerror(1, errno);
				 return -1;
			      }
			  
			    return 1;
			 }
		    }
		  /* If not, it has to be an exact match.  */
		  else if((strncmp(string_ip, ban_host, strlen(ban_host)) == 0)
			  && (strlen(ban_host) == strlen(string_ip))
			  && ((ban_time == 0) || (ban_time > now_time)))
		    {
		       set_lock(fd, F_UNLCK);
		       
		       while(((erret = fclose(fp)) != 0) && (errno == EINTR))
			 logprintf(1, "Error - In check_if_banned()/fclose(): Interrupted system call. Trying again.\n");
		       
		       if(erret != 0)
			 {
			    logprintf(1, "Error - In check_if_banned()/fclose(): ");
			    logerror(1, errno);
			    return -1;
			 }
		      
		       return 1;
	            }
		  
		  /* Check if users hostname is banned.  */
		  if((user->hostname != NULL)
		     && (strncmp(user->hostname, string_ip, strlen(string_ip)) != 0))
		    {
		       if(match_with_wildcards(user->hostname, ban_host) != 0)
			 {
			    set_lock(fd, F_UNLCK);
			    
			    while(((erret = fclose(fp)) != 0) && (errno == EINTR))
			      logprintf(1, "Error - In check_if_banned()/fclose(): Interrupted system call. Trying again.\n");
			    
			    if(erret != 0)
			      {
				 logprintf(1, "Error - In check_if_banned()/fclose(): ");
				 logerror(1, errno);
				 return -1;
			      }
			    
			    return 1;
			 }
		    }		       
	       }	     
	     else
	       {
		  /* Check if a nickname is banned.  */
		  if(((ban_time == 0) || (ban_time > now_time))
		     && (match_with_wildcards(user->nick, ban_host) != 0))
		    {
		       set_lock(fd, F_UNLCK);
		       while(((erret = fclose(fp)) != 0) && (errno == EINTR))
			 logprintf(1, "Error - In check_if_banned()/fclose(): Interrupted system call. Trying again.\n");
		       
		       if(erret != 0)
			 {
			    logprintf(1, "Error - In check_if_banned()/fclose(): ");
			    logerror(1, errno);
			    return -1;
			 }
		       
		       return 1;
		    }
	       }	
          }
     }
   set_lock(fd, F_UNLCK);
   
   while(((erret = fclose(fp)) != 0) && (errno == EINTR))
     logprintf(1, "Error - In check_if_banned()/fclose(): Interrupted system call. Trying again.\n");
   
   if(erret != 0)
     {
	logprintf(1, "Error - In check_if_banned()/fclose(): ");
	logerror(1, errno);
	return -1;
     }
   
   return 0;
}

/* Returns 1 if user is on the allowlist.  */
int check_if_allowed(struct user_t *user)
{
   int i, j;
   int fd;
   int erret;
   FILE *fp;
   char path[MAX_FDP_LEN+1];
   char line[1024];
   char allow_host[MAX_HOST_LEN+1];
   char *string_ip = NULL;
   unsigned long userip = 0;
   unsigned long fileip = 0;
   int byte1, byte2, byte3, byte4, mask;
   time_t allow_time;
   time_t now_time;
   
   snprintf(path, MAX_FDP_LEN, "%s/%s", config_dir, ALLOW_FILE);
   
   while(((fd = open(path, O_RDONLY)) < 0) && (errno == EINTR))
     logprintf(1, "Error - In check_if_allowed()/open(): Interrupted system call. Trying again.\n");   
   
   if(fd < 0)
     {
	logprintf(1, "Error - In check_if_allowed()/open(): ");
	logerror(1, errno);
	return -1;	
     }
   
   /* Set the lock */
   if(set_lock(fd, F_RDLCK) == 0)
     {
	logprintf(1, "Error - In check_if_allowed(): Couldn't set file lock\n");
	close(fd);
	return -1;
     }
   
   if((fp = fdopen(fd, "r")) == NULL)
     {
	logprintf(1, "Error - In check_if_allowed()/fdopen(): ");
	logerror(1, errno);
	set_lock(fd, F_UNLCK);
	close(fd);
	return -1;
     }
   
   now_time = time(NULL);
   
   if((string_ip = ip_to_string(user->ip)) == NULL)
     {
	set_lock(fd, F_UNLCK);
	
	while(((erret = fclose(fp)) != 0) && (errno == EINTR))
	  logprintf(1, "Error - In check_if_allowed()/fclose(): Interrupted system call. Trying again.\n");
	
	if(erret != 0)
	  {
	     logprintf(1, "Error - In check_if_allowed()/fclose(): ");
	     logerror(1, errno);
	     return -1;
	  }
      
	return 0;
     }
   userip = ntohl(user->ip);   
   
   while(fgets(line, 1023, fp) != NULL)
     {
	trim_string(line);
	allow_time = 0;
	
	j = strlen(line);
	if(j != 0)
	  {
	     /* Jump to next char which isn't a space */
	     i = 0;
	     while(line[i] == ' ')
	       i++;
	     
	     sscanf(line+i, "%120s %lu", allow_host, &allow_time);
	     	  		  
	     /* Check if it's part of user's ip */
	     /* First, check if it's a subnet.  */
	     if((sscanf(allow_host, "%d.%d.%d.%d/%d", 
			&byte1, &byte2, &byte3, &byte4, &mask) == 5)
		&& (mask > 0) && (mask <= 32))
	       {
		  fileip = (byte1<<24) | (byte2<<16) | (byte3<<8) | byte4;
		  if((((0xFFFF << (32-mask)) & userip) 
		      == ((0xFFFF << (32-mask)) & fileip)) 
		     && ((allow_time == 0) || (allow_time > now_time)))
		    {
		       set_lock(fd, F_UNLCK);
		       
		       while(((erret = fclose(fp)) != 0) && (errno == EINTR))
			 logprintf(1, "Error - In check_if_allowed()/fclose(): Interrupted system call. Trying again.\n");
		       
		       if(erret != 0)
			 {
			    logprintf(1, "Error - In check_if_allowed()/fclose(): ");
			    logerror(1, errno);
			    return -1;
			 }
		       
		       return 1;
		    }
	       }
	     
	     /* If not, it has to be an exact match.  */
	     else if((strncmp(string_ip, allow_host, strlen(allow_host)) == 0)
		     && (strlen(allow_host) == strlen(string_ip))
		     &&((allow_time == 0) || (allow_time > now_time)))
	       {
		  set_lock(fd, F_UNLCK);
		  
		  while(((erret = fclose(fp)) != 0) && (errno == EINTR))
		    logprintf(1, "Error - In check_if_allowed()/fclose(): Interrupted system call. Trying again.\n");
		  
		  if(erret != 0)
		    {
		       logprintf(1, "Error - In check_if_allowed()/fclose(): ");
		       logerror(1, errno);
		       return -1;
		    }
		  
		  return 1;
	       }
	     
	     /* Check users hostname is allowed.  */
	     if((user->hostname != NULL)
		&& (strncmp(user->hostname, string_ip, strlen(string_ip)) != 0))
	       {
		  if(match_with_wildcards(user->hostname, allow_host) != 0)
		    {
		       set_lock(fd, F_UNLCK);
		       
		       while(((erret = fclose(fp)) != 0) && (errno == EINTR))
			 logprintf(1, "Error - In check_if_allowed()/fclose(): Interrupted system call. Trying again.\n");
		       
		       if(erret != 0)
			 {
			    logprintf(1, "Error - In check_if_allowed()/fclose(): ");
			    logerror(1, errno);
			    return -1;
			 }
		       
		       return 1;
		    }
	       }	
	  }	
     }
   
   set_lock(fd, F_UNLCK);
   while(((erret = fclose(fp)) != 0) && (errno == EINTR))
     logprintf(1, "Error - In check_if_allowed()/fclose(): Interrupted system call. Trying again.\n");
   
   if(erret != 0)
     {
	logprintf(1, "Error - In check_if_allowed()/fclose(): ");
	logerror(1, errno);
	return -1;
     }
   
   return 0;
}

/* Returns 1 if a nick is on the registered list, 2 if nick is op and 3 if 
 * user is op_admin.  */
int check_if_registered(char *user_nick)
{
   int i, j;
   int fd;
   int erret;
   FILE *fp;
   char path[MAX_FDP_LEN+1];
   char line[1024];
   
   snprintf(path, MAX_FDP_LEN, "%s/%s", config_dir, REG_FILE);
   
   while(((fd = open(path, O_RDONLY)) < 0) && (errno == EINTR))
     logprintf(1, "Error - In check_if_registered()/open(): Interrupted system call. Trying again.\n");   
   
   if(fd < 0)
     {
	logprintf(1, "Error - In check_if_registered()/open(): ");
	logerror(1, errno);
	return -1;	
     }
   
   /* Set the lock */
   if(set_lock(fd, F_RDLCK) == 0)
     {
	logprintf(1, "Error - In check_if_registered(): Couldn't set lock\n");
	close(fd);
	return -1;
     }
   
   
   if((fp = fdopen(fd, "r")) == NULL)
     {
	logprintf(1, "Error - In check_if_registered()/fdopen(): ");
	logerror(1, errno);
	set_lock(fd, F_UNLCK);
	close(fd);
	return -1;
     }
   
   while(fgets(line, 1023, fp) != NULL)
     {
	trim_string(line);
	
	j = strlen(line);
	if(j != 0)
	  {
	     /* Jump to next char which isn't a space */
	     i = 0;
	     while(line[i] == ' ')
	       i++;
	     
	     if((strncasecmp(line + i, user_nick, cut_string(line + i, ' ')) == 0)
		&& (cut_string(line + i, ' ') == strlen(user_nick)))
	       {
		  set_lock(fd, F_UNLCK);
		  
		  while(((erret = fclose(fp)) != 0) && (errno == EINTR))
		    logprintf(1, "Error - In check_if_registered()/fclose(): Interrupted system call. Trying again.\n");
		  
		  if(erret != 0)
		    {
		       logprintf(1, "Error - In check_if_registered()/fclose(): ");
		       logerror(1, errno);
		       return -1;
		    }
		  
		  /* Return 3 if user is op admin */
		  if(line[j-1] == '2')
		    return 3;
		  
		  /* Return 2 if user is op */
		  if(line[j-1] == '1')
		    return 2;
		  return 1;
	       }
	  }
     }
   set_lock(fd, F_UNLCK);
   
   while(((erret = fclose(fp)) != 0) && (errno == EINTR))
     logprintf(1, "Error - In check_if_registered()/fclose(): Interrupted system call. Trying again.\n");
   
   if(erret != 0)
     {
	logprintf(1, "Error - In check_if_registered()/fclose(): ");
	logerror(1, errno);
	return -1;
     }
   
   return 0;
}

/* Returns 0 if user is not on the list, 2 if user is registered, 3 if user
 * is OP, 4 if user is Op Admin and -1 if error */
int check_pass(char *buf, struct user_t *user)
{
   int i, j;
   int fd;
   int erret;
   FILE *fp;
   char path[MAX_FDP_LEN+1];
   char line[1024];
   char reg_passwd[51];
   char this_passwd[51];
   char* tmp;
   
   strncpy(this_passwd,buf,50);
   this_passwd[strlen(this_passwd)-1] = '\0';	
   
   snprintf(path, MAX_FDP_LEN, "%s/%s", config_dir, REG_FILE);
   
   while(((fd = open(path, O_RDONLY)) < 0) && (errno == EINTR))
     logprintf(1, "Error - In check_pass()/open(): Interrupted system call. Trying again.\n");   
   
   if(fd < 0)
     {
	logprintf(1, "Error - In check_pass()/open(): ");
	logerror(1, errno);
	return -1;	
     }
   
   /* Set the lock */
   if(set_lock(fd, F_RDLCK) == 0)
     {	
	logprintf(1, "Error - In check_pass(): Couldn't set file lock\n");
	close(fd);
	return -1;
     }      
   
   if((fp = fdopen(fd, "r")) == NULL)
     {
	logprintf(1, "Error - In check_pass()/fdopen(): ");
	logerror(1, errno);
	set_lock(fd, F_UNLCK);
	close(fd);
	return -1;
     }
   
   while(fgets(line, 1023, fp) != NULL)
     {
	trim_string(line);
	
	j = strlen(line);
	if(j != 0)
	  {
	     /* Jump to next char which isn't a space */
	     i = 0;
	     while(line[i] == ' ')
	       i++;
	     
	     if((strncasecmp(line + i, user->nick, cut_string(line + i, ' ')) == 0)
		&& (cut_string(line + i, ' ') == strlen(user->nick)))
	       {
		  /* User is on the list */
		  if((i = cut_string(line + i, ' ')) == -1)
		    {
		       logprintf(1, "Error - In check_pass(): Erroneous line in file\n");
		       set_lock(fd, F_UNLCK);
		       
		       while(((erret = fclose(fp)) != 0) && (errno == EINTR))
			 logprintf(1, "Error - In check_pass()/fclose(): Interrupted system call. Trying again.\n");
		       
		       if(erret != 0)
			 {
			    logprintf(1, "Error - In check_pass()/fclose(): ");
			    logerror(1, errno);
			    return -1;
			 }
		       
		       return -1;
		    }
	    		  
		  while(line[i] == ' ')
		    i++;
		  if(line[i] == '\0')
		    {
		       logprintf(1, "Error - In check_pass(): Erroneous line in file\n");
		       set_lock(fd, F_UNLCK);
		       
		       while(((erret = fclose(fp)) != 0) && (errno == EINTR))
			 logprintf(1, "Error - In check_pass()/fclose(): Interrupted system call. Trying again.\n");
		       
		       if(erret != 0)
			 {
			    logprintf(1, "Error - In check_pass()/fclose(): ");
			    logerror(1, errno);
			    return -1;
			 }
		       
		       return -1;
		    }
		  if((j = i + cut_string(line + i, ' ')) == -1)
		    {
		       logprintf(1, "Error - In check_pass(): Erroneous line in file\n");
		       set_lock(fd, F_UNLCK);
		       
		       while(((erret = fclose(fp)) != 0) && (errno == EINTR))
			 logprintf(1, "Error - In check_pass()/fclose(): Interrupted system call. Trying again.\n");
		       
		       if(erret != 0)
			 {
			    logprintf(1, "Error - In check_pass()/fclose(): ");
			    logerror(1, errno);
			    return -1;
			 }
		       
		       return -1;
		    }
		  
		  /* The password check. */

		  strncpy(reg_passwd,line+i,50);
		  reg_passwd[strlen(reg_passwd)-2] = '\0';

		  if(crypt_enable != 0)
		    tmp = crypt(this_passwd,reg_passwd);
		  else
		    tmp = this_passwd;

		  if(strcmp(tmp,reg_passwd) == 0) 
		    {
		       /* Users password is correct */

		       set_lock(fd, F_UNLCK);
		       
		       while(((erret = fclose(fp)) != 0) && (errno == EINTR))
			 logprintf(1, "Error - In check_pass()/fclose(): Interrupted system call. Trying again.\n");
		       
		       if(erret != 0)
			 {
			    logprintf(1, "Error - In check_pass()/fclose(): ");
			    logerror(1, errno);
			    return -1;
			 }
		       	 
		       while(line[j] == ' ')
			 j++;
		       if(line[j] == '2')
			 {
			    /* User is OP Admin */
			    return 4;
			 }
		       else if(line[j] == '1')
			 {
			    /* User is OP */
			    return 3;
			 }
		       else if(line[j] == '0')
			 {
			    /* User is registered */
			    return 2;
			 }
		       else
			 {
			    logprintf(1, "Error - In check_pass(): Erroneous line in file\n");
			    return -1;
			 }
		    }
		  else
		    {
		       logprintf(1, "User at %s provided bad password for %s\n", user->hostname, user->nick);
		       set_lock(fd, F_UNLCK);
		       
		       while(((erret = fclose(fp)) != 0) && (errno == EINTR))
			 logprintf(1, "Error - In check_pass()/fclose(): Interrupted system call. Trying again.\n");
		       
		       if(erret != 0)
			 {
			    logprintf(1, "Error - In check_pass()/fclose(): ");
			    logerror(1, errno);
			    return -1;
			 }
		       
		       return 0;
		    }
	       }
	  }
     }
  
   while(((erret = fclose(fp)) != 0) && (errno == EINTR))
     logprintf(1, "Error - In check_pass()/fclose(): Interrupted system call. Trying again.\n");
   
   if(erret != 0)
     {
	logprintf(1, "Error - In check_pass()/fclose(): ");
	logerror(1, errno);
	return -1;
     }
 
   if(strlen(default_pass) > 0)
     {
        if(strcmp(this_passwd,default_pass) == 0)
          {
            /* User is regular but default pass required */
            return 1;
          }
        else
	  {
            return 0;
          }
     }
 
   return -1;
}

int get_permissions(char *user_nick)
{
   FILE *fp;
   int fd;
   int erret;
   int perms = 0;
   char path[MAX_FDP_LEN+1];
   char line[1024];
   int i,j;
   
   snprintf(path, MAX_FDP_LEN, "%s/%s", config_dir, OP_PERM_FILE);
   
   while(((fd = open(path, O_RDONLY)) < 0) && (errno == EINTR))
     logprintf(1, "Error - In get_permissions()/open(): Interrupted system call. Trying again.\n");   
   
   if(fd < 0)
     {
	logprintf(1, "Error - In get_permissions()/open(): ");
	logerror(1, errno);
	return -1;	
     }
   
   /* Set the lock */
   if(set_lock(fd, F_RDLCK) == 0)
     {
	logprintf(1, "Error - In get_permissions(): Couldn't set file lock\n");
	close(fd);
	return -1;
     }
   
   if((fp = fdopen(fd, "r")) == NULL)
     {
	logprintf(1, "Error - In get_permissions()/fdopen(): ");
	logerror(1, errno);
	set_lock(fd, F_UNLCK);
	close(fd);
	return -1;
     }
   
   while(fgets(line, 1023, fp) != NULL)
     {
	trim_string(line);
	
	j = strlen(line);
	if(j != 0)
	  {
	     /* Jump to next char which isn't a space */
	     i = 0;
	     while(line[i] == ' ')
	       i++;
	     
	     if((strncasecmp(line + i, user_nick, cut_string(line + i, ' ')) == 0)
		&& (cut_string(line + i, ' ') == strlen(user_nick)))
	       {
		  /* User is on the list */
		  if((i = cut_string(line + i, ' ')) == -1)
		    {
		       logprintf(1, "Error - In get_permissions(): Erroneous line in file\n");
		       set_lock(fd, F_UNLCK);
		       
		       while(((erret = fclose(fp)) != 0) && (errno == EINTR))
			 logprintf(1, "Error - In get_permissions()/fclose(): Interrupted system call. Trying again.\n");
		       
		       if(erret != 0)
			 {
			    logprintf(1, "Error - In get_permissions()/fclose(): ");
			    logerror(1, errno);
			    return -1;
			 }
		       
		       return -1;
		    }
	    		  
		  while(line[i] == ' ')
		    i++;
		  if(line[i] == '\0')
		    {
		       logprintf(1, "Error - In get_permissions(): Erroneous line in file\n");
		       set_lock(fd, F_UNLCK);
		       
		       while(((erret = fclose(fp)) != 0) && (errno == EINTR))
			 logprintf(1, "Error - In get_permissions()/fclose(): Interrupted system call. Trying again.\n");
		       
		       if(erret != 0)
			 {
			    logprintf(1, "Error - In get_permissions()/fclose(): ");
			    logerror(1, errno);
			    return -1;
			 }
		       
		       return -1;
		    }
		  if((j = i + cut_string(line + i, ' ')) == -1)
		    {
		       logprintf(1, "Error - In get_permissions(): Erroneous line in file\n");
		       set_lock(fd, F_UNLCK);
		       
		       while(((erret = fclose(fp)) != 0) && (errno == EINTR))
			 logprintf(1, "Error - In get_permissions()/fclose(): Interrupted system call. Trying again.\n");
		       
		       if(erret != 0)
			 {
			    logprintf(1, "Error - In get_permissions()/fclose(): ");
			    logerror(1, errno);
			    return -1;
			 }
		       
		       return -1;
		    }
		  
		  perms = atoi(line + i);
	       }
	  }
     }
   set_lock(fd, F_UNLCK);
   
   while(((erret = fclose(fp)) != 0) && (errno == EINTR))
     logprintf(1, "Error - In get_permissions()/fclose(): Interrupted system call. Trying again.\n");
   
   if(erret != 0)
     {
	logprintf(1, "Error - In get_permissions()/fclose(): ");
	logerror(1, errno);
	return -1;
     }
   
   return perms;
}

/* Write config file */
int write_config_file(void)
{
   FILE *fp;
   int fd;
   int erret;
   char path[MAX_FDP_LEN+1];
   
   snprintf(path, MAX_FDP_LEN, "%s/%s", config_dir, CONFIG_FILE);
   
   /* Remove existing config file */
   unlink(path);
   
   while(((fd = open(path, O_RDWR | O_CREAT, 0600)) < 0) && (errno == EINTR))
     logprintf(1, "Error - In write_config_file()/open(): Interrupted system call. Trying again.\n");   
   
   if(fd < 0)
     {
	logprintf(1, "Error - In write_config_file()/open(): ");
	logerror(1, errno);
	return -1;	
     }
   
   /* Set the lock */
   if(set_lock(fd, F_WRLCK) == 0)
     {
	logprintf(1, "Error - In write_config_file(): Couldn't set file lock\n");
	close(fd);
	return -1;
     }
   
   if((fp = fdopen(fd, "w")) == NULL)
     {
	logprintf(1, "Error - In write_config_file()/fdopen(): ");
	logerror(1, errno);
	set_lock(fd, F_UNLCK);
	close(fd);
	return -1;
     }
   
   fprintf(fp, "hub_name = \"%s\"\n\n", hub_name);	       	       
	       
   fprintf(fp, "max_users = %d\n\n", max_users);
   
   fprintf(fp, "hub_full_mess = \"%s\"\n\n", hub_full_mess);
   
   fprintf(fp, "hub_description = \"%s\"\n\n", hub_description);
   
   fprintf(fp, "min_share = %llu\n\n", min_share);
	       
   fprintf(fp, "admin_pass = \"%s\"\n\n", admin_pass);

   fprintf(fp, "default_pass = \"%s\"\n\n", default_pass);
	       	
   fprintf(fp, "link_pass = \"%s\"\n\n", link_pass);
   
   fprintf(fp, "users_per_fork = %d\n\n", users_per_fork);
   
   fprintf(fp, "listening_port = %u\n\n", listening_port);
   
   fprintf(fp, "admin_port = %u\n\n", admin_port);

   fprintf(fp, "admin_localhost = %u\n\n", admin_localhost);
   
   fprintf(fp, "hublist_upload = %d\n\n", hublist_upload);
  
   fprintf(fp, "public_hub_host = \"%s\"\n\n", public_hub_host);
  
   fprintf(fp, "hub_hostname = \"%s\"\n\n", hub_hostname);
   
   fprintf(fp, "min_version = \"%s\"\n\n", min_version);
   
   fprintf(fp, "redirect_host = \"%s\"\n\n", redirect_host);
   
   fprintf(fp, "registered_only = %d\n\n", registered_only);
   
   fprintf(fp, "check_key = %d\n\n", check_key);
   
   fprintf(fp, "reverse_dns = %d\n\n", reverse_dns);
   
   fprintf(fp, "ban_overrides_allow = %d\n\n", ban_overrides_allow);
   
   fprintf(fp, "verbosity = %d\n\n", verbosity);
   
   fprintf(fp, "redir_on_min_share = %d\n\n", redir_on_min_share);
   
   fprintf(fp, "syslog_enable = %d\n\n", syslog_enable);
   
   fprintf(fp, "searchcheck_exclude_internal = %d\n\n", searchcheck_exclude_internal);
   
   fprintf(fp, "searchcheck_exclude_all = %d\n\n", searchcheck_exclude_all);
   
   fprintf(fp, "kick_bantime = %d\n\n", kick_bantime);
   
   fprintf(fp, "searchspam_time = %d\n\n", searchspam_time);
   
   fprintf(fp, "max_email_len = %d\n\n", max_email_len);
   
   fprintf(fp, "max_desc_len = %d\n\n", max_desc_len);
   
   fprintf(fp, "crypt_enable = %d\n\n", crypt_enable);
   
   set_lock(fd, F_UNLCK);
   
   while(((erret = fclose(fp)) != 0) && (errno == EINTR))
     logprintf(1, "Error - In write_config_file()/fclose(): Interrupted system call. Trying again.\n");
   
   if(erret != 0)
     {
	logprintf(1, "Error - In write_config_file()/fclose(): ");
	logerror(1, errno);
	return -1;
     }
   
   return 1;
}
     
/* Set lock on file */
int set_lock(int fd, int type)
{
   int ret;
   struct flock lock;
   
   memset(&lock, 0, sizeof(struct flock));
   lock.l_whence = SEEK_SET;
   lock.l_start = 0;
   lock.l_len = 0;
   
   lock.l_type = type;
   
   while(((ret = fcntl(fd, F_SETLKW, &lock)) < 0) && (errno == EINTR))
     logprintf(1, "Error - In set_lock()/fcntl(): Interrupted system call. Trying again.\n");
   
   if(ret < 0)
     {
	logprintf(1, "Error - In set_lock()/fcntl(): ");
	logerror(1, errno);
	quit = 1;
	return 0;
     }   
   
   return 1;
}

/* Removes a user from the reglist */
int remove_reg_user(char *buf, struct user_t *user)
{
   int nick_len;
   char *temp;
   char nick[MAX_NICK_LEN+1];
   char path[MAX_FDP_LEN+1];
   int line_nbr;
   
   line_nbr = 0;
   temp = NULL;
   
   snprintf(path, MAX_FDP_LEN, "%s/%s", config_dir, REG_FILE);
   
   if(buf[strlen(buf)-1] == '|')
     nick_len = strlen(buf)-1;
   else
     nick_len = strlen(buf);
   
   snprintf(nick, (nick_len>MAX_NICK_LEN)?MAX_NICK_LEN+1:nick_len+1, buf);

   if((user->type != ADMIN) && 
      (check_if_registered(nick) > check_if_registered(user->nick)))
     return -1;
   
   return remove_line_from_file(nick, path, 0);
}
   

/* Adds a user to the reglist. Returns 2 if the command had bad format and 3
 * if it's already registered Format is: $AddRegUser <nick> <pass> <opstatus> */
int add_reg_user(char *buf, struct user_t *user)
{
   int ret;
   char command[21];
   char nick[MAX_NICK_LEN+1];
   char pass[51];
   char path[MAX_FDP_LEN+1];
   char line[51 + MAX_NICK_LEN + 2];
   int  type;
   
   snprintf(path, MAX_FDP_LEN, "%s/%s", config_dir, REG_FILE);
   
   if(sscanf(buf, "%20s %50s %50s %d|", command, nick, pass, &type) != 4)
     return 2;
   
   if((pass[0] == '\0') || ((type != 0) && (type != 1) && (type != 2)))
     return 2;

   if ((user != NULL) && (user->type != ADMIN)
       && (type >= check_if_registered(user->nick)))
     return -1;
   
   /* If the user already is there, then remove the user first */
   if(check_if_registered(nick) != 0)
     return 3;
   
   encrypt_pass(pass);

   sprintf(line, "%s %s %d", nick, pass, type);
   
   ret = add_line_to_file(line, path);
   
   /* Send the event to script */
#ifdef HAVE_PERL
   if(ret == 1)
     {	
	command_to_scripts("$Script added_registered_user %c%c", '\005', '\005');
	non_format_to_scripts(nick);
	command_to_scripts("|");
     }   
#endif
   return ret;
}

/* Adds a hub to the linklist. Returns 2 if the command had bad format */
/* Format is: $AddLinkedHub hub_ip port */
int add_linked_hub(char *buf)
{
   char command[21];
   char ip[MAX_HOST_LEN+1];
   char path[MAX_FDP_LEN+1];
   int  port;
   int ret;
   char line[MAX_HOST_LEN + 6];
   int checkret;
   
   snprintf(path, MAX_FDP_LEN, "%s/%s", config_dir, LINK_FILE);
   
   if(sscanf(buf, "%20s %121s %d|", command, ip, &port) != 3)
     return 2;
   
   if((ip[0] == '\0') || (port < 1) || (port > 65536))
     return 2;
   
   if((checkret = check_if_on_linklist(ip, port)) == 1)
     return 3;
   else if(checkret == -1)
     return -1;
   
   /* And add the hub */
   sprintf(line, "%s %d", ip, port);
   
   ret = add_line_to_file(line, path);
   
   /* Send to scripts */
#ifdef HAVE_PERL
   if(ret == 1)
     {	
	command_to_scripts("$Script added_multi_hub %c%c", '\005', '\005', ip);
	non_format_to_scripts(ip);
	command_to_scripts("%c%c%d|", '\005', '\005', port);
     }   
#endif
   return ret;
}

/* Removes a hub from the linklist */
int remove_linked_hub(char *buf)
{
   int ip_len;
   char line[1024];
   char ip[MAX_HOST_LEN+1];
   int port;
   char path[MAX_FDP_LEN+1];
   
   snprintf(path, MAX_FDP_LEN, "%s/%s", config_dir, LINK_FILE);
   
   if(sscanf(buf, "%121s %d|", ip, &port) != 2)
     return 2;
   
   if((ip[0] == '\0') || (port < 1) || (port > 65536))
     return 2;
   
   ip_len = strlen(ip);
  
   sprintf(line, "%s %d", ip, port);
   
   return remove_line_from_file(line, path, port);
}

/* Set the directories used */
int init_dirs(void)
{
   char path[MAX_FDP_LEN+1];
   char script_dir[MAX_FDP_LEN+1];

   if(strlen(working_dir) == 0)
     {
#ifdef __CYGWIN__
	getcwd(working_dir, MAX_FDP_LEN);
#else
#ifdef SWITCH_USER
	struct passwd *user = getpwuid(dchub_user);
	snprintf( working_dir, MAX_FDP_LEN, user->pw_dir );
#else
	if( getenv( "HOME" ) == NULL )
	   return 0;
   
	snprintf( working_dir, MAX_FDP_LEN, getenv( "HOME" ) );
#endif
#endif
     }
   strncpy(path, working_dir, MAX_FDP_LEN);
   snprintf( config_dir, MAX_FDP_LEN, "%s/.opendchub", path );

   sprintfa(path, "/tmp");
   sprintf(un_sock_path, "%s/%s", path, UN_SOCK_NAME);
   sprintf(script_dir, "%s/%s", config_dir, SCRIPT_DIR);
   mkdir(config_dir, 0700);
   mkdir(path, 0700);
   mkdir(script_dir, 0700);
   return 1;
}

/* Print to log file */
void logprintf(int verb, const char *format, ...)
{
   static char buf[4096];
   char path[MAX_FDP_LEN+1];
   FILE *fp = NULL;
   int fd=0;
   int erret;
   char *localtime;
   char *temp;
   time_t current_time;
   int priority;
   
   if(verb > verbosity)
     return;
   
   if ((syslog_enable == 0) && (syslog_switch == 0))
     {
	if (strlen(logfile) > 1)
	  strncpy(path, logfile, MAX_FDP_LEN);
	else									/* If no preset logfile. */
	  snprintf(path, MAX_FDP_LEN, "%s/%s", config_dir, LOG_FILE);
     }
   
   if(format)
     {
	va_list args;
	va_start(args, format);
	vsnprintf(buf, 4095, format, args);
	va_end(args);
	
	if((syslog_enable == 0) && (syslog_switch == 0))
	  {
	     while(((fd = open(path, O_RDWR | O_CREAT, 0600)) < 0) && (errno == EINTR))
	       {
	       }	     
	     
	     if(fd < 0)
	       return;
	     
	     /* Set the lock */
	     if(set_lock(fd, F_WRLCK) == 0)
	       {
		  close(fd);
		  return;
	       }
	     
	     if((fp = fdopen(fd, "a")) == NULL)
	       {
		  set_lock(fd, F_UNLCK);
		  close(fd);
		 return;
	      }
	  }
	
	current_time = time(NULL);
	localtime = ctime(&current_time);
	temp = localtime;
	temp += 4;
	localtime[strlen(localtime)-6] = 0;
	if(debug != 0)
	  printf("%s %s", temp, buf);
#ifdef HAVE_SYSLOG_H
	else if((syslog_enable != 0) || (syslog_switch != 0))
	  {
	     if(verb > 1)
		priority = LOG_DEBUG;
	     else if (strncmp(buf, "Error - ", 8))
		priority = LOG_ERR;
	     else
		priority = LOG_WARNING;
	     syslog(priority, "%s", buf);
	  }
#endif
	else
	  fprintf(fp, "%s %s", temp, buf);
	
	if((syslog_enable == 0) && (syslog_switch == 0))
	  {
	     set_lock(fd, F_UNLCK);
	     while(((erret = fclose(fp)) != 0) && (errno == EINTR))
	       {
	       }
	  }
     }
}

/* Write the motd. Creates the motd file if it doesn't exist. Overwrites
   current motd if overwrite is set to 1. Returns 1 on created file and
   0 if it already exists. */
int write_motd(char *buf, int overwrite)
{
   FILE *fp;
   int fd;
   int erret;
   char path[MAX_FDP_LEN+1];
   
   snprintf(path, MAX_FDP_LEN, "%s/%s", config_dir, MOTD_FILE);
   
   if(overwrite == 0)
     {
	while(((fd = open(path, O_RDONLY)) < 0) && (errno == EINTR))
	  logprintf(1, "Error - In write_motd()/open(): Interrupted system call. Trying again.\n"); 
	
	if(fd >= 0)
	  {
	     /* MOTD already exists */
	     close(fd);
	     return 0;
	  }
     }
   
   if(overwrite != 0)
     unlink(path);
   
   while(((fd = open(path, O_RDWR | O_CREAT, 0600)) < 0) && (errno == EINTR))
     logprintf(1, "Error - In write_motd()/open(): Interrupted system call. Trying again.\n");
   
   if(fd < 0)
     {
	logprintf(1, "Error - In write_motd()/open(): ");
	logerror(1, errno);
	return -1;
     }
   
   /* Set the lock */
   if(set_lock(fd, F_WRLCK) == 0)
     {	
	close(fd);
	return -1;
     }
   
   if((fp = fdopen(fd, "w")) == NULL)
     {
	logprintf(1, "Error - In write_motd()/fdopen(): ");
	logerror(1, errno);
	set_lock(fd, F_UNLCK);
	close(fd);
	return -1;
     }
   fprintf(fp, "%s", buf);
   set_lock(fd, F_UNLCK);
   
   while(((erret = fclose(fp)) != 0) && (errno == EINTR))
     logprintf(1, "Error - In write_motd()/fclose(): Interrupted system call. Trying again.\n");
   
   if(erret != 0)
     {
	logprintf(1, "Error - In write_motd()/fclose(): ");
	logerror(1, errno);
	return -1;
     }
   
   if(overwrite != 0)
     return 0;
   else
     return 1;
}

/* Sends the motd to the particular user. */
int send_motd(struct user_t *user)
{
   FILE *fp;
   int fd;
   int erret;
   char line[4095];
   char path[MAX_FDP_LEN+1];
   
   snprintf(path, MAX_FDP_LEN, "%s/%s", config_dir, MOTD_FILE);
   
   while(((fd = open(path, O_RDONLY)) < 0) && (errno == EINTR))
     logprintf(1, "Error - In send_motd()/open(): Interrupted system call. Trying again.\n");   
   
   if(fd < 0)
     {
	logprintf(1, "Error - In send_motd()/open(): ");
	logerror(1, errno);
	return -1;	
     }
   
   /* Set the lock */
   if(set_lock(fd, F_RDLCK) == 0)
     {
	logprintf(1, "Error - In send_motd(): Couldn't set file lock\n");
	close(fd);
	return -1;
     }
   
   if((fp = fdopen(fd, "r")) == NULL)
     {
	logprintf(1, "Error - In send_motd()/fdopen(): ");
	logerror(1, errno);
	set_lock(fd, F_UNLCK);
	close(fd);
	return -1;
     }
   
   if(fgets(line, 4094, fp) != NULL)
     {
	trim_string(line);
	uprintf(user, "%s", line);
	while(fgets(line, 4094, fp) != NULL)
	  {
	     trim_string(line);
	     uprintf(user, "\r\n%s", line);
	  }
     }  
   set_lock(fd, F_UNLCK);
   
   while(((erret = fclose(fp)) != 0) && (errno == EINTR))
     logprintf(1, "Error - In send_motd()/fclose(): Interrupted system call. Trying again.\n");
   
   if(erret != 0)
     {
	logprintf(1, "Error - In send_motd()/fclose(): ");
	logerror(1, errno);
	return -1;
     }

   return 1;
}

/* Sends the welcome message to a newly connected user. */
int welcome_mess(struct user_t *user)
{
   int ret;
   //uprintf(user, "$To: %s From: Hub $", user->nick);   //This did not let motd to be sent when new user connects. 
   ret = send_motd(user);
   send_to_user("|", user);
   return ret;
}

/* Prints the error to the log file */
void logerror(int verb, int error)
{
   char path[MAX_FDP_LEN+1];
   FILE *fp=NULL;
   int fd=0;
   int erret;
   int priority;
   
   if(verb > verbosity)
     return;
   
   if((syslog_enable == 0) && (syslog_switch == 0))
     {
	snprintf(path, MAX_FDP_LEN, "%s/%s", config_dir, LOG_FILE);
   	
	while(((fd = open(path, O_RDWR | O_CREAT, 0600)) < 0) && (errno == EINTR))
	  {
	  }	     
	
	if(fd < 0)
	  return;
   
	/* Set the lock */
	if(set_lock(fd, F_WRLCK) == 0)
	  {
	     close(fd);
	     return;
	  }
   
	if((fp = fdopen(fd, "a")) == NULL)
	  {
	     set_lock(fd, F_UNLCK);
	     close(fd);
	     return;
	  }
     }
   
   if(debug != 0)
     printf("%s\n", strerror(error));
#ifdef HAVE_SYSLOG_H
   else if((syslog_enable != 0) || (syslog_switch != 0))
     {
	if(verb > 1)
	   priority = LOG_DEBUG;
	else
	   priority = LOG_ERR;
	syslog(priority, "%s", strerror(error));
     }
#endif
   else
     fprintf(fp, "%s\n", strerror(error));
   
   if((syslog_enable == 0) && (syslog_switch == 0))
     {
	set_lock(fd, F_UNLCK);
	
	while(((erret = fclose(fp)) != 0) && (errno == EINTR))
	  {
	  }		
     }
}   

/* Adds line to end of a file */
int add_line_to_file(char *line, char *file)
{
   FILE *fp;
   int fd;
   int erret;
   
   /* Open the file */
   while(((fd = open(file, O_RDWR)) < 0) && (errno == EINTR))
     logprintf(1, "Error - In add_line_to_file()/open(): Interrupted system call. Trying again.\n");   
   
   if(fd < 0)
     {
	logprintf(1, "Error - In add_line_to_file()/open(), file = %s: ", file);
	logerror(1, errno);
	return -1;	
     }   
   
   /* Set the lock */
   if(set_lock(fd, F_WRLCK) == 0)
     {	
	logprintf(1, "Error - In add_line_to_file(): Couldn't set file lock, file = %s\n", file);
	close(fd);
	return -1;
     }
   
   if((fp = fdopen(fd, "a")) == NULL)
     {	
	logprintf(1, "Error - In add_line_to_file()/fdopen(), file = %s: ", file);
	logerror(1, errno);
	set_lock(fd, F_UNLCK);
	close(fd);
	return -1;
     }
   
   fprintf(fp, "%s\n", line);
   
   set_lock(fd, F_UNLCK);
   
   while(((erret = fclose(fp)) != 0) && (errno == EINTR))
     logprintf(1, "Error - In add_line_to_file()/fclose(): Interrupted system call. Trying again.\n");
   
   if(erret != 0)
     {
	logprintf(1, "Error - In add_line_to_file()/fclose(): ");
	logerror(1, errno);
	return -1;
     }
   
   return 1;
}

/* Removes line from file. Word has to match first word in the line in
 * the file. If port is set to anything else than zero, it assumes it's the
 * linklist file and then the port must match as well. Returns 1 on success, 
 * 0 if pattern wasn't found and -1 on error.  */
int remove_line_from_file(char *line, char *file, int port)
{
   FILE *fp;
   int fd;
   int erret;
   char *temp;
   char word[201];
   char fileline[1024];
   char fileword[201];
   int i, len;
   int fileport;
   int line_nbr = 0;
   
   if((temp = malloc(sizeof(char) * 2)) == NULL)
     {
	logprintf(1, "Error - In remove_line_from_file()/malloc(): ");
	logerror(1, errno);
	quit = 1;
	return -1;
     }   

   sscanf(line, "%200s", word);
   
   sprintf(temp, "%c", '\0');

   while(((fd = open(file, O_RDWR)) < 0) && (errno == EINTR))
     logprintf(1, "Error - In remove_line_from_file()/open(): Interrupted system call. Trying again.\n");   
   
   if(fd < 0)
     {
	logprintf(1, "Error - In remove_line_from_file()/open(), file = %s: ", file);	logprintf(1, "Error - In remove_line_from_file()/open(), file = %s: ", file);	logprintf(1, "Error - In remove_line_from_file()/open(), file = %s: ", file);
	logerror(1, errno);
	free(temp);
	return -1;	
     }   
   
   /* Set the lock */
   if(set_lock(fd, F_WRLCK) == 0)
     {	
	logprintf(1, "Error - In remove_line_from_file(): Couldn't set file lock, file = %s\n", file);
	close(fd);
	free(temp);
	return -1;
     }
   
   if((fp = fdopen(fd, "r")) == NULL)
     {	
	logprintf(1, "Error - In remove_line_from_file()/fdopen(), file = %s: ", file);
	logerror(1, errno);
	set_lock(fd, F_UNLCK);
	close(fd);
	free(temp);
	return -1;
     }
   
   while(fgets(fileline, 1023, fp) != NULL)
     {	
	line_nbr++;
	if(port != 0)	     
	  sscanf(fileline, "%200s %d", fileword, &fileport);
	else 
	  {	     
	     sscanf(fileline, "%200s", fileword);
	     fileport = 0;
	  }	
	
	if(((strncasecmp(word, fileword, strlen(word)) == 0)
	   && (strlen(word) == strlen(fileword))
	   && (port == fileport)))
	  {	     
	     /* Put the rest of the file in the temporary string */
	     while(fgets(fileline, 1023, fp) != NULL)
	       {		  
		  if((temp = realloc(temp, sizeof(char)
				     * (strlen(temp) + strlen(fileline) + 1))) == NULL)
		    {	
		       logprintf(1, "Error - In remove_line_from_file()/realloc(): ");
		       logerror(1, errno);
		       quit = 1;
		       set_lock(fd, F_UNLCK);
		       fclose(fp);		       
		       return -1;
		    }		  
		  strcat(temp, fileline);
	       }	     
	     rewind(fp);
	     
	     /* Go to the position where the user name is */
	     for(i = 1; i<= (line_nbr-1); i++)
	       fgets(fileline, 1023, fp);
	     
	     /* Truncate the file */
	     len = ftell(fp);
	     
	     while(((erret = fclose(fp)) != 0) && (errno == EINTR))
	       logprintf(1, "Error - In remove_line_from_file()/fclose(): Interrupted system call. Trying again.\n");
	     
	     if(erret != 0)
	       {
		  logprintf(1, "Error - In remove_line_from_file()/fclose(): ");
		  logerror(1, errno);
		  return -1;
	       }
	     
	     truncate(file, len);
	     
	     while(((fd = open(file, O_RDWR)) < 0) && (errno == EINTR))
	       logprintf(1, "Error - In remove_line_from_file()/open(): Interrupted system call. Trying again.\n");   
	     
	     if(fd < 0)
	       {		  
		  logprintf(1, "Error - In remove_line_from_file()/open(), file = %s: ", file);
		  logerror(1, errno);
		  free(temp);
		  return -1;
	       }
	     
	     if((fp = fdopen(fd, "a")) == NULL)
	       {		  
		  logprintf(1, "Error - In remove_line_from_file()/fdopen(), file = %s: ", file);
		  logerror(1, errno);
		  set_lock(fd, F_UNLCK);
		  close(fd);
		  free(temp);
		  return -1;
	       }	     
	     fwrite(temp, strlen(temp), 1, fp);
	     
	     set_lock(fd, F_UNLCK);
	     
	     while(((erret = fclose(fp)) != 0) && (errno == EINTR))
	       logprintf(1, "Error - In remove_line_from_file()/fclose(): Interrupted system call. Trying again.\n");
	     
	     if(erret != 0)
	       {
		  logprintf(1, "Error - In remove_line_from_file()/fclose(): ");
		  logerror(1, errno);
		  free(temp);
		  return -1;
	       }
	     
	     free(temp);
	     return 1;
	  }	
     }   
   set_lock(fd, F_UNLCK);
   
   while(((erret = fclose(fp)) != 0) && (errno == EINTR))
     logprintf(1, "Error - In remove_line_from_file()/fclose(): Interrupted system call. Trying again.\n");
   
   if(erret != 0)
     {
	logprintf(1, "Error - In remove_line_from_file()/fclose(): ");
	logerror(1, errno);
	free(temp);
	return -1;
     }
   
   free(temp);
   return 0;
}

/* Remove an expired ban/allow line from a file.  */
int remove_exp_from_file(time_t now_time, char *file)
{
   FILE *fp;
   FILE *newfp;
   int fd;
   int erret;
   int newfd;
   char *newfile;
   char fileline[1024];
   char fileword[201];
   time_t exp_time;
   
   if((newfile = malloc(strlen(file) + 2)) == NULL)
     {
	logprintf(1, "Error - In remove_exp_from_file()/malloc(): ");
	logerror(1, errno);
	quit = 1;
	return -1;
     }   

   strcpy(newfile, file);
   strcat(newfile, "1");
   
   while(((fd = open(file, O_RDWR)) < 0) && (errno == EINTR))
     logprintf(1, "Error - In remove_exp_from_file()/open(): Interrupted system call. Trying again.\n");
   
   if(fd < 0)
     {	
	logprintf(1, "Error - In remove_exp_from_file()/open(), file = %s: ", file);
	logerror(1, errno);
	free(newfile);
	return -1;
     }

   /* Set the lock */
   if(set_lock(fd, F_WRLCK) == 0)
     {	
	logprintf(1, "Error - In remove_exp_from_file(): Couldn't set file lock, file = %s\n", file);
	close(fd);
	free(newfile);
	return -1;
     }

   if((fp = fdopen(fd, "r")) == NULL)
     {	
	logprintf(1, "Error - In remove_exp_from_file()/fdopen(), file = %s: ", file);
	logerror(1, errno);
	set_lock(fd, F_UNLCK);
	close(fd);
	free(newfile);
	return -1;
     }

   unlink(newfile);
   
   while(((newfd = open(newfile, O_RDWR | O_CREAT, 0600)) < 0) && (errno == EINTR))
     logprintf(1, "Error - In remove_exp_from_file()/open(): Interrupted system call. Trying again.\n");   
   
   if(newfd < 0)
     {
	logprintf(1, "Error - In remove_exp_from_file()/open(), file = %s: ", newfile);
	logerror(1, errno);
	set_lock(fd, F_UNLCK);
	while(((erret = fclose(fp)) != 0) && (errno == EINTR))
	  logprintf(1, "Error - In remove_exp_from_file()/fclose(): Interrupted system call. Trying again.\n");
	
	if(erret != 0)
	  {
	     logprintf(1, "Error - In remove_exp_from_file()/fclose(): ");
	     logerror(1, errno);
	     free(newfile);
	     return -1;
	  }
       
	free(newfile);
	return -1;
     }
   
   if(set_lock(newfd, F_WRLCK) == 0)
     {
	logprintf(1, "Error - In remove_exp_from_file(): Couldn't set file lock, file = %s\n", newfile);
	set_lock(fd, F_UNLCK);
	fclose(fp);
	close(newfd);
	free(newfile);
	return -1;
     }

   if((newfp = fdopen(newfd, "w")) == NULL)
     {
	logprintf(1, "Error - In remove_exp_from_file()/fdopen(), file = %s: ", newfile);
	logerror(1, errno);
	set_lock(fd, F_UNLCK);
	fclose(fp);
	set_lock(newfd, F_UNLCK);
	close(newfd);
	free(newfile);
	return -1;
     }

   while(fgets(fileline, 1023, fp) != NULL)
     {	
	exp_time = 0;
	sscanf(fileline, "%200s %lu", fileword, &exp_time);
	
	if((exp_time == 0) || (exp_time > now_time))
	  fprintf(newfp, "%s", fileline);
     }   
   set_lock(newfd, F_UNLCK);
   set_lock(fd, F_UNLCK);
   
   while(((erret = fclose(newfp)) != 0) && (errno == EINTR))
     logprintf(1, "Error - In remove_exp_from_file()/fclose(): Interrupted system call. Trying again.\n");
   
   if(erret != 0)
     {
	logprintf(1, "Error - In remove_exp_from_file()/fclose(): ");
	logerror(1, errno);
	free(newfile);
	return -1;
     }
   
   while(((erret = fclose(fp)) != 0) && (errno == EINTR))
     logprintf(1, "Error - In remove_exp_from_file()/fclose(): Interrupted system call. Trying again.\n");
   
   if(erret != 0)
     {
	logprintf(1, "Error - In remove_exp_from_file()/fclose(): ");
	logerror(1, errno);
	free(newfile);
	return -1;
     }
   
   rename(newfile, file);
   free(newfile);
   return 0;
}

/* This puts a list of all files in directory dirname that ends with '.pl'
 * in namelist. It returns the number of matching entries.  */
int my_scandir(char *dirname, char *namelist[])
{
   DIR *dp;
   struct dirent *dent;
   int i = 0;
   
   if((dp = opendir(dirname)) == NULL)
     return -1;
   
   while((dent = readdir(dp)) != NULL)
     i++;
   
   if(i == 0)
     return 0;
   
   rewinddir(dp);
   
   i = 0;
   
   while((dent = readdir(dp)) != NULL)
     {
	
	/* Only parse files with filenames ending with .pl  */
	if(!((strlen( (strrchr(dent->d_name, 'l') == NULL)
		      ? "" : strrchr(dent->d_name, 'l')) == 1)
	     && (strlen( (strrchr(dent->d_name, 'p') == NULL)
			 ? "" : strrchr(dent->d_name, 'p')) == 2)
	     && (strlen( (strrchr(dent->d_name, '.') == NULL)
			 ? "" : strrchr(dent->d_name, '.')) == 3)))
	  continue;
	if((namelist[i] = (char *)malloc(sizeof(char)
				    * (strlen(dirname) + strlen(dent->d_name) + 2))) == NULL)
	  {	     
	     logprintf(1, "Error - In my_scandir()/malloc(): ");
	     logerror(1, errno);
	     quit = 1;
	     return 0;
	  }
	sprintf(namelist[i], "%s/%s", dirname, dent->d_name);
	i++;
     }
   closedir(dp);
   return i;
}

/* Adds a permission to an op. Returns 2 if the command had bad format, 3
 * if the op already has that permission and 4 if the user is not an op.
 * Format is: $AddPerm <nick> <permission> */
int add_perm(char *buf, struct user_t *user)
{
   int ret;
   char command[21];
   char nick[MAX_NICK_LEN+1];
   char perm[15];
   int new_perm, old_perm;
   char path[MAX_FDP_LEN+1];
   char line[51 + MAX_NICK_LEN + 2];
   struct user_t *targ_user;
   
   snprintf(path, MAX_FDP_LEN, "%s/%s", config_dir, OP_PERM_FILE);
   
   if(sscanf(buf, "%20s %50s %15[^|]", command, nick, perm) != 3)
     return 2;
   
   if(perm[0] == '\0')
     return 2;
   
   if(check_if_registered(nick) != 2)
     return 4;
   
   if((targ_user = get_human_user(nick)) == NULL)
     {
	if(*buf == '!')
	  {	
	     *buf = '$';
	     send_to_non_humans(buf, FORKED, user);
	     *buf = '!';
	  }
	else
	  send_to_non_humans(buf, FORKED, user);
	return 1;
     }   
   else
     {
	if(!(strcasecmp(perm, "BAN_ALLOW")))
	  new_perm = BAN_ALLOW;
	else if(!(strcasecmp(perm, "USER_INFO")))
	  new_perm = USER_INFO;
	else if(!(strcasecmp(perm, "MASSMESSAGE")))
	  new_perm = MASSMESSAGE;
	else if(!(strcasecmp(perm, "USER_ADMIN")))
	  new_perm = USER_ADMIN;
	else
	  return 2;
	
	old_perm = get_permissions(nick);
	if((old_perm & new_perm) != 0)
	  return 3;
	
	if(old_perm > 0)
	  {
	     sprintf(line, "%s", nick);
	     ret = remove_line_from_file(line, path, 0);
	     if(ret != 1)
	       return ret;
	  }
	
	old_perm = old_perm | new_perm;
	
	sprintf(line, "%s %d", nick, old_perm);
	
	ret = add_line_to_file(line, path);    
	
	targ_user->permissions = old_perm;
	
	return ret;
     }   
}

/* Removes a permission from an op. Returns 2 if the command had bad format,
 * 3 if the op does not have that permission and 4 if the user is not an op.
 * Format is: $RemovePerm <nick> <permission> */
int remove_perm(char *buf, struct user_t *user)
{
   int ret;
   char command[21];
   char nick[MAX_NICK_LEN+1];
   char perm[15];
   int old_perm, del_perm;
   char path[MAX_FDP_LEN+1];
   char line[51 + MAX_NICK_LEN + 2];
   struct user_t *targ_user;
   
   snprintf(path, MAX_FDP_LEN, "%s/%s", config_dir, OP_PERM_FILE);
   
   if(sscanf(buf, "%20s %50s %15[^|]", command, nick, perm) != 3)
     return 2;
   
   if(perm[0] == '\0')
     return 2;
   
   if(check_if_registered(nick) != 2)
     return 4;

   if((targ_user = get_human_user(nick)) == NULL)
     {	
	if(*buf == '!')
	  {	     
	     *buf = '$';
	     send_to_non_humans(buf, FORKED, user);
	     *buf = '!';
	  }	
	else
	  send_to_non_humans(buf, FORKED, user);
	return 1;
     }
   else
     {	   
	if(!(strcasecmp(perm, "BAN_ALLOW")))
	  del_perm = BAN_ALLOW;
	else if(!(strcasecmp(perm, "USER_INFO")))
	  del_perm = USER_INFO;
	else if(!(strcasecmp(perm, "MASSMESSAGE")))
	  del_perm = MASSMESSAGE;
	else if(!(strcasecmp(perm, "USER_ADMIN")))
	  del_perm = USER_ADMIN;
	else
	  return 2;
     
	old_perm = get_permissions(nick);
	if((old_perm & del_perm) == 0)
	  return 3;
	
	sprintf(line, "%s", nick);
	ret = remove_line_from_file(line, path, 0);
	if(ret != 1)
	  return ret;
	
	old_perm = (old_perm ^ del_perm);
	
	if(old_perm > 0)
	  {
	     sprintf(line, "%s %d", nick, old_perm);
	     ret = add_line_to_file(line, path);
	  }
	
	targ_user->permissions = old_perm;
	
	return ret;
     }
}

/* Checks if an entry exists in the linklist. Returns 1 if user exists, 
 * otherwise 0.  */
int check_if_on_linklist(char *ip, int port)
{
   int fd;
   int erret;
   FILE *fp;
   char path[MAX_FDP_LEN+1];
   char line[1024];
   char fileip[MAX_HOST_LEN+1];
   int fileport;
   
   snprintf(path, MAX_FDP_LEN, "%s/%s", config_dir, LINK_FILE);
   
   while(((fd = open(path, O_RDONLY)) < 0) && (errno == EINTR))
     logprintf(1, "Error - In check_if_on_linklist()/open(): Interrupted system call. Trying again.\n");
   
   if(fd < 0)
     {
	logprintf(1, "Error - In check_if_on_linklist()/open(): ");
	logerror(1, errno); 	
	return -1;
     }
   
   /* Set the lock */
   if(set_lock(fd, F_RDLCK) == 0)
     {
	logprintf(1, "Error - In check_if_on_linklist): Couldn't set lock\n");
	close(fd);
	return -1;
     }
   
   if((fp = fdopen(fd, "r")) == NULL)
     {
	logprintf(1, "Error - In check_if_on_linklist()/fdopen(): ");
	logerror(1, errno);
	set_lock(fd, F_UNLCK);
	close(fd);
	return -1;
     }
   
   while(fgets(line, 1023, fp) != NULL)
     {
	trim_string(line);
	sscanf(line, "%121s %d", fileip, &fileport);
	if((strncmp(ip, fileip, strlen(fileip)) == 0)
	   && (port == fileport) && (strlen(ip) == strlen(fileip)))
	  {	     
	     while(((erret = fclose(fp)) != 0) && (errno == EINTR))
	       logprintf(1, "Error - In check_if_on_linklist()/fclose(): Interrupted system call. Trying again.\n");
	     return 1;
	  }
     }
   
   while(((erret = fclose(fp)) != 0) && (errno == EINTR))
     logprintf(1, "Error - In check_if_on_linklist()/fclose(): Interrupted system call. Trying again.\n");
   
   return 0;
}
   
