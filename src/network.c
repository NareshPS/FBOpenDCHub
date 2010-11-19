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

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#if HAVE_FCNTL_H
# include <fcntl.h>
#endif
#if HAVE_UNISTD_H
# include <unistd.h>
#endif
#include <string.h>
#if HAVE_SYS_POLL_H
# include <sys/poll.h>
#elif HAVE_SYS_SELECT_H
# include <sys/select.h>
#endif
#include <sys/un.h>
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


#include "main.h"
#include "utils.h"
#include "fileio.h"
#include "network.h"
#ifdef HAVE_PERL
# include "perl_utils.h"
#endif

/* Sends as many packets as it takes. */
/* This was taken from Beej's guide to network programming: */
/* http://www.ecst.csuchico.edu/~beej/guide/net/html/ */
int sendall(int s, char *buf, int *len)
{
   register int total = 0;        /* how many bytes we've sent */
   register int bytesleft = *len; /* how many we have left to send */
   register int n = 0;
   
   while(total < *len)
     {
	n = send(s, buf+total, bytesleft, 0);
	if(n == -1){ 
	   break;
	}
	total += n;
	bytesleft -= n;
     }
   
   *len = total; /* return number actually sent here */
   return n == -1?-1:0; /* return -1 on failure, 0 on success */
}

/* Get ip of hub */
int set_hub_hostname(void)
{
   struct hostent *host;
   struct in_addr in;
   char temp_host[130];
   
   memset(&in, 0, sizeof(struct in_addr));
   if(gethostname(temp_host, 121) == -1)
     {
	return -1;
     }
   host = gethostbyname(temp_host);
   if(host == NULL)
     {
       logprintf(1, "Failed setting hostname\n");
       return -1;
     }
   
   /* If the hostname doesn't contain any dots, it's not the FQDN, so the ip
    * is stored instead */
   if(strchr(temp_host, '.') == NULL)
     {
       in.s_addr = *((long unsigned *)host->h_addr);
       sprintf(hub_hostname, "%s", inet_ntoa(in));
     }
   else
     sprintf(hub_hostname, "%s", temp_host);
   
   /* Make sure hubname isn't set to any af the local hostnames */

   if((strncmp(hub_hostname, "127.0.0.1", 9) == 0)
      || (strncmp(hub_hostname, "localhost", 9) == 0))
     {
	hublist_upload = 0;
	hub_hostname[0] = '\0';
	return 1;
     }
   logprintf(1, "Hostname of hub set to %s\n", hub_hostname);
   return 0;
}

#ifdef HAVE_POLL
void add_fd(struct pollfd *newfd, int sock)
{
   newfd->fd = sock;
   newfd->events = (POLLIN | POLLPRI);
   
   return;
}
#endif

/* Get action from one of the sockets */
void get_socket_action(void)
{
   struct user_t *non_human, *next_non_human;
   struct sock_t *human_user, *next_human_user;
#ifdef HAVE_POLL
   struct pollfd *ufds;
   struct pollfd *fds;
   int num;
   int total;
   int matched;
#else
   fd_set fds;
   struct timeval tv;
#endif

#ifdef HAVE_POLL
   non_human = non_human_user_list;
   human_user = human_sock_list;
   
   total = count_users(0xFFFF);

   if(pid > 0)
     total += 2;
   else if(pid == 0)
     {
	if(listening_socket != -1)
	  total++;
	if(admin_listening_socket != -1)
	  total++;
     }
   
   if((ufds = calloc(total, sizeof(struct pollfd))) == NULL)
     {
	logprintf(1, "Error - In get_socket_action()/calloc(): ");
	logerror(1, errno);
	quit = 1;
	return;
     }
   
   /* Add our listening tcp, udp and unix socket to the set if we are the parent */
   num = 0;
   if(pid > 0)
     {
	add_fd(&ufds[0], listening_unx_socket);
	add_fd(&ufds[1], listening_udp_socket);
	num = 2;
     }
   else if((pid == 0) && (listening_socket != -1))
     {
	add_fd(&ufds[0], listening_socket);
	num = 1;
	if(admin_listening_socket != -1)
	  {		     
	     add_fd(&ufds[1], admin_listening_socket);
	     num = 2;
	  }   
     }
   
   /* ...the established non-human users...  */
   while(non_human != NULL)
     {
	if(non_human->type != LINKED)
	  {	     
	     add_fd(&ufds[num], non_human->sock);
	     num++;
	  }	
	non_human = non_human->next;
     }
   
   /* ...and all human users.  */
   while(human_user != NULL)
     {
	add_fd(&ufds[num], human_user->user->sock);
	human_user = human_user->next;
	num++;
     }
        
   /* The very central poll, where the program should spend most of its time */   
   if((num = poll(ufds, total, 1000)) <= 0)
     {
	free(ufds);
	return;
     }   
   
   for(num = 0; num < total; num++)
     {
	fds = &ufds[num];
	if(((fds->revents & POLLIN) != 0) || ((fds->revents & POLLPRI) != 0))
	  {
	     matched = 0;
	     /* Check if it's a new admin connection */
	     if((pid == 0) && (admin_listening_socket != -1)
		&& (fds->fd == admin_listening_socket))
	       {
		  new_human_user(admin_listening_socket);
		  matched = 1;
	       }
	     /* Check if it's a new connection */
	     else if((pid == 0) && (listening_socket != -1)
		     && (fds->fd == listening_socket))
	       {
		  new_human_user(listening_socket);
		  matched = 1;
	       }
	     /* Or if it's a new forked process */
	     else if((pid > 0) && (fds->fd == listening_unx_socket))
	       {
		  new_forked_process();
		  matched = 1;
	       }
	     /* Or a linked hub */
	     else if((pid > 0) && (fds->fd == listening_udp_socket))
	       {
		  udp_action();
		  matched = 1;
	       }			
	     
	     /* Run through established non-human user connections.  */
	     non_human = non_human_user_list;
	     while((matched == 0) && (non_human != NULL))
	       {	     
		  next_non_human = non_human->next;
		  if(non_human->type != LINKED)
		    {
		       if(fds->fd == non_human->sock)
			 {
			    socket_action(non_human);
			    matched = 1;
			 }
		    }
		  /* Using a temporary user instead of user = user->next;
		   so freed memory won't be accessed */
		  non_human = next_non_human;
	       }
	     
	     /* And run through established human user connections.  */
	     if(pid == 0)
	       {	     
		  human_user = human_sock_list;
		  while((matched == 0) && (human_user != NULL))
		    {
		       next_human_user = human_user->next;
		       if(human_user->user->type != LINKED)
			 {
			    if(fds->fd == human_user->user->sock)
			      {
				 socket_action(human_user->user);
				 matched = 1;
			      }
			 }
		       /* Using a temporary user instead of user = user->next;
			so freed memory won't be accessed */
		       human_user = next_human_user;
		    }
	       }	
	  }
     }   
   
   free(ufds);
#else
   memset(&fds, 0, sizeof(fd_set));
   memset(&tv, 0, sizeof(struct timeval));
   tv.tv_sec = 1;
   tv.tv_usec = 0;
   
   non_human = non_human_user_list;
   human_user = human_sock_list;
   
   FD_ZERO(&fds);
   
   /* Add our listening tcp, udp  and unix socket to the set if we are the parent */
   if(admin_listening_socket != -1)
     FD_SET(admin_listening_socket, &fds);
   if(listening_socket != -1)
     FD_SET(listening_socket, &fds);

   
   if(pid > 0)
     {
	FD_SET(listening_unx_socket, &fds);
	FD_SET(listening_udp_socket, &fds);
     }
   
   /* ...the established non-human users...  */
   while(non_human != NULL)
     {
	if(non_human->type != LINKED)
	  FD_SET(non_human->sock, &fds);
	
	non_human = non_human->next;
     }
   
   /* ...and all human users.  */
   while(human_user != NULL)
     {
	FD_SET(human_user->user->sock, &fds);
	human_user = human_user->next;
     }   
   
   /* The very central select, where the program should spend most of its time */
   if(select(max_sockets, &fds, NULL, NULL, &tv) <= 0)
     {
	return;
     }
   
     /* Check if it's a new admin connection */
   if((admin_listening_socket != -1) && FD_ISSET(admin_listening_socket, &fds))
     {
	new_human_user(admin_listening_socket);
	return;
     }
   
   /* Check if it's a new connection */
   if((listening_socket != -1) && FD_ISSET(listening_socket, &fds))
     {
	new_human_user(listening_socket);
	return;
     }
   
   /* Or if it's a new forked process */
   if((FD_ISSET(listening_unx_socket, &fds)) && (pid > 0))
     new_forked_process();
   
   /* Or a linked hub */
   if((FD_ISSET(listening_udp_socket, &fds)) && (pid > 0))
     udp_action();
   
   /* Run through established non-human user connections.  */
   non_human = non_human_user_list;
   while(non_human != NULL)
     {
	next_non_human = non_human->next;
	if(non_human->type != LINKED)
	  {	     
	     if(FD_ISSET(non_human->sock, &fds))
	       {
		  socket_action(non_human);
		  return;
	       }
	  }	      
	/* Using a temporary user instead of user = user->next; 
	 so freed memory won't be accessed */
	non_human = next_non_human;
     }
   
   /* And run through established human user connections.  */
   human_user = human_sock_list;
    while(human_user != NULL)
     {
	next_human_user = human_user->next;
	if(human_user->user->type != LINKED)
	  {	     
	     if(FD_ISSET(human_user->user->sock, &fds))
	       {
		  socket_action(human_user->user);
		  return;
	       }
	  }	      
	/* Using a temporary user instead of user = user->next; 
	 so freed memory won't be accessed */
	human_user = next_human_user;
     }
#endif
}

/* Returns a socket to listen for connections, or -1 on failure */
int get_listening_socket(int port, int set_to_localhost)
{
   int sock;
   int yes = 1;
   int flags;
   struct sockaddr_in hub_addr;
   
   if(port == 0)
     return -1;
   
   memset(&hub_addr, 0, sizeof(struct sockaddr_in));
   /* Create socket */
   if((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1)
     {
	return -1;
     }
   
   /* Fix the address already in use error */
   if(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes,
		  sizeof(int)) == -1)
     {
	return -1;
     }
   memset(&hub_addr, 0, sizeof(struct sockaddr_in));
   hub_addr.sin_family = AF_INET;
   if (set_to_localhost) {
     inet_pton(AF_INET, "127.0.0.1", &hub_addr.sin_addr);
   } else {
     hub_addr.sin_addr.s_addr = INADDR_ANY;
   }
   hub_addr.sin_port = htons(port);
   
   /* Bind socket to port */
   if(bind(sock, (struct sockaddr *)&hub_addr, sizeof(hub_addr)) == -1)
     {
	logprintf(1, "Error - In get_listening_socket()/bind(): ");
	logerror(1, errno);
	return -1;
     }
   
   /* Listen on socket */
   if(listen(sock, 100) == -1)
     {
	logprintf(1, "Error - In get_listening_socket()/listen(): ");
	logerror(1, errno);
	return -1;
     }
   
   if((flags = fcntl(sock, F_GETFL, 0)) < 0)
     {
	logprintf(1, "Error - In get_listening_socket()/fcntl(): ");
	logerror(1, errno);
	return -1;
     }
    
   /* Non blocking mode */
   if(fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0)
     {
	logprintf(1, "Error - In get_listening_socket()/fcntl(): ");
	logerror(1, errno);
	return -1;
     }
   
   return(sock);
}

/* Returns a socket to listen for forked processes, or -1 on failure */
int get_listening_unx_socket(void)
{
   int sock;
   int flags;
   int len;
   struct sockaddr_un local_addr;
   
   memset(&local_addr, 0, sizeof(struct sockaddr_un));
   
   /* Create socket */
   if((sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
     {
	logprintf(1, "Error - In get_listening_socket()/socket(): ");
	logerror(1, errno);
	return -1;
     }
   
   if((flags = fcntl(sock, F_GETFL, 0)) < 0)
     {	
	logprintf(1, "Error - In get_listening_socket()/fcntl(): ");
	logerror(1, errno);
	return -1;
     }
   
   if(fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0)
     {
	logprintf(1, "Error - In get_listening_socket()/fcntl(): ");
	logerror(1, errno);
	return -1;
     }
   
   memset(&local_addr, 0, sizeof(struct sockaddr_un));
   local_addr.sun_family = AF_UNIX;
   strcpy(local_addr.sun_path, un_sock_path);
   unlink(local_addr.sun_path);
   len = strlen(local_addr.sun_path) + sizeof(local_addr.sun_family) + 1;
   
   /* Bind socket to port */
   if(bind(sock, (struct sockaddr *)&local_addr, len) == -1)
     {
	logprintf(1, "Error - In get_listening_unx_socket()/bind(): ");
	logerror(1, errno);
	return -1;
     }
   
   /* Listen on socket */
   if(listen(sock, 10) == -1)
     {
	return -1;
     }
   
   return(sock);
}

int get_listening_udp_socket(int port)
{
   int sock;
   int yes = 1;
   int flags;
   struct sockaddr_in hub_addr;
   
   memset(&hub_addr, 0, sizeof(struct sockaddr_in));
   /* Create socket */
   if((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
     {
	logprintf(1, "Error - In get_listening_udp_socket()/socket(): ");
	logerror(1, errno);
	return -1;
     }
   
   /* Fix the address already in use error */
   if(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes,
		  sizeof(int)) == -1)
     {
	logprintf(1, "Error - In get_listening_udp_socket()/setsockopt(): ");
	logerror(1, errno);
	return -1;
     }
 
   if((flags = fcntl(sock, F_GETFL, 0)) < 0)
     {
	logprintf(1, "Error - In get_listening_udp_socket()/fcntl(): ");
	logerror(1, errno);
	return -1;
     }
      
   if(fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0)
     {
	logprintf(1, "Error - In get_listening_udp_socket()/fcntl(): ");
	logerror(1, errno);
	return -1;
     }                    
   
   hub_addr.sin_family = AF_INET;
   hub_addr.sin_addr.s_addr = INADDR_ANY;
   hub_addr.sin_port = htons(port);
   memset(hub_addr.sin_zero, 0, 8);
   
   /* Bind socket to port */
   if(bind(sock, (struct sockaddr *)&hub_addr, sizeof(struct sockaddr)) == -1)
     {
	logprintf(1, "Error - In get_listening_udp_socket()/bind(): ");
	logerror(1, errno);
	return -1;
     }
   
   return(sock);
}

/* Returns the hostname from an ip. If error, it returns the ip in ascii */
char *hostname_from_ip(long unsigned ip)
{
   struct hostent *hp; 
   long unsigned addr = ip;
   unsigned char *p; 
   static char s[MAX_HOST_LEN+1];

   hp=gethostbyaddr((char *)&addr,sizeof(addr),AF_INET); 
   if(hp == NULL)
     {
	p = (unsigned char *)&addr;
	sprintf(s, "%u.%u.%u.%u", (unsigned int)p[0], (unsigned int)p[1], (unsigned int)p[2], (unsigned int)p[3]);
	return s;
     }
   strncpy(s, hp->h_name, MAX_HOST_LEN);
   s[MAX_HOST_LEN] = '\0';
   return s;
}

/* Uploads hub description to public hub list */
/* This is run in a separate thread because connect() is blocking */
void upload_to_hublist(int nbrusers)
{
   int port;
   int local_port;
   int host_len;
   int buf_len;
   int key_len;
   int bufp;
   int i, j, k;
   int s;
   int erret;
   unsigned int uc;
   char buf[400];
   char key[400];
   struct hostent *hostnm;
   struct sockaddr_in server;
   struct sockaddr_in host;
   
   memset(&host, 0, sizeof(struct sockaddr_in));
   memset(&server, 0, sizeof(struct sockaddr_in));
   memset(buf, 0, sizeof(buf));
   memset(key, 0, sizeof(key));
   hostnm = gethostbyname(public_hub_host);
   if (hostnm == (struct hostent *) 0)
     {
	logprintf(1, "Error - In upload_to_hublist(): Gethostbyname failed on public hub host\n");
	exit(EXIT_FAILURE);
     }
   
   port = 2501;
   
   server.sin_family = AF_INET;
   server.sin_port = htons(port);
   server.sin_addr.s_addr = *((long unsigned *)hostnm->h_addr);
   
   if((s = socket(AF_INET, SOCK_STREAM, 0)) < 0)      
     {	
	logprintf(1, "Error - In upload_to_hublist(): Could not get a socket\n");
	close(s);
	exit(EXIT_FAILURE);       
     }
   
   if(connect(s, (struct sockaddr *)&server, sizeof(server)) < 0)
     {
	logprintf(1, "Error - In upload_to_hublist(): Connection failed\n");
	close(s);
	exit(EXIT_FAILURE);
     }

   while(((erret = recv(s, buf, sizeof(buf), 0)) < 0) && (errno == EINTR))
     logprintf(1, "Error - In upload_to_hublist()/send(): Interrupted system call. Trying again.\n");
   
   if(erret < 0)
     {
	logprintf(1, "Error - In upload_to_hublist(): Receive failed\n");
	logerror(1, errno);
	close(s);
	exit(EXIT_FAILURE);
     }
   
   host_len = sizeof(host);
   if(getsockname(s, (void*)&host, &host_len) != 0)
     {
	logprintf(4, "Error - In upload_to_hublist()/getsockname(): ");
	logerror(4, errno);
	close(s);
	exit(EXIT_FAILURE);
     }
   
   local_port = ntohs(host.sin_port);
   uc = local_port + (local_port >> 8);
   
   if(strncmp(buf, "$Lock ", 6) != 0)
     {
	close(s);
	exit(EXIT_FAILURE);
     }
   
   sprintf(key, "$Key ");
   bufp = 6;
   
   buf_len = cut_string(buf+6, ' ') + 5;
  
   /* Now, compute the key from the lock */
   
   /* The first character is computed differently */
   i = (((unsigned int)(buf[bufp]     ))&0xff)
     ^ (((unsigned int)(buf[buf_len]  ))&0xff)
       ^ (((unsigned int)(buf[buf_len-1]))&0xff)
	 ^ uc;
   
   j = ((i | (i << 8)) >> 4)&0xff;
   
   switch(j)
     {
      case 5:
	sprintfa(key, "/%%DCN005%%/");
	break;
	
      case 36:
	sprintfa(key, "/%%DCN036%%/");
	break;
	
      case 96:
	sprintfa(key, "/%%DCN096%%/");
	break;
	
      default:
	sprintfa(key, "%c", j);
	break;
     }
   bufp++;
   
   for(k = bufp; k <= buf_len; k++)
     {
	i = (((unsigned int)(buf[k]     ))&0xff)
	  ^ (((unsigned int)(buf[k-1]   ))&0xff);
	
	j = ((i | (i << 8)) >> 4)&0xff;
	
	switch(j)
	  {
	   case 5:
	     sprintfa(key, "/%%DCN005%%/");
	     break;
	     
	   case '$':
	     sprintfa(key, "/%%DCN036%%/");
	     break;

	   case 96:
	     sprintfa(key, "/%%DCN096%%/");
	     break;
	     
	   default:
	     sprintfa(key, "%c", j);
	     break;
	  }
     }
   
   sprintfa(key, "|");
   
   /* The listening port only needs to be uploaded if it's not 411 because
    * the Windoze client defaults to port 411 */
   if(listening_port == 411)
     sprintfa(key, "%s|%s|%s|%d|%llu|", hub_name, hub_hostname,
	      hub_description, nbrusers, get_total_share());
   else
     sprintfa(key, "%s|%s:%u|%s|%d|%llu|", hub_name, hub_hostname, 
	      listening_port, hub_description, nbrusers, get_total_share());
   
   /* And finally, upload the key */
   key_len = strlen(key) + 1;
   sendall(s, (char *)key, &key_len);
   logprintf(2, "Uploaded to public hub list. Users: %d, Share: %llu\n", nbrusers, get_total_share());
   close(s);
   exit(EXIT_SUCCESS);
}

/* Send the $Up message to all linked hubs on the list */
void send_linked_hubs(void)
{
   char buf[200];
   int fd;
   int sock;
   int erret;
   FILE *fp;
   char ip[MAX_HOST_LEN+1];
   char path[MAX_FDP_LEN+1];
   char line[1024];
   int port;
   struct hostent *hostnm;
   struct sockaddr_in myhost;
   struct sockaddr_in sin;
   int yes = 1;
   
   memset(&myhost, 0, sizeof(struct sockaddr_in));
   memset(&sin, 0, sizeof(struct sockaddr_in));

   snprintf(path, MAX_FDP_LEN, "%s/%s", config_dir, LINK_FILE);
   
   while(((fd = open(path, O_RDONLY)) < 0) && (errno == EINTR))
     logprintf(1, "Error - In send_linked_hubs()/open(): Interrupted system call. Trying again.\n");
   
   if(fd < 0)
     {
	logprintf(1, "Error - In send_linked_hubs()/open(): ");
	logerror(1, errno);
	return;
     }

   /* Set the lock */
   if(set_lock(fd, F_RDLCK) == 0)
     {
	logprintf(1, "Error - In send_linked_hubs(): Couldn't set file lock\n");
	close(fd);
	return;
     }
   
   if((fp = fdopen(fd, "r")) == NULL)
     {	
	logprintf(1, "Error - In send_linked_hubs()/fdopen(): ");
	logerror(1, errno);	
	set_lock(fd, F_UNLCK);
	close(fd);
	return;
     }
   
   sprintf(buf, "$Up %s %s|", link_pass, hub_hostname);
   
   while(fgets(line, 1023, fp) != NULL)
     {
	trim_string(line);
	sscanf(line, "%121s %d", ip, &port);
	if((ip[0] == '\0') || (port < 1) || (port > 65536))
	  continue;
	
	hostnm = gethostbyname(ip);
	if(hostnm == (struct hostent *) 0)
	  continue;
	
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	sin.sin_addr.s_addr = *((long unsigned *)hostnm->h_addr);
    
	/* These messages are udp */
	if((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
	  {
	     logprintf(1, "Error - In send_linked_hubs()/socket(): ");
	     logerror(1, errno);
	     return;
	  }
	
	myhost.sin_family = AF_INET;
	myhost.sin_addr.s_addr = htonl(INADDR_ANY);
	myhost.sin_port = htons(listening_port);
	
	if(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes,
		      sizeof(int)) == -1)
	  { 
	     logprintf(1, "Error - In send_linked_hubs()/setsockopt(): ");
	     logerror(1, errno);
	     return;
	  }
	
	/* Bind socket to port */
	if(bind(sock, (struct sockaddr *)&myhost, sizeof(myhost)) == -1)     
	   {
	      
	      logprintf(1, "Error - In send_linked_hubs()/bind(): ");
	      logerror(1, errno);
	      return;
	   }
	   
	sendto(sock, buf, strlen(buf), 0, (struct sockaddr *)&sin, 
		   sizeof(sin));
	
	while(((erret =  close(sock)) != 0) && (errno == EINTR))
	  logprintf(1, "Error - In send_linked_hubs()/close(): Interrupted system call. Trying again.\n");
	
	if(erret != 0)
	  {	     
	     logprintf(1, "Error - In send_linked_hubs()/close(): ");
	     logerror(1, errno);
	  }	
	
     }
   
   set_lock(fd, F_UNLCK);
   
   while(((erret = fclose(fp)) != 0) && (errno == EINTR))
     logprintf(1, "Error - In read_config()/fclose(): Interrupted system call. Trying again.\n");
   
   if(erret != 0)
     {
	logprintf(1, "Error - In read_config()/fclose(): ");
	logerror(1, errno);
     }
}

/* Add a users socket to the socket list.  */
void add_socket(struct user_t *user)
{
   struct sock_t *sock;
   
   if((sock = malloc(sizeof(struct sock_t))) == NULL)
     {
	logprintf(1, "Error in add_socket()/malloc(): ");
	logerror(1, errno);
	quit = 1;
	return;
     }
   
   /* Set the user to whom this sock points to.  */
   sock->user = user;
   
   /* And add the socket to the list.  */
   sock->next = human_sock_list;
   human_sock_list = sock;
}

/* Removes a socket from the list.  */
void remove_socket(struct user_t *user)
{
   struct sock_t *sock, *last_sock;
   
   sock = human_sock_list;
   last_sock = NULL;
   
   while(sock != NULL)
     {
	if(sock->user == user)
	  {
	     if(last_sock == NULL) 
	       human_sock_list = sock->next;	     
	     else
	       last_sock->next = sock->next;
	     
	     /* Remove the sock:  */
	     free(sock);
	     
	     return;
	  }
	last_sock = sock;
	sock = sock->next;
     }
}

/* Sends a string to all non-human users who are included in type, ex_user is
 * excluded.  */
void send_to_non_humans(char *buf, int type, struct user_t *ex_user)
{
   register struct user_t *user;
   
   user = non_human_user_list;
   
   while(user != NULL)
     {
	if(((type & user->type) != 0) && (user != ex_user))
	  send_to_user(buf, user);
	
	user = user->next;
     }
}

/* Sends a string to all human users who are included in type, ex_user is 
 * excluded.  */
void send_to_humans(char *buf, int type, struct user_t *ex_user)
{
   register struct sock_t *sock;
   
   sock = human_sock_list;
   
   while(sock != NULL)
     {
	if(((type & sock->user->type) != 0) && (sock->user != ex_user))
	  send_to_user(buf, sock->user);
	sock = sock->next;
     }
}

/* Returns ip in string format.  */
char *ip_to_string(unsigned long ip)
{
   struct sockaddr_in client;

   memset(&client, 0, sizeof(struct sockaddr_in));   
   client.sin_addr.s_addr = ip;
   
   return inet_ntoa(client.sin_addr);
}

/* Checks if an ip is an address used in internal networks.  */
int is_internal_address (long unsigned ip)
{   
   if(searchcheck_exclude_internal != 0)
     if (((ip ^ inet_network("127.0.0.0")) <= 16777215) || /* 127.0.0.0/8 */
	 ((ip ^ inet_network("192.168.0.0")) <= 65535) ||  /* 192.168.0.0/16 */
	 ((ip ^ inet_network("10.0.0.0")) <= 16777215) ||  /* 10.0.0.0/8 */
	 ((ip ^ inet_network("172.16.0.0")) <= 8388607))   /* 172.17.0.0/12 */
	return 1;
   return 0;
}

/* Sends string to user */
void send_to_user(char *buf, struct user_t *user)
{
   int len, len2;
   int sock;
   int erret;
   int flags;
   struct hostent *hostnm;
   struct sockaddr_in myhost;
   struct sockaddr_in linked_hub;
   int yes=1;
   char *new_outbuf, *temp;
   register char *send_buf;
   
   memset(&myhost, 0, sizeof(struct sockaddr_in));
   memset(&linked_hub, 0, sizeof(struct sockaddr_in));
   
   /* If user is a linked hub */
   if(user->type == LINKED)
     {
	hostnm = gethostbyname(user->hostname);
	if (hostnm == (struct hostent *) 0)
	  {
	     logprintf(1, "Error - In send_to_user(): Gethostbyname failed\n");
	     return;
	  }
	linked_hub.sin_family = AF_INET;
	linked_hub.sin_port = htons(user->key);
	linked_hub.sin_addr.s_addr = *((long unsigned *)hostnm->h_addr);
	
	if((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
	  {
	     logprintf(1, "Error - In send_to_user()/socket(): ");
	     logerror(1, errno);
	     return;
	  }
	
	/* The port we send from must be the listening port*/
	myhost.sin_family = AF_INET;
	myhost.sin_addr.s_addr = htonl(INADDR_ANY);
	myhost.sin_port = htons(listening_port);
	
	if(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes,
		      sizeof(int)) == -1)
	  {
	     logprintf(1, "Error - In send_to_user()/setsockopt(): ");
	     logerror(1, errno);
	     close(sock);
	     return;
	  }
	
	if((flags = fcntl(sock, F_GETFL, 0)) < 0)
	  {
	     logprintf(1, "Error - In send_to_user()/fcntl(): ");
	     logerror(1, errno);
	     close(sock);
	     return;
	  }
	
	if(fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0)
	  {
	     logprintf(1, "Error - In send_to_user()/fcntl(): ");
	     logerror(1, errno);
	     close(sock);
	     return;
	  }
	
	if(bind(sock, (struct sockaddr *)&myhost, sizeof(myhost)) == -1)
	  {
	     logprintf(1, "Error - In send_to_user()/bind(): ");
	     logerror(1, errno);
	     close(sock);
	     return;
	  }
	
	if(sendto(sock, buf, strlen(buf), 0,
		  (struct sockaddr *)&linked_hub, sizeof(linked_hub)) < 0)
	  {
	     logprintf(4, "Error - In send_to_user()/sendto(): ");
	     logerror(4, errno);
	     close(sock);
	     return;
	  }
	
	while(((erret =  close(sock)) != 0) && (errno == EINTR))
	  logprintf(1, "Error - In send_to_user()/close(): Interrupted system call. Trying again.\n");
	
	if(erret != 0)
	  {
	     logprintf(1, "Error - In send_to_user()/close(): ");
	     logerror(1, errno);
	  }
     }
   else
     {
	/* If there already is something in the outbuf we add current buf to
	 * the end of users outbuf.  */
	if(user->outbuf == NULL)
	  send_buf = buf;
	
	else
	  {
	     if((user->outbuf = realloc(user->outbuf, sizeof(char) * (strlen(user->outbuf) + strlen(buf) + 1))) == NULL)
	       {
		  logprintf(1, "Error - In send_to_user()/realloc(): ");
		  logerror(1, errno);
		  quit = 1;
		  return;
	       }
	     strcat(user->outbuf, buf);
	     send_buf = user->outbuf;
	  }
	len = len2 = strlen(send_buf);
	if(sendall(user->sock, send_buf, &len) == -1)
	  {
	     if(user->outbuf == NULL)
	       {
		  if((user->outbuf = malloc(sizeof(char) * (strlen(buf) + 1))) == NULL)
		    {
		       logprintf(1, "Error - In send_to_user()/malloc(): ");
		       logerror(1, errno);
		       quit = 1;
		       return;
		    }
		  strcpy(user->outbuf, buf);
	       }
	     
	     if((errno != EAGAIN) && (errno != EINTR))
	       {
		  /* If it's a forked or a script process, this error can mean
		   * that the process is trying to send to us at the same time 
		   * as we are trying to send to it.  */
		  if(((user->rem == 0) && (user->type & (FORKED | SCRIPT)) == 0)
		     || ((user->outbuf != NULL)
			 && (strlen(user->outbuf) >= MAX_BUF_SIZE)))
		    {
		       logprintf(5, "Error - When trying to send to user %s at %s - In send_to_user()/sendall()/send(), pid: %d, buf: %s: ",
				 user->nick, user->hostname, getpid(), buf);
		       logerror(5, errno);
		       logprintf(5, "Removing user %s at %s\n", user->nick, user->hostname);
		       if(strlen(buf) < 3500)
			 logprintf(5, "buf: %s\n", buf);
		       else
			 logprintf(5, "too large buf\n");
		       user->rem = REMOVE_USER | SEND_QUIT | REMOVE_FROM_LIST;
		    }
		  return;
	       }
	     if(strlen(user->outbuf) >= MAX_BUF_SIZE)
	       {
		  if(user->rem == 0)
		    logprintf(1, "User from %s had too big buf, removing user\n", user->hostname);
		  user->rem = REMOVE_USER | SEND_QUIT | REMOVE_FROM_LIST;
		  return;
	       }
	     if(len != 0)
	       {
		  if((new_outbuf = malloc(sizeof(char) * (len2 - len + 1))) == NULL)
		    {
		       logprintf(1, "Error - In send_to_user()/malloc(): ");
		       logerror(1, errno);
		       quit = 1;
		       return;
		    }
		  strcpy(new_outbuf, user->outbuf + len);
		  temp = user->outbuf;
		  user->outbuf = new_outbuf;
		  free(temp);
	       }
	     
	  }
	else if(user->outbuf != NULL)
	  {
	     free(user->outbuf);
	     user->outbuf = NULL;
	  }
     }
}
