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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#if HAVE_UNISTD_H
# include <unistd.h>
#endif
#if HAVE_FCNTL_H
# include <fcntl.h>
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
#include <errno.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/sem.h>

#include "main.h"
#include "utils.h"
#include "fileio.h"
#include "userlist.h"
#include "network.h"

/* the number of the next char which is the char c */
/* Maybe it's better with just strchr(buf) - buf */
int cut_string(char *buf, char c)
{
   int i;
   i = 0;
   while((buf[i] != c) && (buf[i] != (char)NULL))
     i++;
   if(buf[i] == c)
     return i;
   return -1;
}

/* Appends to the end of a string */
/* NO checking of buf size, so it MUST be big enough */
/* The string usually has to be zeroed before this can be used */
void sprintfa(char *buf, const char *format, ...)
{  
   if(format)
     {
	va_list args;
	va_start(args, format);
	vsprintf(buf + strlen(buf), format, args);
	va_end(args);
     }
}

/* Send formated string to user. Maximum length is 4096 chars */
void uprintf(struct user_t *user, char *format, ...)
{
   char buf[4096];
   if(format)
     {
	va_list args;
	va_start(args, format);
	vsnprintf(buf, 4095, format, args);
	va_end(args);
	send_to_user(buf, user);
     }
}
	  
/* Removes \r:s and \n:s and bs:s from end of a string */
int trim_string(char *buf)
{
   int len;
   if(!buf)
     return 0;
   if(buf[0] == '\0')
     return 1;
   for(len = strlen(buf)-1; len >=0; len--)
     {
	if((buf[len] == '\n') || (buf[len] == '\r') || (buf[len] == ' '))
	  buf[len] = '\0';
	else
	  break;
     }
   return 1;
}

/* Counts number of users which are included in type.  */
int count_users(int type)
{
   int count;
   struct user_t *non_human;
   struct sock_t *human_user;
   
   count = 0;
   non_human = non_human_user_list;
   human_user = human_sock_list;
   
   /* Start with non-human users.  */
   while(non_human != NULL)
     {
	if((type & non_human->type) != 0)
	  count++;
  
	non_human = non_human->next;
     }
   
   /* And the human users.  */
   while(human_user != NULL)
     {
	if((type & human_user->user->type) != 0)
	  count++;
	
	human_user = human_user->next;
     }
   
   return count;
}


/* Count all users in the whole hub.  */
int count_all_users(void)
{
   char *buf;
   int spaces=0, entries=0;
   
   sem_take(user_list_sem);
   
   /* Attach to the shared segment */
   if((buf = (char *)shmat(get_user_list_shm_id(), NULL, 0))
      == (char *)-1)
     {	
	logprintf(1, "Error - In count_all_users()/shmat(): ");
	logerror(1, errno);
	sem_give(user_list_sem);
	quit = 1;
	return -1;
     }
   
   if(sscanf(buf, "%d %d", &spaces, &entries) != 2)
     {	
	logprintf(1, "Error - In count_all_users(): Couldn't get number of entries\n");
	shmdt(buf);
	sem_give(user_list_sem);
	quit = 1;
	return -1;
     }
   shmdt(buf);
   sem_give(user_list_sem);
   return entries;
}
   
/* Sends initial $Lock string to client */
void send_lock(struct user_t *user)
{
   char lock_string[150];
   int len;
   int i, j, k;
   
   if(check_key != 0)
     {		
	create_lock:
	
	memset(lock_string, 0, sizeof(lock_string));
	
	srand(time(NULL));
	
	/* This will be the seed value used to compare the clients lock key with
	 * the correct one */
	user->key = rand();
	srand(user->key);
	len = 48 + rand()%30;
	
	sprintf(lock_string, "$Lock ");
	
	lock_string[6] = '%' + rand()%('z'-'%');
	/* The values in the lock should vary from '%' to 'z' */ 
	for(k = 7; k <= len+6; k++)
	  {
	     lock_string[k] = '%' + rand()%('z'-'%');
	     i = (((unsigned int)(lock_string[k]     ))&0xff)
	       ^ (((unsigned int)(lock_string[k-1]   ))&0xff);
	     j = ((i | (i << 8)) >> 4)&0xff;
	     if(j == '\0')
	       k--;
	  }
	
	i = (((unsigned int)(lock_string[6]     ))&0xff)
	  ^ (((unsigned int)(lock_string[6+len]  ))&0xff)
	    ^ (((unsigned int)(lock_string[6+len-1]))&0xff)
	      ^ 0x05;
	j = ((i | (i << 8)) >> 4)&0xff;
	if(j == '\0') 
	  goto create_lock;
	
	sprintfa(lock_string, " Pk=");
	k += 4;
	for(j = 0; j <= 15; j++)
	  lock_string[k+j] = '%' + rand()%('z'-'%');
	sprintfa(lock_string, "|");
     }
   else
     sprintf(lock_string, "$Lock Sending_key_isn't_neccessary,_key_won't_be_checked. Pk=Same_goes_here.|");
   send_to_user(lock_string, user);   
}

/* Checks the key sent from the client */
int validate_key(char *buf, struct user_t *user)
{
   char lock_string[150];
   char key[400];
   int i, j, k, len;
   int lockp;
   
   /* First, reconstruct the lock string that was sent to the client */
   srand(user->key);
   len = 48 + rand()%30;
 
   lock_string[0] = '%' + rand()%('z'-'%');
   for(k = 1; k <= len; k++)
     {
	lock_string[k] = '%' + rand()%('z'-'%');
	i = (((unsigned int)(lock_string[k]     ))&0xff)
	  ^ (((unsigned int)(lock_string[k-1]   ))&0xff);
	j = ((i | (i << 8)) >> 4)&0xff;
	if(j == '\0')
	  k--;
     }
   
   lockp = 0;
   
   /* The first character is computed differently */
   i = (((unsigned int)(lock_string[lockp]     ))&0xff)
     ^ (((unsigned int)(lock_string[len]  ))&0xff)
       ^ (((unsigned int)(lock_string[len-1]))&0xff)
	 ^ 0x05;
   j = ((i | (i << 8)) >> 4)&0xff;
   
   switch(j)
     {
      case 5:
	sprintf(key, "/%%DCN005%%/");
	break;
	
      case 36:
	sprintf(key, "/%%DCN036%%/");
	break;
	
      case 96:
	sprintf(key, "/%%DCN096%%/");
	break;
	
      default:
	sprintf(key, "%c", j);
	break;
     }
   lockp++;

   for(k = lockp; k <= len; k++)
     {
	i = (((unsigned int)(lock_string[k]     ))&0xff)
	  ^ (((unsigned int)(lock_string[k-1]   ))&0xff);
	
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
   if(strncmp(buf+5, key, strlen(key)) != 0)
      return 0;
   user->type = NON_LOGGED;
   return 1;
}

/* Puts users hostname in buffy.  */
void get_users_hostname(char *nick, char *buffy)
{
   char *buf, *bufp;
   char temp_nick[MAX_NICK_LEN+1];
   char temp_host[MAX_HOST_LEN+1];
   int spaces=0, entries=0;
   int i;
   
   sem_take(user_list_sem);
   
   /* Attach to the shared segment.  */
   if((buf = (char *)shmat(get_user_list_shm_id(), NULL, 0))
      == (char *)-1)
     {	
	logprintf(1, "Error - In get_users_hostname()/shmat(): ");
	logerror(1, errno);
	sem_give(user_list_sem);
	quit = 1;
	return;
     }
   
   if(sscanf(buf, "%d %d", &spaces, &entries) != 2)
     {	
	logprintf(1, "Error - In remove_user_from_list(): Couldn't get number of entries\n");
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
	     if((strncasecmp(temp_nick, nick, strlen(nick)) == 0)
		&& (strlen(nick) == strlen(temp_nick)))
	       {		  
		  /* The user is here, so detach and put the hostname in the
		   * buf.  */
		  sprintf(buffy, "%s", temp_host);
		  shmdt(buf);
		  sem_give(user_list_sem);
		  return;
	       }	     
	  }	
	bufp += USER_LIST_ENT_SIZE;
     }
   
   /* If user wasn't found, put null in returning string */
   *buffy = '\0';
   
   shmdt(buf);
   sem_give(user_list_sem);
}

/* Returns a hash value from a users nickname. It's important that this 
 * function generates values as random as possible, but also stays fast.  */
int get_hash(char *nick)
{
   register char *s1, *s2;
   register int i = 0;
   register int hash = 0;

   /* First char in nick.  */
   s1 = nick;
   
   /* Last char in nick.  */
   s2 = nick + strlen(nick) - 1;
   
   do 
     {      	
	hash |= ((*s1 & 0x1) << i);
	i++;
	hash |= ((*s2 & 0x1) << i);
	i++;
	s1++;
	s2--;
     } while((s1 <= s2) && (hash < max_sockets));
   
   while(hash > max_sockets)
     hash >>= 1;
   
   return hash;
}

/* Initializes the semaphore sem to state "taken".  */
int init_sem(int *sem)
{
   union my_semun arg;
   
   *sem = semget(IPC_PRIVATE, 1, 0600);   
   if(*sem < 0)
     {
	logprintf(1, "Error - In init_sem()/semget(): ");
	logerror(1, errno);
	return -1;
     }
   
   arg.val = 1;
   if(semctl(*sem, 0, SETVAL, arg) == -1)
     {	
	logprintf(1, "Error - In init_sem()/semctl(): ");
	logerror(1, errno);
	return -1;
     }
   return 1;
}

/* Takes a semaphore.  */
void sem_take(int sem)
{
   int ret;
   struct sembuf buf;

   memset(&buf, 0, sizeof(struct sembuf));

   buf.sem_num = 0;
   buf.sem_op = -1;
   buf.sem_flg = 0;
   
   /* Take the semaphore.  */
   while(((ret = semop(sem, &buf, 1)) < 0) && (errno == EINTR))
     logprintf(1, "Error - In sem_take/semop(): Interrupted system call. Trying again.\n");
   
   if(ret < 0)
     {	
	logprintf(1, "Error - In sem_take()/semop(): ");
	logerror(1, errno);
	quit = 1;
     }   
}

/* Gives a semaphore.  */
void sem_give(int sem)
{
   int ret;
   struct sembuf buf;
   
   memset(&buf, 0, sizeof(struct sembuf));

   buf.sem_num = 0;
   buf.sem_op = 1;
   buf.sem_flg = 0;
   
   /* Give the semaphore.  */
   while(((ret = semop(sem, &buf, 1)) < 0) && (errno == EINTR)) 
     logprintf(1, "Error - In sem_give/semop(): Interrupted system call. Trying again.\n");
   
   if(ret < 0)
     {	
	logprintf(1, "Error - In sem_give()/semop(): ");
	logerror(1, errno);
	quit = 1;
     }   
}

/* Initializes the shared memory segment with to total share.  */
int init_share_shm(void)
{
   long long *init_share;
   
   /* Get identifier for the shared data segment */
   if((total_share_shm = shmget(IPC_PRIVATE, sizeof(long long), 0600)) < 0)
     {	
	logprintf(1, "Error - In init_share_shm()/shmget(): ");
	logerror(1, errno);
	return -1;
     }
   
   /* Attach to the shared segment */
   if((init_share = shmat(total_share_shm, NULL, 0))
      == (long long *) -1)
     {	
	logprintf(1, "Error - In init_share_shm()/shmat(): ");
	logerror(1, errno);
	shmctl(total_share_shm, IPC_RMID, NULL);
	return -1;
     }
   
   *init_share = 0;
   shmdt((char *)init_share);
   
   return 1;
}

/* Adds to the total share, can be both positive and negative.  */
void add_total_share(long long add)
{
   long long *share_size;

   /* Take the semaphore.  */
   sem_take(total_share_sem);
  
   /* Attach to the shared memory segment.  */
   if((share_size = shmat(total_share_shm, NULL, 0))
       == (long long *) -1)
     {	
	logprintf(1, "Error - In init_share_shm()/shmat(): ");
	logerror(1, errno);
	shmctl(total_share_shm, IPC_RMID, NULL);
	semctl(total_share_sem, 0, IPC_RMID, NULL);
	return;
     }
   
   /* Add to the segment.  */
   *share_size += add;
   
   /* Dettach from the segment.  */
   shmdt((char *)share_size);
   
   /* And give back the semaphore.  */
   sem_give(total_share_sem);
}

/* Get the current total share.  */
long long get_total_share(void)
{
   long long *share_size;
   long long ret;
   
   /* Take the semaphore.  */
   sem_take(total_share_sem);
   
   /* Attach to the shared memory segment.  */
   if((share_size = shmat(total_share_shm, NULL, 0))
       == (long long *) -1)
     {	
	logprintf(1, "Error - In get_total_share()/shmat(): ");
	logerror(1, errno);
	sem_give(total_share_sem);
	return 0;
     }
   
   /* Get the return value.  */
   ret = *share_size;
   
   /* Dettach from the segment.  */
   shmdt((char *)share_size);
   
   /* And give back the semaphore.  */
   sem_give(total_share_sem);
   return ret;
}

/* Get the uptime of the hub in seconds.  */
double get_uptime(void)
{
   return difftime(time(NULL), hub_start_time);
}

/* Returns 1 if buf1 is a match in buf2, wich can contain wildcards.  */
int match_with_wildcards(char *buf1, char *buf2)
{
   int k = 0;
   char token[MAX_HOST_LEN+1];
   char *fbuf, *ubuf;
   
   /* The '*' is allowed as wildcard. To ban a nick with a '*'in it, it has to be
    * escaped with a '\'. '\':s also have to be escaped with '\'.  */

   fbuf = buf2;
   ubuf = buf1;
   while((*fbuf != '\0') && (*ubuf != '\0'))
     {
	/* If we are escaping a '\' or a '*':  */
	if(*fbuf == '\\')
	  {
	     /* After a '\', only '*' and '\' is allowed.  */
	     fbuf++;
	     if(*fbuf == '\0')
	       return 0;
	     if(*fbuf == '\\')
	       {
		  if(*ubuf != '\\')
		    return 0;
	       }
	     else if(*fbuf == '*')
	       {
		  if(*ubuf != '*')
		    return 0;
	       }
	     else
	       return 0;
	  }			    
	
	/* If we have a wildcard.  */
	if(*fbuf == '*')
	  {	
	     fbuf++;
	     if(*fbuf == '\0')
	       return 1;
	     
	     if(*fbuf == '*')
	       return 0;
	     
	     if((k = cut_string(fbuf, '*')+1) == 0)
	       k = strlen(fbuf)+1;
	     
	     if(k == 1)
	       k = strlen(fbuf);
	     
	     if((strncmp(fbuf, ubuf, k) == 0) && (*(ubuf+k) == '\0'))
	       return 1;
	     
	     strncpy(token, fbuf, k-1);
	     *(token + k - 1) = '\0';
	     if(strstr(ubuf, token) == NULL)
		  return 0;
	     
	     fbuf += k-2;
	     ubuf = strstr(ubuf, token) + k - 2;
	  }   
	
	/* No wildcard, just compare the strings character by 
	 * character.  */
	else if(*fbuf != *ubuf)
	     return 0;

	fbuf++;
	ubuf++;
     }
   
   if((*ubuf == '\0') && ((*fbuf == '*') && (*(fbuf+1) == '\0')))
     return 1;

   if(*fbuf != *ubuf)
     {	
	fbuf = buf2+strlen(buf2)-1;
	ubuf = buf1+strlen(buf1)-1;
	while((fbuf >= buf2) && (*fbuf != '*'))
	  {
	     if(*fbuf != *ubuf)
	       return 0;
	     fbuf--;
	     ubuf--;
	  }
     }   
   return 1;
}

/* This function prints all names in the hashtable for a certain process. It
 * can be commented out and can be used anywhere. */
/*void print_usernames(void)
{
   struct user_t *user;
   int i;
   int count = 1;
   
   sem_take(user_list_sem);
   logprintf(1, "Printing all users in process %d\n", getpid());
   
   for(i = 0; i <= max_sockets; i++)
     {
	user = human_hash_table[i];
	while(user != NULL) 
	  {
	     logprintf(1, "User %d:s nick: %s\n", count, user->nick);
	     count++;
	     user = user->next;
	  }
     }
   sem_give(user_list_sem);
}*/
