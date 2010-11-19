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



int    cut_string(char *buf, char c);
void   sprintfa(char *buf, const char *format, ...);
int    trim_string(char *buf);
int    count_users(int type);
int    count_all_users(void);
void   uprintf(struct user_t *user, char *format, ...);
void   send_lock(struct user_t *user);
int    validate_key(char *buf, struct user_t *user);
void   get_users_hostname(char *nick, char *buf);
int    get_hash(char *nick);
int    init_sem(int *sem);
int    init_share_shm(void);
void   sem_take(int sem);
void   sem_give(int sem);
void   add_total_share(long long add);
long long get_total_share(void);
double get_uptime();
int    match_with_wildcards(char *buf1, char *buf2);
