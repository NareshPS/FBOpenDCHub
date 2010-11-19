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


int read_config(void);
int check_banlist(void);
int check_if_banned(struct user_t *user, int type);
int check_if_allowed(struct user_t *user);
int check_if_registered(char *user_nick);
int check_pass(char *buf, struct user_t *user);
int get_permissions(char *user_nick);
int write_config_file(void);
int set_lock(int fd, int type);
void create_banlist(void);
void create_nickbanlist(void);
void create_allowlist(void);
void create_reglist(void);
void create_op_permlist(void);
void create_linklist(void);
int add_reg_user(char *buf, struct user_t *user);
int remove_reg_user(char *buf, struct user_t *user);
int add_linked_hub(char *buf);
int remove_linked_hub(char *buf);
int init_dirs(void);
void logprintf(int verb, const char *format, ...);
int send_motd(struct user_t *user);
int write_motd(char *buf, int overwrite);
int welcome_mess(struct user_t *user);
void logerror(int verb, int error);
int add_line_to_file(char *line, char *file);
int remove_line_from_file(char *line, char *file, int port);
int my_scandir(char *dirname, char *namelist[]);
int remove_exp_from_file(time_t now_time, char *file);
int add_perm(char *buf, struct user_t *user);
int remove_perm(char *buf, struct user_t *user);
int check_if_on_linklist(char *ip, int port);
