/* Open DC Hub - A Linux/Unix version of the Direct Connect hub.
 * Copyright (C) 2002,2003  Jonatan Nilsson 
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

int  init_user_list(void);
int  init_user_list_shm_shm(void);
int  get_user_list_shm_id(void);
void set_user_list_shm_id(int id);
int  add_user_to_list(struct user_t *user);
int  remove_user_from_list(char *nick);
char *check_if_on_user_list(char *nick);
void increase_user_list(void);
void purge_user_list(void);
void send_user_list(int type, struct user_t *user);
char *get_op_list(void);
int  set_listening_pid(int pid);
int  get_listening_pid(void);
