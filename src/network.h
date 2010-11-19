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


int    sendall(int s, char *buf, int *len);
int    set_hub_hostname(void);
void   get_socket_action(void);
int    get_listening_socket(int port, int set_to_localhost);
int    get_listening_unx_socket(void);
int    get_listening_udp_socket(int port);
char   *hostname_from_ip(long unsigned ip);
void   upload_to_hublist(int nbrusers);
void   send_linked_hubs(void);
void   add_socket(struct user_t *user);
void   remove_socket(struct user_t *user);
void   send_to_non_humans(char *buf, int type, struct user_t *ex_user);
void   send_to_humans(char *buf, int type, struct user_t *ex_user);
char  *ip_to_string(unsigned long ip);
int    is_internal_address (long unsigned ip);
void   send_to_user(char *buf, struct user_t *user);
