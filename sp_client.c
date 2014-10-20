/*
 *
 * Author: gplll <gplll1818@gmail.com>, Oct 2014
 *  
 */

#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include "sp_api.h"

char *realm = NULL;
char *user = NULL;
char *xattrs_user = NULL;
char *app = NULL;
int list_users = 0;

void get_options (int argc, char *argv[]) 
{
	int opt;
	while ((opt = getopt(argc, argv, "hr:u:x:a:l")) != -1) {
               switch (opt) {
               case 'r':
                   realm = optarg;
                   break;
               case 'u':
                   user = optarg;
                   break;
               case 'x':
                   xattrs_user = optarg;
                   break;
               case 'a':
                   app = optarg;
                   break;
               case 'l':
                   list_users = 1;
                   break;
				case 'h':
               default: /* '?' */
                   fprintf(stderr, "Usage: %s [-r realm] [-u user] [-x user] [-a application] [-l] [-h]\n", argv[0]);
                   fprintf(stderr, "       -r: apply to specified realm\n");
                   fprintf(stderr, "       -u: get user info\n");
                   fprintf(stderr, "       -x: get user xattrs\n");
                   fprintf(stderr, "       -a: get application info\n");
                   fprintf(stderr, "       -l: get list of users\n");
                   fprintf(stderr, "       -h: display usage\n");
                   exit(0);
               }
  }
}

void get_user_info (char *user) {
	sp_user_info_t *user_info;

		if (sp_user_info (&user_info, user) == -1) {
			printf ("sp_user_info() returned error\n");
		} else {
			/* print user */
			printf ("nin =%s\n", user_info->nin);
			printf ("name =%s\n", user_info->name);
			printf ("surname =%s\n", user_info->surname);
			printf ("mobile =%s\n", user_info->mobile);
			printf ("rfid =%s\n", user_info->rfid);
			printf ("enabled =%s\n", user_info->enabled);
			printf ("token =%s\n", user_info->token);
			printf ("manager =%s\n", user_info->manager);
			printf ("password =%s\n", user_info->password);
			printf ("email =%s\n", user_info->email);
			free (user_info);
		}
}

void get_xattrs (char *user) {

	sp_xattrs_t *xattrs;

	if (sp_xattrs (&xattrs, user) == -1) {
		printf ("sp_xattrs() returned error\n");
	} else {
		/* print xattrs */
		printf ("posixuid =%s\n", xattrs->posixuid);
		printf ("posixgid =%s\n", xattrs->posixgid);
		printf ("posixhomedir =%s\n", xattrs->posixhomedir);
		printf ("posixshell =%s\n", xattrs->posixshell);
		printf ("posixgecos =%s\n", xattrs->posixgecos);
		free (xattrs);
	}
}

int main(int argc, char *argv[]) {
	char **user_list;
	int len, i;

	get_options(argc, argv);
	if (user) {
		get_user_info (user);
#if 0
		if (sp_user_info (&user_info, user) == -1) {
			printf ("sp_user_info() returned error\n");
		} else {
			/* print user */
			printf ("nin =%s\n", user_info->nin);
			printf ("name =%s\n", user_info->name);
			printf ("surname =%s\n", user_info->surname);
			printf ("mobile =%s\n", user_info->mobile);
			printf ("rfid =%s\n", user_info->rfid);
			printf ("enabled =%s\n", user_info->enabled);
			printf ("token =%s\n", user_info->token);
			printf ("manager =%s\n", user_info->manager);
			printf ("password =%s\n", user_info->password);
			printf ("email =%s\n", user_info->email);
			free (user_info);
		}
#endif
	} 
	if (xattrs_user) {
		get_xattrs (xattrs_user);
#if 0
		if (sp_xattrs (&xattrs, xattrs_user) == -1) {
			printf ("sp_xattrs() returned error\n");
		} else {
			/* print xattrs */
			printf ("posixuid =%s\n", xattrs->posixuid);
			printf ("posixgid =%s\n", xattrs->posixgid);
			printf ("posixhomedir =%s\n", xattrs->posixhomedir);
			printf ("posixshell =%s\n", xattrs->posixshell);
			printf ("posixgecos =%s\n", xattrs->posixgecos);
			free (xattrs);
		}
#endif
	} 
	if (app) {
	} 
	if (list_users) {
		len = sp_list_users (&user_list, realm);
		if (len == -1) {
			printf ("sp_list_users() returned error\n");
		} else {
			/* print list of users */
			for (i=0; i<len; i++) {
				printf ("\nUSERNAME = %s\n", *(user_list + i));
				get_user_info (*(user_list + i)); 
				get_xattrs (*(user_list + i)); 
			}
			free (user_list);
		}
	}		
	return (0);
}
