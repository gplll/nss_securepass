/*
 *
 * Author: gplll <gplll1818@gmail.com>, Oct 2014 - Feb 2017
 *  
 */

#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <ctype.h>
#include <string.h>
#include "sp_api.h"

char *realm = NULL;
char *user = NULL;
char *group = NULL;
char *groupm = NULL;
char *xattrs_user = NULL;
char *app = NULL;
int list_users = 0;
int verbose = 0;
char *user_pwd = NULL;
char *user_secret = NULL;

void get_options (int argc, char *argv[]) 
{
	int opt;
	while ((opt = getopt(argc, argv, "hvr:u:g:x:m:a:lw:t:")) != -1) {
               switch (opt) {
               case 'r':
                   realm = optarg;
                   break;
               case 'u':
                   user = optarg;
                   break;
               case 'g':
                   group = optarg;
                   break;
               case 'm':
                   groupm = optarg;
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
               case 'w':
				   user_pwd = optarg;
                   break;
               case 't':
				   user_secret = optarg;
                   break;
               case 'v':
				   verbose = 1;
                   break;
				case 'h':
               default: /* '?' */
                   fprintf(stderr, "Usage: %s [-r realm] [-u user] [-x user] [-g group] [-m group] [-a application] [-l] [-w 'user password'] [-t 'user secret'] [-v] [-h]\n", argv[0]);
                   fprintf(stderr, "       -r: apply to specified realm\n");
                   fprintf(stderr, "       -u: get user info\n");
                   fprintf(stderr, "       -x: get user xattrs\n");
                   fprintf(stderr, "       -g: get group xattrs\n");
                   fprintf(stderr, "       -m: get group members\n");
                   fprintf(stderr, "       -a: get application info\n");
                   fprintf(stderr, "       -l: get list of users and groups\n");
                   fprintf(stderr, "       -w: set user password\n");
                   fprintf(stderr, "       -t: authenticate user (secret is the concatenation of OTP and pwd)\n");
                   fprintf(stderr, "       -v: display usage\n");
                   fprintf(stderr, "       -h: display usage\n");
                   exit(0);
               }
  }
}

void get_user_info (char *user) {
	sp_users_info_t *user_info;

		if (sp_users_info (&user_info, user) == -1) {
			printf ("sp_users_info() returned error\n");
		} else {
			/* print user */
			printf ("nin = %s\n", user_info->nin);
			printf ("name = %s\n", user_info->name);
			printf ("surname = %s\n", user_info->surname);
			printf ("mobile = %s\n", user_info->mobile);
			printf ("rfid = %s\n", user_info->rfid);
			printf ("enabled = %s\n", user_info->enabled);
			printf ("token = %s\n", user_info->token);
			printf ("manager = %s\n", user_info->manager);
			printf ("password = %s\n", user_info->password);
			printf ("email = %s\n", user_info->email);
			free (user_info);
		}
}

void get_xattrs (char *user) {

	sp_users_xattrs_t *xattrs;

	if (sp_users_xattrs (&xattrs, user, 0) == -1) {
		printf ("sp_users_xattrs() returned error\n");
	} else {
		/* print xattrs */
		printf ("posixuid = %s\n", xattrs->posixuid);
		printf ("posixgid = %s\n", xattrs->posixgid);
		printf ("posixhomedir = %s\n", xattrs->posixhomedir);
		printf ("posixshell = %s\n", xattrs->posixshell);
		printf ("posixgecos = %s\n", xattrs->posixgecos);
		free (xattrs);
	}
}

void get_group_info (char *group) {

	sp_groups_xattrs_t *xattrs;

	if (sp_groups_xattrs (&xattrs, group) == -1) {
		printf ("sp_groups_xattrs() returned error\n");
	} else {
		/* print xattrs */
		printf ("posixgid = %s\n", xattrs->posixgid);
		free (xattrs);
	}
}

void set_passwd (char *user_pwd) {
	char *user = strtok (user_pwd, " ");
	char *pwd = strtok (NULL, " ");
	if ((user == NULL) || (pwd == NULL)) {
		printf ("argument must be in the form 'user pwd'\n");
	} else {
		/* printf ("user=%s pwd=%s\n", user, pwd); */
		if (sp_user_password_change (user, pwd) == -1) {
			printf ("sp_user_password_change() returned error\n");
		} else {
			printf ("password has been set\n");
		}	
	}	
}

void user_auth (char *user_secret) {
	char *user = strtok (user_secret, " ");
	char *secret = strtok (NULL, " ");
	if ((user == NULL) || (secret == NULL)) {
		printf ("argument must be in the form 'user secret'\n");
	} else {
		/* printf ("user=%s secret=%s\n", user, secret); */
		if (sp_user_auth (user, secret) == -1) {
			printf ("sp_user_auth() returned error for user %s\n", user);
		} else {
			printf ("user %s has been authenticated\n", user);
		}	
	}	
}

int main(int argc, char *argv[]) {
	char **user_list, **group_list;
	int len, i;

	get_options(argc, argv);
	if (user) {
		get_user_info (user);
	} 
	if (xattrs_user) {
		get_xattrs (xattrs_user);
	} 
	if (group) {
		get_group_info (group);
	} 
	if (groupm) {
		len = sp_groups_members_list (&user_list, groupm, realm);
		if (len == -1) {
			printf ("sp_group_members_list() returned error\n");
		} else {
			/* print list of users */
			for (i=0; i<len; i++) {
				printf ("USER: %s\n", *(user_list + i));
			}
			free (user_list);
		}
	} 
	if (app) {
			printf ("-a option is not yet implemented\n");
	} 
	if (list_users) {
		len = sp_users_list (&user_list, realm);
		if (len == -1) {
			printf ("sp_users_list() returned error\n");
		} else {
			/* print list of users */
			for (i=0; i<len; i++) {
				printf ("USER: %s\n", *(user_list + i));
				if (verbose) {
					get_user_info (*(user_list + i)); 
					get_xattrs (*(user_list + i)); 
					printf ("\n");
				}
			}
			free (user_list);
		}
		len = sp_groups_list (&group_list, realm);
		if (len == -1) {
			printf ("\nsp_groups_list() returned error\n");
		} else {
			/* print list of groups */
			for (i=0; i<len; i++) {
				printf ("GROUP: %s\n", *(group_list + i));
			}
			free (group_list);
		}
	}		
	if (user_pwd) {
		set_passwd (user_pwd);
	} 
	if (user_secret) {
		user_auth (user_secret);
	} 
	return (0);
}
