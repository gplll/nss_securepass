/*
 *
 * Author: gplll <gplll1818@gmail.com>, Oct 2014 - Feb 2017
 *  
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <pthread.h>
#include <ctype.h>
#include <string.h>

static int stress = 0;
static int verbose = 0;
static int num_threads = 2;
static char *user = NULL;
static char *group = NULL;
static uid_t uid = 0xffffffff;
static gid_t gid = 0xffffffff;

void get_options (int argc, char *argv[]) 
{
	int opt;
	while ((opt = getopt(argc, argv, "hsp:u:i:g:j:v")) != -1) {
               switch (opt) {
               case 's':
                   stress = 1;
                   break;
               case 'p':
                   num_threads = atoi (optarg);
                   break;
               case 'u':
                   user = optarg;
                   break;
               case 'i':
                   uid = (uid_t) (atoi (optarg));
                   break;
               case 'g':
                   group = optarg;
                   break;
               case 'j':
                   gid = (gid_t) (atoi (optarg));
                   break;
               case 'v':
                   verbose = 1;
                   break;
               case 'h':
               default: /* '?' */
                   fprintf(stderr, "Usage: %s [-s] [-p parallelism] [-v] [-u user] [-i uid] [-g group] [-j gid]\n", argv[0]);
                   fprintf(stderr, "       -s: run multithreaded stress test\n");
                   fprintf(stderr, "       -p: specify number of threads for stress test (default is 2 threads for passwd and 2 threads for group)\n");
                   fprintf(stderr, "       -v: verbose during multithreaded stress test\n");
                   fprintf(stderr, "       -u: get user from name\n");
                   fprintf(stderr, "       -i: get user from uid\n");
                   fprintf(stderr, "       -g: get group from name\n");
                   fprintf(stderr, "       -j: get group from gid\n");
                   fprintf(stderr, "       -h: display usage\n");
                   exit(0);
               }
  }
}

void* getpw (void* arg) {

	struct passwd *pwd;
	uint mypid = (uint) pthread_self();
	int num_loops = 0;
	int num_entries = 0;

	while (1) {
		num_loops++;
		num_entries = 0;
		setpwent ();
		if (verbose)
			printf ("thread id = %u, loop# = %d, setpwent() called\n", mypid, num_loops);
		while (1) {
			pwd = getpwent();
			if (verbose)
				printf ("thread id = %u, loop# = %d, entries read = %d\n", mypid, num_loops, num_entries);
			if (pwd == NULL) {
				break;
			}
			num_entries++;
		}
		printf ("thread id = %u, loop# = %d, endpwent() called, entries read = %d\n", mypid, num_loops, num_entries);
		endpwent ();
	}
	return NULL; 
} 

void* getgrp (void* arg) {

	struct group *grp;
	uint mypid = (uint) pthread_self();
	int num_loops = 0;
	int num_entries = 0;

	while (1) {
		num_loops++;
		num_entries = 0;
		setgrent ();
		if (verbose)
			printf ("thread id = %u, loop# = %d, setgrent() called\n", mypid, num_loops);
		while (1) {
			grp = getgrent();
			if (verbose)
				printf ("thread id = %u, loop# = %d, entries read = %d\n", mypid, num_loops, num_entries);
			if (grp == NULL) {
				break;
			}
			num_entries++;
		}
		printf ("thread id = %u, loop# = %d, endgrent() called, entries read = %d\n", mypid, num_loops, num_entries);
		endgrent ();
	}
	return NULL; 
} 
 
int main(int argc, char *argv[]) {
	struct passwd *pwd;
	struct group *grp;
	int i;

	get_options(argc, argv);

	if (stress == 1) {
		pthread_t thread; 

		for (i = 0; i < num_threads; i++) {
			pthread_create (&thread, NULL, &getpw, NULL); 
		}
		for (i = 0; i < num_threads; i++) {
			pthread_create (&thread, NULL, &getgrp, NULL); 
		}
		pthread_join (thread, NULL);
	}
	if (user != NULL) {
		struct passwd p, *presult;
		int buflen = 1000;
		char buf[buflen];
		int rc = getpwnam_r(user, &p, buf, buflen, &presult);
        if ((rc != 0) || (presult == NULL)) {
            printf ("getpwnam_r returned error (%d) or user %s not found\n", rc, user);
        } 
		else {
			printf ("user=%s, uid=%u, gid=%u\n", p.pw_name, p.pw_uid, p.pw_gid);
		}
/*
		pwd = getpwnam (user);
		if (pwd == NULL) {
			printf ("user %s not found\n", user);
		}
		else {
			printf ("user=%s, uid=%u, gid=%u\n", pwd->pw_name, pwd->pw_uid, pwd->pw_gid);
		}
*/
		exit (0);	
	}
	if (uid != 0xffffffff) {
		pwd = getpwuid (uid);
		if (pwd == NULL) {
			printf ("userid %u not found\n", uid);
		}
		else {
			printf ("user=%s, uid=%u, gid=%u\n", pwd->pw_name, pwd->pw_uid, pwd->pw_gid);
		}
		exit (0);	
	}
	if (group != NULL) {
		struct group g, *gresult;
		int buflen = 1000;
		char buf[buflen];
		int rc = getgrnam_r (group, &g, buf, buflen, &gresult);
        if ((rc != 0) || (gresult == NULL)) {
            printf ("getgrnam_r returned error (%d) or group %s not found\n", rc, group);
        } 
		else {
			printf ("group=%s, gid=%u\nmembers=", g.gr_name, g.gr_gid);
			char **members = g.gr_mem;
			while (*members)
			{
				printf ("%s,", *(members));
				members++;
			}
			printf ("\n");
			
		}
		exit (0);	
	}
	if (gid != 0xffffffff) {
		grp = getgrgid (gid);
		if (grp == NULL) {
			printf ("groupid %u not found\n", gid);
		}
		else {
			printf ("group=%s, gid=%u\nmembers=", grp->gr_name, grp->gr_gid);
			char **members = grp->gr_mem;
			while (*members)
			{
				printf ("%s,", *(members));
				members++;
			}
			printf ("\n");
		}
		exit (0);	
	}
	else {
		setpwent ();
		while (1) {
			pwd = getpwent();
			if (pwd == NULL) {
				break;
			}
			printf ("user=%s, uid=%u, gid=%u\n", pwd->pw_name, pwd->pw_uid, pwd->pw_gid);
		}
		endpwent ();
		setgrent ();
		while (1) {
			grp = getgrent();
			if (grp == NULL) {
				exit (0);
			}
			printf ("group=%s, gid=%u\n", grp->gr_name, grp->gr_gid);
		}
		endgrent ();
	}
	return (0);
}
