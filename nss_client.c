/*
 *
 * Author: gplll <gplll1818@gmail.com>, Oct 2014
 *  
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/types.h>
#include <pwd.h>
#include <pthread.h>

static int stress = 0;
static int verbose = 0;
static int num_threads = 2;
static char *user = NULL;
static uid_t uid = 0xffffffff;

void get_options (int argc, char *argv[]) 
{
	int opt;
	while ((opt = getopt(argc, argv, "hsp:u:i:v")) != -1) {
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
               case 'v':
                   verbose = 1;
                   break;
               case 'h':
               default: /* '?' */
                   fprintf(stderr, "Usage: %s [-s] [-p parallelism] [-v] [-u user] [-i uid]\n", argv[0]);
                   fprintf(stderr, "       -s: run multithreaded stress test\n");
                   fprintf(stderr, "       -p: specify number of threads for stress test (default is 2)\n");
                   fprintf(stderr, "       -v: verbose during multithreaded stress test\n");
                   fprintf(stderr, "       -u: get user from name\n");
                   fprintf(stderr, "       -i: get user from uid\n");
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

 
int main(int argc, char *argv[]) {
	struct passwd *pwd;
	int i;

	get_options(argc, argv);

	if (stress == 1) {
		pthread_t thread; 

		for (i = 0; i < num_threads; i++) {
			pthread_create (&thread, NULL, &getpw, NULL); 
		}
		pthread_join (thread, NULL);
	}
	if (user != NULL) {
		pwd = getpwnam (user);
		if (pwd == NULL) {
			printf ("user %s not found\n", user);
		}
		else {
			printf ("user=%s, uid=%u, gid=%u\n", pwd->pw_name, pwd->pw_uid, pwd->pw_gid);
		}
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
	else {
		setpwent ();
		while (1) {
			pwd = getpwent();
			if (pwd == NULL) {
				exit (0);
			}
			printf ("user=%s, uid=%u, gid=%u\n", pwd->pw_name, pwd->pw_uid, pwd->pw_gid);
		}
	}
	return (0);
}
