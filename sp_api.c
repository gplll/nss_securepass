/*
 *
 * Author: gplll <gplll1818@gmail.com>, Oct 2014 - Feb 2017
 *  
 */

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <malloc.h>
#include <ctype.h>
#include <string.h>
#include <syslog.h>
#include <pthread.h>
#include <curl/curl.h>
#include "minIni.h"
#include "jsmn.h"
#include "sp_api.h"
#include "nss_sp.h"

#define SP_CONFFILE "/etc/securepass.conf"
#define MANDATORY_PARAMS_NUMBER 6 /* number of mandatory params to be read from config file */
#define ACCEPT "Accept: application/json"
#define CONTENT_TYPE "Content-type: SecurePass CLI"
#define DEFAULT_HOME "/home/"
#define DEFAULT_SHELL "/bin/false"

#define IS_ARRAY(t) ((t).type == JSMN_ARRAY)
#define IS_OBJECT(t) ((t).type == JSMN_OBJECT)
#define TOK_CMP(js, t, s) \
     ((strlen(s) == (t).end - (t).start) \
     && (strncmp(js+(t).start, s, (t).end - (t).start) == 0))
     
#define SP_INIT \
    if (sp_config.status != SP_INITED) { \
        if (sp_init () == -1) return -1; \
    }

struct sp_config sp_config ={SP_NOT_INITED, 0, 0, "", "", "", "", "", "", "", "", "", "", "", 
    DEFAULT_HOME, DEFAULT_SHELL, ""};

struct MemoryStruct {
  char *memory;
  size_t size;
};
int param_count = 0; /* number of parameters read from config file */
char *types[] = {"PRIMITIVE", "OBJECT","ARRAY","STRING"};
 
static pthread_mutex_t sp_init_lock = PTHREAD_MUTEX_INITIALIZER; /* Lock protecting the initialization data */
# define SP_INIT_ENTER		pthread_mutex_lock (&sp_init_lock)
# define SP_INIT_LEAVE		pthread_mutex_unlock (&sp_init_lock)

/*
 * checks a key/value found in config file and fills the output variable adding a prefix and postfic
 * key: key found in config file (eg. APP_IP)
 * value: value associated to key into config file
 * key_to_chk: value is copied if key_to_chk and key match
 * result: output variable - is mallocated() within this function
 * prefix: string to be prefixed to value
 * postfix: string to be postfixed to value 
 * mandatory: param is mandatory, increment param_count global variable
 */
void check_ini_string (const char *key, const char *value, const char *key_to_chk, char **result, 
						char *prefix, char *postfix, int mandatory) {

		int pre_len = 0, post_len = 0;
		if (strcmp (key, key_to_chk) == 0) {
			if (prefix != NULL) {
				pre_len = strlen (prefix);
			}
			if (postfix != NULL) {
				post_len = strlen (postfix);
			}
			if ((*result = malloc (strlen (value) + pre_len + post_len + 1)) == NULL) {
				error ("malloc() failed");
				return;
			}
			**result = 0;
			if (prefix != NULL) {
				strcpy (*result, prefix);
			}
			strcat (*result, value);
			if (postfix != NULL) {
				strcat (*result, postfix);
			}
			if (mandatory)
				param_count++;
		}
}

int IniCallback(const char *section, const char *key, const char *value, const void *userdata)
{
	/* copy key to local variable and force lower case */
	char key1[strlen(key) + 1];
	strcpy (key1, key);
	char *k = key1;
	int i = 0;
	for (; key1[i]; i++){
		  key1[i] = tolower(key1[i]);
	}

	if ((strcmp (k, "app_id") == 0) || (strcmp (k, "app_secret") == 0)) {
		debug (2, "IniCallback:    [%s] %s=****************", section, k);
	} 
	else {
		debug (2, "IniCallback:    [%s] %s=%s", section, k, value);
	}
	if (strcmp (section, "default") == 0) {
		check_ini_string (k, value, "app_id", &sp_config.app_id, "X-SecurePass-App-ID:", NULL, 1);
		check_ini_string (k, value, "app_secret", &sp_config.app_secret, "X-SecurePass-App-Secret:", NULL, 1);
		check_ini_string (k, value, "endpoint", &sp_config.URL_users_list, NULL, "/api/v1/users/list", 1);
		check_ini_string (k, value, "endpoint", &sp_config.URL_users_info, NULL, "/api/v1/users/info", 1);
		check_ini_string (k, value, "endpoint", &sp_config.URL_users_xattrs_list, NULL, "/api/v1/users/xattrs/list", 1);
		check_ini_string (k, value, "endpoint", &sp_config.URL_groups_list, NULL, "/api/v1/groups/list", 1);
		check_ini_string (k, value, "endpoint", &sp_config.URL_groups_xattrs_list, NULL, "/api/v1/groups/xattrs/list", 1);
		check_ini_string (k, value, "endpoint", &sp_config.URL_groups_members_list, NULL, "/api/v1/groups/members/list", 1);
		check_ini_string (k, value, "endpoint", &sp_config.URL_u_pwd_chg, NULL, "/api/v1/users/password/change", 1);
		check_ini_string (k, value, "endpoint", &sp_config.URL_u_auth, NULL, "/api/v1/users/auth", 1);
		if (strcmp (k, "debug") == 0) {
			sp_config.debug = atoi (value);
		}
		if (strcmp (k, "debug_stderr") == 0) {
			sp_config.debug_stderr = atoi (value);
		}
	}
	if (strcmp (section, "nss") == 0) {
		check_ini_string (k, value, "realm", &sp_config.realm, NULL, NULL, 1);
		check_ini_string (k, value, "default_gid", &sp_config.default_gid, NULL, NULL, 0);
		check_ini_string (k, value, "default_home", &sp_config.default_home, NULL, "/", 0);
		check_ini_string (k, value, "default_shell", &sp_config.default_shell, NULL, NULL, 0);
	}
	return 1;
}

int sp_init() {
	SP_INIT_ENTER;
	if (sp_config.status == SP_INITED) {
		SP_INIT_LEAVE;
		return 1;
    }	
	if ((sp_config.status == SP_ERROR)) {
		SP_INIT_LEAVE;
		return -1;
	}

#if 1 
/*
 * Flag LOG_CONS is needed at boot/init time, before syslogd is started
 * But even with this flag, randomly /etc/init or any of its children hangs when debugging is enabled 
 */
	openlog (NULL, LOG_CONS, 0); 
#endif

	/* read config. files and fill sp_config */
	ini_browse(IniCallback, NULL, SP_CONFFILE);
	if (param_count < MANDATORY_PARAMS_NUMBER) {
		error ("sp_init: missing config file or missing mandatory parameter in configfile");
		sp_config.status = SP_ERROR;
		SP_INIT_LEAVE;
		return -1;
	}
	debug (2, "==> sp_init");
	/* call non-thread safe curl init function */
	curl_global_init(CURL_GLOBAL_ALL);

	sp_config.status = SP_INITED;
	SP_INIT_LEAVE;
	return 1;
}

static size_t
read_from_url(void *contents, size_t size, size_t nmemb, void *userp)
{
  size_t realsize = size * nmemb;
  struct MemoryStruct *mem = (struct MemoryStruct *)userp;
 
  debug (4, "==> read_from_url; size=%u, nmemb=%u\n", (unsigned int) size, (unsigned int) nmemb);
  mem->memory = realloc(mem->memory, mem->size + realsize + 1);
  if(mem->memory == NULL) {
	error ("realloc() failed");
    return 0;
  }
 
  memcpy(&(mem->memory[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = 0;
 
  return realsize;
}

int p_json = 0;
int w_stdout = 0;
char *url;

int parse_json (char *js, int len, jsmntok_t *tok, int num_tok)
{
    jsmn_parser p;
    int r, i, s, e;
	char saved;

	debug (4, "==> parse_json");
    jsmn_init(&p);
    r = jsmn_parse(&p, js, len, tok, num_tok);
	if (r <= 0) {
		error ("jsmn_parse returned error (%d)", r);
		return r;
	}
	if (sp_config.debug || sp_config.debug_stderr) {
		for (i = 0; i < r; i++) {
			s = tok[i].start;
			e = tok[i].end; 
			saved = js[e];
			js[e] = 0;
       	 	debug  (4, "tok.type = %s", types[tok[i].type]);
       		debug  (4, "value = %s", js + s);
			js[e] = saved;
    	} 
    } 
	return r;
}

int  skip_array (jsmntok_t *tok, int size) {
    int i;
    for (i = 0; i < size; i++, tok++) {
        if (IS_ARRAY(*tok)) {
            return (i + skip_array (tok + 1, tok->size));
        }
        if (IS_OBJECT(*tok)) {
            return -1;
        }
    }
    return i;
}

static int get_tok (char *js, jsmntok_t *tok, int ntok, char *s) {
	int i; 
	int do_cmp = ~(0); /* only compare first value into token pair */
    if (tok->type != JSMN_OBJECT) {
        return -1;
    }
	for (i = 1, tok++; i < ntok; ) { 
	
		/* we don't expect nested Objects */
		 if (IS_OBJECT(*tok)) {
			return -1;
         }
		/* if token is an array, skip it */	
		 if (IS_ARRAY(*tok)) {
			int skip = skip_array (tok + 1, tok->size);
			if (skip == -1) {
				return -1;
			}
			i += skip + 1;
			tok += skip + 1;
			do_cmp = ~(do_cmp);
			continue;
        }
		/* simple token: compare only if first value into pair and return index of second value if matched */
		if ((do_cmp) && (TOK_CMP(js, *tok, s))) {
			return (i + 1);
		}
		do_cmp = ~(do_cmp);
		i += 1;
		tok += 1;
	}
	return -1;
}

/*
 * checks if token "rc" is present into the JSON string and if its value is 0
 * returns 0 if error, 1 if success
 */
static int rc_ok (char *js, jsmntok_t *tok, int ntok) {
	debug (4, "==> rc_ok");
	int r = get_tok (js, tok, ntok, "rc");
	if (r == -1) {
		debug (2, "token rc not found in JSON response");
		return 0;
	}
	if (TOK_CMP (js, tok[r], "0") == 0) {
		debug (2, "token rc has wrong value, expected 0");
		return 0;
	}
	return 1;
}

/* cp_tok_t is used by caller and callee to maintain the state between a series of calls to copy_tok() */
typedef struct {
	char *buf;
	int buflen;
	int offset;
	int status;
} cp_tok_t;

/*
 * copy_tok() copies the second token of a JSON pair into user buffer, if the first token matches a given string
 * js: pointer to the JSON buffer
 * tok: JSMN pointers to JSON tokens
 * ntok: number of JMNS pointers
 * cp_tok->buf: output user buffer - must be allocated by caller
 * cp_tok->buflen: buffer length
 * cp_tok->offset: buffer offset where to copy the token found. 
 * cp_tok->status: set to 0 if SUCCESS, set to -1 if not enough space to contain the token found. 
 *                  In this case offset will contain the new buffer lenght to hold the token to be copied
 * first: value to be matched for first token 
 * s_def: string to be returned if not matched
 */
static void copy_tok (char *js, jsmntok_t *tok, int ntok, cp_tok_t *cp_tok, char *first,
						char *s_def) {
	debug (4, "==> copy_tok");
	int r = get_tok (js, tok, ntok, first);
	if (r == -1) {
		/* token not found in JSON buffer: copy the default string into user buffer */
		debug (4, "token %s not found in JSON response", first);
		int l = strlen (s_def); 
		if ((cp_tok->buflen - cp_tok->offset) < (l + 1)) {
			/* buffer is too small. Set error into cp_tok descriptor and update offset */
			cp_tok->status = -1;
			cp_tok->offset += (l + 1);
			return;
		}
		if (cp_tok->status != -1) {
			/* if cp_tok descriptor has error set, don't copy back data and only update offset */
			strcpy (cp_tok->buf + cp_tok->offset, s_def);
		}
		cp_tok->offset += (l + 1); 
	}
	else {
		/* token found in JSON buffer */
		int l = tok[r].end - tok[r].start;
		if ((cp_tok->buflen - cp_tok->offset) < (l + 1)) {
			/* buffer is too small. Set error into cp_tok descriptor and update offset */
			cp_tok->status = -1;
			cp_tok->offset += (l + 1);
			return;
		}
		if (cp_tok->status != -1) {
			/* if cp_tok descriptor has error set, don't copy back data and only update offset */
			memcpy (cp_tok->buf + cp_tok->offset, (js + tok[r].start), l);
			*(cp_tok->buf + cp_tok->offset + l) = 0;
		}
		cp_tok->offset += (l + 1);
		return;
	}
}

/*
 * returns -1 if error or 0 tokens found, otherwise the number of JSON tokens returned
 * chunk must be allocated by the caller
 * chunk->memory is allocated within this function and will be freed by caller
 * (*tok) is allocated within this function and will be freed by caller
 */
static int do_curl (const char *url, char *post_data, jsmntok_t **tok, struct MemoryStruct *chunk) {
	CURLcode res;
	CURL *curl_handle;
	struct curl_slist *slist=NULL;
    jsmn_parser p;
	int num_tok;

	debug (2, "==> do_curl");
	chunk->memory = NULL;    /* will be grown as needed by realloc */
	chunk->size = 0;    /* no data at this point */ 
 
	curl_handle = curl_easy_init();
  	if (!curl_handle) {
		error ("curl_easy_easy_init() failed");
		return -1;
  	}
	curl_easy_setopt(curl_handle, CURLOPT_URL, url);

	/* add HTTP headers */
	slist = curl_slist_append(slist, sp_config.app_id);  
	slist = curl_slist_append(slist, sp_config.app_secret);  
	slist = curl_slist_append(slist, ACCEPT);  
	slist = curl_slist_append(slist, CONTENT_TYPE);  

	curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, slist);

	/* set SSL options */
	curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, 0L);
	curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYHOST, 0L);

	if (post_data != NULL)
	    curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, post_data);   
 
  /* send all data to this function  */ 
  curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, read_from_url);
	 
  /* we pass our 'chunk' struct to the callback function */ 
  curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)chunk);
  res = curl_easy_perform(curl_handle);
  curl_slist_free_all(slist); /* free the list again */ 
  curl_easy_cleanup(curl_handle);
  if (res != CURLE_OK) {
	error ("curl_easy_perfom() returned error (%d)", res);
	return -1;
  }
	/* 
     * number of returned bytes divided by 4 is quite a large upper bound for number of tokens to be allocated
	 * in case they are not enough, we'll ask Jasmine how many tokens we need to allocate
	 */
	num_tok = (chunk->size/4);
	*tok = malloc (num_tok * sizeof(jsmntok_t));
	if (*tok == NULL) {
		error ("malloc() failed");
		return -1;
	}
	while (1) {
		res = parse_json (chunk->memory, chunk->size, *tok, num_tok);
		if (res == (CURLcode) JSMN_ERROR_NOMEM) {
    		jsmn_init(&p);
    		num_tok = jsmn_parse(&p, chunk->memory, chunk->size, (jsmntok_t *)NULL, 0);
			if (num_tok < 0) {
				error ("jsmn_parse() returned error (%d)", num_tok);
				return -1;
			}
			*tok = realloc (*tok, num_tok * sizeof(jsmntok_t));
			if (*tok == NULL) {
				error ("realloc() failed");
				return -1;
			}
			continue;
		}
		if (res <= 0) {
			return -1;
		} else {
			return res; 
		}
	}
}

/*
 * returns 1 if SUCCESS, -1 if error
 * xattrs: pointer to a sp_xattrs_t that will be allocated by this function
 * caller will free() the structure after use
 * username: specifies the username in SecurePass format, i.e. user@realm
 * get_defaults: 
 *   if 1: when no value is returned by securepass for a token, return default values from config file
 *   if 0: when no value is returned by securepass for a token, return an empty value
 */
int sp_users_xattrs (sp_users_xattrs_t **xattrs, char *sp_username, int get_defaults) {
	int len;
	jsmntok_t *tok;
	struct MemoryStruct chunk;

	SP_INIT;
	debug (2, "==> sp_users_xattrs");
	if (sp_username == NULL)  {
		error ("sp_users_xattrs() called with username=NULL");
		return -1;
	}

	/* call curl */
	char post_data[(strlen ("USERNAME=") + strlen (sp_username) + 1)];
	sprintf (post_data, "%s%s", "USERNAME=", sp_username);
	len = do_curl(sp_config.URL_users_xattrs_list, post_data, &tok, (struct MemoryStruct *) &chunk);
	if (len == -1) {
		return -1;
	}
	/* check for value of rc token */
	if (!(rc_ok (chunk.memory, tok, len))) {
		free (tok);
		free (chunk.memory);
		return -1;
	}
	/* prepare default values */
	char *def_gid;
	char *def_home;
	char *def_shell;
	int l1 = strlen (sp_config.default_home);
	int l2 = strlen (strtok (sp_username, "@"));
	char home [(l1 + l2 + 1)];
	if (get_defaults) {
		def_gid = sp_config.default_gid;	

		def_home = home;
		sp_username[l2] = 0;
		strcat ((strcpy (home, sp_config.default_home)), sp_username);
		sp_username[l2] = '@';

		def_shell = sp_config.default_shell;	
	}
	else {
		def_gid = def_home = def_shell = "";
	}
	/*
	 * Allocate buffer to be returned and copy data to it. 
     * size of sp_users_xattrs_t + chunk.size + sum of lenghts of default values + 1 string terminator 
     * for each output field are un upper bound to contain the user info. 
     */
	cp_tok_t cp_tok;
	cp_tok.buflen = sizeof (sp_users_xattrs_t) + chunk.size + strlen (def_gid) +
					strlen (def_home) + strlen (def_shell) + 5;
	cp_tok.buf = malloc (cp_tok.buflen);
	if (!(cp_tok.buf)) {
		error ("malloc() failed");
		free (tok);
		free (chunk.memory);
		return -1;
	}
	cp_tok.offset = sizeof (sp_users_xattrs_t); 
	cp_tok.status = 0; /* status = OK */ 

    /* copy the values to the buffer */
	*xattrs = (sp_users_xattrs_t *) cp_tok.buf;
	(*xattrs)->size = cp_tok.buflen; /* copy the size of the returned buffer */

	/* for each field into the structure, set the pointer and copy the returned value */
	(*xattrs)->posixuid = cp_tok.buf + cp_tok.offset;
	copy_tok (chunk.memory, tok, len, &cp_tok, "posixuid", "");

	(*xattrs)->posixgid = cp_tok.buf + cp_tok.offset;
	copy_tok (chunk.memory, tok, len, &cp_tok, "posixgid", def_gid);

	(*xattrs)->posixhomedir = cp_tok.buf + cp_tok.offset;
	copy_tok (chunk.memory, tok, len, &cp_tok, "posixhomedir", def_home);

	(*xattrs)->posixshell = cp_tok.buf + cp_tok.offset;
	copy_tok (chunk.memory, tok, len, &cp_tok, "posixshell", def_shell);

	(*xattrs)->posixgecos = cp_tok.buf + cp_tok.offset;
	copy_tok (chunk.memory, tok, len, &cp_tok, "posixgecos", sp_username);

#if 0
	/* 
	 * the code below is not needed anymore, as now the user buffer is sized from the start to
	 * contain all the user info. I've also removed the rounding while(1) loop to do the realloc.
	 */
	if (cp_tok.status == -1) {
		/* buffer is too small. Reallocate with the size computed by copy_tok() in previous calls */
		debug (2, "reallocating buffer from %d to %d bytes", cp_tok.buflen, cp_tok.offset);
		cp_tok.buflen = cp_tok.offset;
		cp_tok.offset = sizeof (sp_users_xattrs_t); 
		cp_tok.status = 0; 
		if ((cp_tok.buf = realloc (cp_tok.buf, cp_tok.buflen)) == NULL ) {
			error ("realloc(%d) failed", cp_tok.buflen);
			free (tok);
			free (chunk.memory);
			return -1;
		}
		continue;
	}
#endif
	free (chunk.memory);
	if (cp_tok.status == -1) {
		error ("copy_tok returned unexpected error, cp_tok.buflen=%d, cp_tok.offset=%d", 
				cp_tok.buflen, cp_tok.offset);
		free (tok);
		return -1;
	}
	free (tok);
	debug (4, "sp_users_xattrs(%s) returning buffer_size= %d number_of_bytes=%d", 
			sp_username, cp_tok.buflen, cp_tok.offset);
	return 1;
}

/*
 * returns 1 if SUCCESS, -1 if error
 * xattrs: pointer to a sp_users_xattrs_t that will be allocated by this function
 * caller will free() the structure after use
 * username: specifies the username in Posix format, i.e. user
 */
int sp_users_xattrs_p (sp_users_xattrs_t **xattrs, const char *username, int get_defaults) {

	SP_INIT;
	if (username == NULL)  {
		error ("sp_users_xattrs_p() called with username=NULL");
		return -1;
	}
	/* concatenate realm to name */
 	char sp_name[(strlen (username) + strlen (sp_config.realm) + 2)]; 
	sprintf (sp_name, "%s%s%s", username, "@", sp_config.realm);
	int rc = sp_users_xattrs (xattrs, sp_name, get_defaults);

	return rc;
}

/*
 * returns 1 if SUCCESS, -1 if error
 * xattrs: pointer to a sp_xattrs_t that will be allocated by this function
 * caller will free() the structure after use
 * groupname: specifies the groupname in SecurePass format, i.e. group@realm
 */
int sp_groups_xattrs (sp_groups_xattrs_t **xattrs, char *sp_groupname) {
	int len;
	jsmntok_t *tok;
	struct MemoryStruct chunk;

	SP_INIT;
	debug (2, "==> sp_groups_xattrs (%s)", sp_groupname);
	if (sp_groupname == NULL)  {
		error ("sp_groups_xattrs() called with groupname=NULL");
		return -1;
	}

	/* call curl */
	char post_data[(strlen ("GROUP=") + strlen (sp_groupname) + 1)];
	sprintf (post_data, "%s%s", "GROUP=", sp_groupname);
	len = do_curl(sp_config.URL_groups_xattrs_list, post_data, &tok, (struct MemoryStruct *) &chunk);
	if (len == -1) {
		return -1;
	}
	/* check for value of rc token */
	if (!(rc_ok (chunk.memory, tok, len))) {
		free (tok);
		free (chunk.memory);
		return -1;
	}
	/*
	 * Allocate buffer to be returned and copy data to it. 
     * size of sp_groups_xattrs_t + chunk.size + 1 string terminator for each output fields
     * is an upper bound to contain the user info.
     */
	cp_tok_t cp_tok;
	cp_tok.buflen = sizeof (sp_groups_xattrs_t) + chunk.size + 1;
	cp_tok.buf = malloc (cp_tok.buflen);
	if (!(cp_tok.buf)) {
		error ("malloc() failed");
		free (tok);
		free (chunk.memory);
		return -1;
	}
	cp_tok.offset = sizeof (sp_groups_xattrs_t); 
	cp_tok.status = 0; /* status = OK */ 

	*xattrs = (sp_groups_xattrs_t *) cp_tok.buf;

	/* for each field into the structure, set the pointer and copy the returned value */
	(*xattrs)->posixgid = cp_tok.buf + cp_tok.offset;
	copy_tok (chunk.memory, tok, len, &cp_tok, "posixgid", "");
	free (chunk.memory);
	if (cp_tok.status == -1) {
		error ("copy_tok returned unexpected error, cp_tok.buflen=%d, cp_tok.offset=%d", 
				cp_tok.buflen, cp_tok.offset);
		free (tok);
		return -1;
	}
	debug (4, "sp_groups_xattrs(%s) returning buffer_size= %d number_of_bytes=%d", 
			sp_groupname, cp_tok.buflen, cp_tok.offset);
	free (tok);
	return 1;
}

/*
 * returns 1 if SUCCESS, -1 if error
 * xattrs: pointer to a sp_groups_xattrs_t that will be allocated by this function
 * caller will free() the structure after use
 * groupname: specifies the groupname in Posix format, i.e. user
 */
int sp_groups_xattrs_p (sp_groups_xattrs_t **xattrs, const char *groupname) {

	SP_INIT;
	if (groupname == NULL)  {
		error ("sp_groups_xattrs_p() called with groupname=NULL");
		return -1;
	}
	/* concatenate realm to name */
 	char sp_name[(strlen (groupname) + strlen (sp_config.realm) + 2)]; 
	sprintf (sp_name, "%s%s%s", groupname, "@", sp_config.realm);
	int rc = sp_groups_xattrs (xattrs, sp_name);

	return rc;
}

/*
 * returns 1 if SUCCESS, -1 if error
 * sp_username: specifies the username in SecurePass format, i.e. group@realm
 * pwd: password to set
 */
int sp_user_password_change (const char *sp_username, const char* pwd) {

	int len;
	jsmntok_t *tok;
	struct MemoryStruct chunk;

	SP_INIT;
	/*	debug (4, "==> sp_user_password_change sp_username=%s pwd=%s", sp_username, pwd); */
	debug (2, "==> sp_user_password_change sp_username=%s", sp_username);
	if (sp_username == NULL)  {
		error ("sp_user_password_change() called with username=NULL");
		return -1;
	}
	if (pwd == NULL)  {
		error ("sp_user_password_change() called with password=NULL");
		return -1;
	}
	/* call curl */
	char post_data[(strlen ("USERNAME=") + strlen (sp_username) + strlen ("PASSWORD") + strlen (pwd) + 2)];
	sprintf (post_data, "USERNAME=%s&PASSWORD=%s", sp_username, pwd);
	len = do_curl(sp_config.URL_u_pwd_chg, post_data, &tok, (struct MemoryStruct *) &chunk);
	if (len == -1) {
		return -1;
	}
	/* check for value of rc token */
	if (!(rc_ok (chunk.memory, tok, len))) {
		free (tok);
		free (chunk.memory);
		return -1;
	}
	return 1;
}

/*
 * returns 1 if SUCCESS, -1 if error
 * username: specifies the username in Posix format, i.e. user
 * pwd: password to set
 */
int sp_user_password_change_p (const char *username, const char* pwd) {

	SP_INIT;
	if (username == NULL)  {
		error ("sp_user_password_change_p() called with username=NULL");
		return -1;
	}
	/* concatenate realm to name */
 	char sp_name[(strlen (username) + strlen (sp_config.realm) + 2)]; 
	sprintf (sp_name, "%s%s%s", username, "@", sp_config.realm);
	return sp_user_password_change (sp_name, pwd);
}

/*
 * returns 1 if SUCCESS, -1 if error
 * sp_username: specifies the username in SecurePass format, i.e. user@realm
 * secret: concatenation of OTP and password
 */
int sp_user_auth (const char *sp_username, const char* secret) {

	int len;
	jsmntok_t *tok;
	struct MemoryStruct chunk;

	SP_INIT;
	/* debug (4, "==> sp_user_auth, sp_username=%s secret=%s", sp_username, secret); */
	debug (2, "==> sp_user_auth, sp_username=%s", sp_username);
	if (sp_username == NULL)  {
		error ("sp_user_auth() called with username=NULL");
		return -1;
	}
	if (secret == NULL)  {
		error ("sp_user_auth() called with secret=NULL");
		return -1;
	}
	/* call curl */
	char post_data[(strlen ("USERNAME=") + strlen (sp_username) + strlen ("SECRET") + strlen (secret) + 2)];
	sprintf (post_data, "USERNAME=%s&SECRET=%s", sp_username, secret);
	len = do_curl(sp_config.URL_u_auth, post_data, &tok, (struct MemoryStruct *) &chunk);
	if (len == -1) {
		return -1;
	}
	/* check for value of rc token */
	if (!(rc_ok (chunk.memory, tok, len))) {
		free (tok);
		free (chunk.memory);
		return -1;
	}
	int r = get_tok (chunk.memory, tok, len, "authenticated");
	if (r == -1) {
		debug (2, "token 'authenticated' not found in JSON response");
	} else {
		if (TOK_CMP (chunk.memory, tok[r], "true") == 0) {
			debug (2, "token 'authenticated' has wrong value, expected true");
			/* set error */
			r = -1;
		}
	}
	if (r == -1) {
		free (tok);
		free (chunk.memory);
		return -1;
	}
	return 1;
}

/*
 * returns 1 if SUCCESS, -1 if error
 * sp_username: specifies the username in Posix format, i.e. user
 * secret: made up of concatenation of OTP and password
 */
int sp_user_auth_p (const char *username, const char* secret) {
	SP_INIT;
	if (username == NULL)  {
		error ("sp_user_auth_p() called with username=NULL");
		return -1;
	}
	/* concatenate realm to name */
 	char sp_name[(strlen (username) + strlen (sp_config.realm) + 2)]; 
	sprintf (sp_name, "%s%s%s", username, "@", sp_config.realm);
	return sp_user_auth (sp_name, secret);
}

/*
 * returns 1 if SUCCESS, -1 if error
 * uinfo: pointer to a sp_users_info - will be allocated by this function
 * 										caller will free() the structure after use
 * username: specifies the username
 */
int sp_users_info (sp_users_info_t **uinfo, const char *sp_username) {
	int len;
	jsmntok_t *tok;
	struct MemoryStruct chunk;

	SP_INIT;
	debug (2, "==> sp_users_info");
	if (sp_username == NULL)  {
		error ("sp_users_info() called with username=NULL");
		return -1;
	}
	char post_data[(strlen ("USERNAME=") + strlen (sp_username) + 1)];
	sprintf (post_data, "%s%s", "USERNAME=", sp_username);
	len = do_curl(sp_config.URL_users_info, post_data, &tok, (struct MemoryStruct *) &chunk);
	if (len == -1) {
		return -1;
	}
	if (!(rc_ok (chunk.memory, tok, len))) {
		free (tok);
		free (chunk.memory);
		return -1;
	}
	/*
	 * Allocate buffer to be returned and copy data to it. 
     * size of sp_users_info_t + chunk.size + 1 string terminator for each output fields
	 * is an upper bound to contain user info
     */
	*uinfo = (sp_users_info_t *) malloc (sizeof (sp_users_info_t) + chunk.size);
	if (!(*uinfo)) {
		error ("malloc() failed");
		return -1;
	}
	cp_tok_t cp_tok;
	cp_tok.buflen = sizeof (sp_users_info_t) + chunk.size + 10;
	cp_tok.buf = malloc (cp_tok.buflen);
	if (!(cp_tok.buf)) {
		error ("malloc() failed");
		free (tok);
		free (chunk.memory);
		return -1;
	}
	cp_tok.offset = sizeof (sp_users_info_t); 
	cp_tok.status = 0; /* status = OK */ 
	*uinfo = (sp_users_info_t *) cp_tok.buf;

	/* for each field into the structure, set the pointer and copy the returned value */

	(*uinfo)->nin = cp_tok.buf + cp_tok.offset;
	copy_tok (chunk.memory, tok, len, &cp_tok, "nin", "");

	(*uinfo)->name = cp_tok.buf + cp_tok.offset;
	copy_tok (chunk.memory, tok, len, &cp_tok, "name", "");

	(*uinfo)->surname = cp_tok.buf + cp_tok.offset;
	copy_tok (chunk.memory, tok, len, &cp_tok, "surname", "");

	(*uinfo)->mobile = cp_tok.buf + cp_tok.offset;
	copy_tok (chunk.memory, tok, len, &cp_tok, "mobile", "");

	(*uinfo)->rfid = cp_tok.buf + cp_tok.offset;
	copy_tok (chunk.memory, tok, len, &cp_tok, "rfid", "");

	(*uinfo)->enabled = cp_tok.buf + cp_tok.offset;
	copy_tok (chunk.memory, tok, len, &cp_tok, "enabled", "");

	(*uinfo)->token = cp_tok.buf + cp_tok.offset;
	copy_tok (chunk.memory, tok, len, &cp_tok, "token", "");

	(*uinfo)->manager = cp_tok.buf + cp_tok.offset;
	copy_tok (chunk.memory, tok, len, &cp_tok, "manager", "");

	(*uinfo)->password = cp_tok.buf + cp_tok.offset;
	copy_tok (chunk.memory, tok, len, &cp_tok, "password", "");

	(*uinfo)->email = cp_tok.buf + cp_tok.offset;
	copy_tok (chunk.memory, tok, len, &cp_tok, "email", "");

	free (chunk.memory);
	if (cp_tok.status == -1) {
		error ("copy_tok returned unexpected error, cp_tok.buflen=%d, cp_tok.offset=%d", 
				cp_tok.buflen, cp_tok.offset);
		free (tok);
		return -1;
	}
	free (tok);
	debug (4, "sp_users_info(%s) returning buffer_size= %d number_of_bytes=%d", 
			sp_username, cp_tok.buflen, cp_tok.offset);
	return 1;
}

/*
 * this function is used for those SP APIs returning a list of strings:
 * - api/v1/users/list 
 * - api/v1/groups/list 
 * - api/v1/groups/members/list 
 * returns -1 if error, 0 if no items within the list, otherwise the number of items retrieved
 * xxx: pointer to an array containing pointers to returned items - it's allocated within this function
 * caller will free() the array after use, only in case len > 0
 * url: url to be invoked
 * post_data: POST data to be used
 * token_name: name of token paired to the list (e.g. "username", "group", ...) 
 */
int sp_xxx_list (char ***xxx, const char *url, char *post_data, char *token_name) {
	int len, i;
	char **u_ptr, *u_str;
	jsmntok_t *tok;
	struct MemoryStruct chunk;

	len = do_curl(url, post_data, &tok, (struct MemoryStruct *) &chunk);
	if (len == -1) {
		return -1;
	}
	if (!(rc_ok (chunk.memory, tok, len))) {
		free (tok);
		free (chunk.memory);
		return -1;
	}
	/*
	 * Get array from JSON response
     */
	int idx = get_tok (chunk.memory, tok, len, token_name);
	if (idx == -1) {
		debug (2, "token %s not found in JSON response", token_name);
		free (tok);
		free (chunk.memory);
		return -1;
	}
	
	if (!(IS_ARRAY(tok[idx]))) {
		debug (2, "pair of token %s in JSON response is not an array", token_name);
		free (tok);
		free (chunk.memory);
		return -1;
	}
	if ((len = tok[idx].size) > 0) {
		idx++;
		/*
		 * Allocate buffer to be returned and copy data to it. chunk.size is surely un upper bound to contain 
		 * the user list
		 */
		int ptrs_size = (len * sizeof (char *));
		int buflen = ptrs_size + chunk.size;
		*xxx = (char **) malloc (buflen);
		if (!(*xxx)) {
			error ("malloc(%d) failed", buflen);
			free (tok);
			free (chunk.memory);
			return -1;
		}
		for (i = idx, u_ptr = (char **) *xxx, u_str=((char *) *xxx + ptrs_size); i < (idx + len); i++) {
			int l = tok[i].end - tok[i].start;
			memcpy (u_str, chunk.memory + tok[i].start, l);
			*(u_str + l) = 0;
			*u_ptr = u_str;
			u_str += l + 1;
			u_ptr++;
		}
		free (tok);
		free (chunk.memory);
	}
	return len;
}

/*
 * this function list the users within a realm 
 * returns -1 if error, 0 if no users in realm, otherwise the number of users retrieved
 * users: pointer to an array containing pointers to returned users - it's allocated within this function
 * caller will free() the array after use, only in case len > 0
 * realm: specifies the realm; if NULL, the default realm will be used 
 */
int sp_users_list (char ***users, const char *realm) {

	SP_INIT;
	/* compile POST data */
	debug (2, "==> sp_users_list");
	char *r_ptr;
	if (realm != NULL) 
		r_ptr = (char *) realm;
	else
		r_ptr = sp_config.realm;	
	char post_data[(strlen ("REALM=") + strlen (r_ptr) + 1)];
	sprintf (post_data, "%s%s", "REALM=", r_ptr);

	/* call generic list function */
    return sp_xxx_list(users, sp_config.URL_users_list, post_data, "username");
}

/*
 * this function list the groups within a realm 
 * returns -1 if error, 0 if no groups in realm, otherwise the number of groups retrieved
 * groups: pointer to an array containing pointers to returned groups - it's allocated within this function
 * caller will free() the array after use, only in case len > 0
 * realm: specifies the realm; if NULL, the default realm will be used 
 */
int sp_groups_list (char ***groups, const char *realm) {

	SP_INIT;
	debug (2, "==> sp_groups_list");
	/* compile Post data */
	char *r_ptr;
	if (realm != NULL) 
		r_ptr = (char *) realm;
	else
		r_ptr = sp_config.realm;	
	char post_data[(strlen ("REALM=") + strlen (r_ptr) + 1)];
	sprintf (post_data, "%s%s", "REALM=", r_ptr);

	/* call generic list function */
    return sp_xxx_list(groups, sp_config.URL_groups_list, post_data, "group");
}

/*
 * this function list the members of a group within a realm 
 * returns -1 if error, 0 if no members in realm, otherwise the number of members retrieved
 * members: pointer to an array containing pointers to returned members - it's allocated within this function
 * caller will free() the array after use, only in case len > 0
 * realm: specifies the realm; if NULL, the default realm will be used 
 */
int sp_groups_members_list (char ***members, const char *groupname, const char *realm) {

	SP_INIT;
	debug (2, "==> sp_groups_members_list (%s)", groupname);

	/* compile POST data */
	char *r_ptr;
	if (realm != NULL) 
		r_ptr = (char *) realm;
	else
		r_ptr = sp_config.realm;	
	/* allocate POST data buffer including the string terminator, the '&' character and the '@' character*/
	char post_data[(strlen ("REALM=") + strlen (r_ptr) + strlen ("GROUP=") + strlen (groupname) + strlen (r_ptr) + 3)];
	sprintf (post_data, "REALM=%s&GROUP=%s@%s", r_ptr, groupname, r_ptr);

	/* call generic list function */
    return sp_xxx_list(members, sp_config.URL_groups_members_list, post_data, "members");
}
