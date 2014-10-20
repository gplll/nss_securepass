/*
 *
 * Author: gplll <gplll1818@gmail.com>, Oct 2014
 *  
 */

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <malloc.h>
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
#define DEFAULT_GID "100"
#define DEFAULT_HOME_DIR "/home/"
#define DEFAULT_SHELL "/bin/bash"

#define IS_ARRAY(t) ((t).type == JSMN_ARRAY)
#define IS_OBJECT(t) ((t).type == JSMN_OBJECT)
#define TOK_CMP(js, t, s) \
     ((strlen(s) == (t).end - (t).start) \
     && (strncmp(js+(t).start, s, (t).end - (t).start) == 0))
     
struct sp_config sp_config ={SP_NOT_INITED, 0, 0, "", "", "", ""};

struct MemoryStruct {
  char *memory;
  size_t size;
};
int param_count = 0; /* number of parameters read from config file */
char *types[] = {"PRIMITIVE", "OBJECT","ARRAY","STRING"};
char *post_data=NULL;
 
void check_ini_string (const char *key, const char *value, const char *key_to_chk, char **result, 
						char *prefix, char *postfix) {

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
			param_count++;
		}
}

int IniCallback(const char *section, const char *key, const char *value, const void *userdata)
{
	if ((strcmp (key, "APP_ID") == 0) || (strcmp (key, "APP_SECRET") == 0)) {
		debug (2, "IniCallback:    [%s] %s=****************", section, key);
	} 
	else {
		debug (2, "IniCallback:    [%s] %s=%s", section, key, value);
	}
	if (strcmp (section, "default") == 0) {
		check_ini_string (key, value, "APP_ID", &sp_config.app_id, "X-SecurePass-App-ID:", NULL);
		check_ini_string (key, value, "APP_SECRET", &sp_config.app_secret, "X-SecurePass-App-Secret:", NULL);
		check_ini_string (key, value, "SP_URL", &sp_config.URL_u_list, NULL, "/users/list");
		check_ini_string (key, value, "SP_URL", &sp_config.URL_u_info, NULL, "/users/info");
		check_ini_string (key, value, "SP_URL", &sp_config.URL_u_x_list, NULL, "/users/xattrs/list");
		if (strcmp (key, "DEBUG") == 0) {
			sp_config.debug = atoi (value);
		}
		if (strcmp (key, "DEBUG_STDERR") == 0) {
			sp_config.debug_stderr = atoi (value);
		}
	}
	if (strcmp (section, "nss") == 0) {
		check_ini_string (key, value, "SP_REALM", &sp_config.realm, NULL, NULL);
	}
  return 1;
}

int sp_init() {
	if ((sp_config.status == SP_ERROR)) {
		return 0;
	}
	/* read config. files and fill sp_config */
	ini_browse(IniCallback, NULL, SP_CONFFILE);
	if (param_count < MANDATORY_PARAMS_NUMBER) {
		error ("sp_init: missing config file or missing mandatory parameter in configfile");
		sp_config.status = SP_ERROR;
		return 0;
	}
	sp_config.status = SP_INITED;
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
		error ("jsmn_parse returned error(%d)", r);
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
		debug (1, "token rc not found in JSON response");
		return 0;
	}
	if (TOK_CMP (js, tok[r], "0") == 0) {
		debug (1, "token rc has wrong value, expected 0");
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
 * cp_tok->offset: buffer offset where to copy the token found
 * cp_tok->status: set to -1 if not enough space to contain the token found
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

	debug (4, "==> do_curl");
	chunk->memory = NULL;    /* will be grown as needed by realloc */
	chunk->size = 0;    /* no data at this point */ 
 
	curl_global_init(CURL_GLOBAL_ALL);

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
				error ("jsmn_parse() returned error(%d)", num_tok);
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
 */
int sp_xattrs (sp_xattrs_t **xattrs, char *sp_username) {
	int len;
	jsmntok_t *tok;
	struct MemoryStruct chunk;
	char *post_data;

	debug (4, "==> sp_xattrs");
	if ((sp_config.status != SP_INITED)) {
		if (!(sp_init ())) return -1;
	}
	if (sp_username == NULL)  {
		error ("sp_xattrs() called with username=NULL");
		return -1;
	}
	/* call curl */
	if ((post_data = malloc (strlen ("USERNAME=") + strlen (sp_username) + 1)) == NULL) {
		error ("malloc() failed");
		return -1;
	}
	sprintf (post_data, "%s%s", "USERNAME=", sp_username);
	len = do_curl(sp_config.URL_u_x_list, post_data, &tok, (struct MemoryStruct *) &chunk);
	free (post_data);
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
	 * Allocate buffer to be returned and copy data to it. chunk.size is likely un upper bound to contain 
	 * the user info. Buffer will be reallocated if too small
     */
	cp_tok_t cp_tok;
	cp_tok.buflen = sizeof (sp_xattrs_t) + chunk.size;
	cp_tok.buf = malloc (cp_tok.buflen);
	if (!(cp_tok.buf)) {
		error ("malloc() failed");
		free (tok);
		free (chunk.memory);
		return -1;
	}
	cp_tok.offset = sizeof (sp_xattrs_t); 
	cp_tok.status = 0; /* status = OK */ 
	while (1) {
		*xattrs = (sp_xattrs_t *) cp_tok.buf;

		/* for each field into the structure, set the pointer and copy the returned value */
		(*xattrs)->posixuid = cp_tok.buf + cp_tok.offset;
		copy_tok (chunk.memory, tok, len, &cp_tok, "posixuid", "");

		(*xattrs)->posixgid = cp_tok.buf + cp_tok.offset;
		copy_tok (chunk.memory, tok, len, &cp_tok, "posixgid", "");

		(*xattrs)->posixhomedir = cp_tok.buf + cp_tok.offset;
		copy_tok (chunk.memory, tok, len, &cp_tok, "posixhomedir", "");

		(*xattrs)->posixshell = cp_tok.buf + cp_tok.offset;
		copy_tok (chunk.memory, tok, len, &cp_tok, "posixshell", "");

		(*xattrs)->posixgecos = cp_tok.buf + cp_tok.offset;
		copy_tok (chunk.memory, tok, len, &cp_tok, "posixgecos", "");

		if (cp_tok.status == -1) {
			/* buffer is too small. Reallocate with the size computed by copy_tok() in previous calls */
			debug (1, "buffer is too small to hold output bytes, reallocating to %d bytes", cp_tok.offset);
			cp_tok.buflen = cp_tok.offset;
			cp_tok.offset = sizeof (sp_xattrs_t); 
			cp_tok.status = 0; 
			if ((cp_tok.buf = realloc (cp_tok.buf, cp_tok.buflen)) == NULL ) {
				error ("realloc(%d) failed", cp_tok.buflen);
				free (tok);
				free (chunk.memory);
				return -1;
			}
			continue;
		}
		free (tok);
		free (chunk.memory);
		return 1;
	}
}

/*
 * returns 1 if SUCCESS, -1 if error
 * xattrs: pointer to a sp_xattrs_t that will be allocated by this function
 * caller will free() the structure after use
 * username: specifies the username in Posix format, i.e. user
 */
int sp_xattrs_p (sp_xattrs_t **xattrs, const char *username) {
	char *sp_name;

	if ((sp_config.status != SP_INITED)) {
		if (!(sp_init ())) return -1;
	}
	if (username == NULL)  {
		error ("sp_xattrs_p() called with username=NULL");
		return -1;
	}
	/* concatenate realm to name */
	if ((sp_name = malloc (strlen (username) + strlen (sp_config.realm) + 2)) == NULL) {
		error ("malloc() failed");
		return -1;
	}
	sprintf (sp_name, "%s%s%s", username, "@", sp_config.realm);
	int rc = sp_xattrs (xattrs, sp_name);
	free (sp_name);
	return rc;

}

/*
 * returns 1 if SUCCESS, -1 if error
 * uinfo: pointer to a sp_user_info_t - will be allocated by this function
 * 										caller will free() the structure after use
 * username: specifies the username
 */
int sp_user_info (sp_user_info_t **uinfo, const char *username) {
	int len;
	jsmntok_t *tok;
	struct MemoryStruct chunk;
	char *post_data;

	debug (4, "==> sp_user_info");
	if ((sp_config.status != SP_INITED)) {
		if (!(sp_init ())) return -1;
	}
	if (username == NULL)  {
		error ("sp_user_info() called with username=NULL");
		return -1;
	}
	if ((post_data = malloc (strlen ("USERNAME=") + strlen (username) + 1)) == NULL) {
		error ("malloc() failed");
		return -1;
	}
	sprintf (post_data, "%s%s", "USERNAME=", username);
	len = do_curl(sp_config.URL_u_info, post_data, &tok, (struct MemoryStruct *) &chunk);
	free (post_data);
	if (len == -1) {
		return -1;
	}
	if (!(rc_ok (chunk.memory, tok, len))) {
		free (tok);
		free (chunk.memory);
		return -1;
	}
	/*
	 * Allocate buffer to be returned and copy data to it. chunk.size is likely un upper bound to contain 
	 * the user info, will be reallocated if too small
     */
	*uinfo = (sp_user_info_t *) malloc (sizeof (sp_user_info_t) + chunk.size);
	if (!(*uinfo)) {
		error ("malloc() failed");
		return -1;
	}
	cp_tok_t cp_tok;
	cp_tok.buflen = sizeof (sp_user_info_t) + chunk.size;
	cp_tok.buf = malloc (cp_tok.buflen);
	if (!(cp_tok.buf)) {
		error ("malloc() failed");
		free (tok);
		free (chunk.memory);
		return -1;
	}
	cp_tok.offset = sizeof (sp_user_info_t); 
	cp_tok.status = 0; /* status = OK */ 
	while (1) {
		*uinfo = (sp_user_info_t *) cp_tok.buf;

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

		if (cp_tok.status == -1) {
			/* buffer is too small. Reallocate with size computed by copy_tok() in previous calls */
			debug (1, "buffer is too small to hold output bytes, reallocating to %d bytes", cp_tok.offset);
			cp_tok.buflen = cp_tok.offset;
			cp_tok.offset = sizeof (sp_user_info_t); 
			cp_tok.status = 0; 
			if ((cp_tok.buf = realloc (cp_tok.buf, cp_tok.buflen)) == NULL ) {
				error ("realloc(%d) failed", cp_tok.buflen);
				free (tok);
				free (chunk.memory);
				return -1;
			}
			continue;
		}
		free (tok);
		free (chunk.memory);
		return 1;
	}
	return 1; /* should not be reached */
}

/*
 * returns -1 if error, 0 if no users in realm, otherwise the number of users retrieved
 * user: pointer to an array containing pointers to returned users - it's allocated within this function
 * caller will free() the array after use
 * buflen: lenght in bytes of returned buffer
 * realm: specifies the realm; if NULL, the default realm will be used 
 */
int sp_list_users (char ***user, const char *realm) {
	int len, i;
	char *r_ptr, **u_ptr, *u_str;
	jsmntok_t *tok;
	struct MemoryStruct chunk;
	char *post_data;

	if ((sp_config.status != SP_INITED)) {
		if (!(sp_init ())) return -1;
	}
	if (realm != NULL) 
		r_ptr = (char *) realm;
	else
		r_ptr = sp_config.realm;	
	if ((post_data = malloc (strlen ("REALM=") + strlen (r_ptr) + 1)) == NULL) {
		error ("malloc() failed");
		return -1;
	}
	sprintf (post_data, "%s%s", "REALM=", r_ptr);
	len = do_curl(sp_config.URL_u_list, post_data, &tok, (struct MemoryStruct *) &chunk);
	free (post_data);
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
	int idx = get_tok (chunk.memory, tok, len, "username");
	if (idx == -1) {
		debug (1, "token \"username\" not found in JSON response");
		free (tok);
		free (chunk.memory);
		return 0;
	}
	
	if (!(IS_ARRAY(tok[idx]))) {
		debug (1, "pair of token \"username\" in JSON response is not an array");
		free (tok);
		free (chunk.memory);
		return 0;
	}
	len = tok[idx].size;
	idx++;
	/*
	 * Allocate buffer to be returned and copy data to it. chunk.size is surely un upper bound to contain 
	 * the user list
     */
	int ptrs_size = (len * sizeof (char *));
	int buflen = ptrs_size + chunk.size;
	*user = (char **) malloc (buflen);
	if (!(*user)) {
		error ("malloc(%d) failed", buflen);
		free (tok);
		free (chunk.memory);
		return -1;
	}
	for (i = idx, u_ptr=(char **) *user, u_str=((char *) *user + ptrs_size); i < (idx + len); i++) {
		int l = tok[i].end - tok[i].start;
		memcpy (u_str, chunk.memory + tok[i].start, l);
		*(u_str + l) = 0;
		*u_ptr = u_str;
		u_str += l + 1;
		u_ptr++;
	}
	free (tok);
	free (chunk.memory);
	return len;
}
