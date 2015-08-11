/*
 *
 * Author: gplll <gplll1818@gmail.com>, Oct 2014
 *  
 */

/* States for status field in sp_config structure */
#define SP_NOT_INITED 0
#define SP_INITED 1
#define SP_ERROR 2

struct sp_config {
	char status;
	char debug;
	char debug_stderr;
	char *app_id;
	char *app_secret;
	char *URL_u_list;
	char *URL_u_info;
	char *URL_u_x_list;
	char *URL_u_pwd_chg;
	char *URL_u_auth;
	char *default_gid;
	char *default_home;
	char *default_shell;
	char *realm;
};

typedef struct {
	char *nin;
	char *name;
	char *surname;
	char *mobile;
	char *rfid;
	char *enabled;
	char *token;
	char *manager;
	char *password;
	char *email;
} sp_user_info_t;

typedef struct {
	char *posixuid;
	char *posixgid;
	char *posixhomedir;
	char *posixshell;
	char *posixgecos;
} sp_xattrs_t;

extern struct sp_config sp_config;

int sp_init ();
int sp_list_users (char ***user, const char *realm);
int sp_user_info (sp_user_info_t **uinfo, const char *username);
int sp_xattrs (sp_xattrs_t **xattrs, char *username, int get_defaults);
int sp_xattrs_p (sp_xattrs_t **xattrs, const char *username, int get_defaults);
int sp_user_password_change (const char *sp_username, const char* pwd);
int sp_user_password_change_p (const char *sp_username, const char* pwd);
int sp_user_auth (const char *sp_username, const char* secret);
int sp_user_auth_p (const char *sp_username, const char* secret);
