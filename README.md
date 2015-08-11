# NSS and PAM modules for SecurePass

This repository contains an NSS module and a PAM module for users defined on SecurePass.
SecurePass provides web single sign-on through the CAS protocol.

More on SecurePass at http://www.secure-pass.net

To install and configure the modules:
- Install libcurl development package (e.g. libcurl4-gnutls-dev under Ubuntu)
- Install libpam development package (e.g. libpam0g-dev under Ubuntu)
- ./configure
- make
- make install
- Copy file securepass.conf.template into /etc/securepass.conf (uid=root, gid=root, perms=600)
- See the instructions into the file to configure the module
- Edit file /etc/nssswitch.conf and add service 'sp' to the passwd line (e.g. 'passwd: compat sp')
- (recommended) start nscd (Name Service Cache Daemon)
- Configure PAM module (/lib/security/pam_sp_auth.so) under /etc/pam.d 
- This repo includes the following sample programs to test the SecurePass, NSS and PAM APIs: 
      sp_client, nss_client, pam_client

## NSS module

There are reserved words in SecurePass extended attributes:

* `posixuid` -> UID of the user
* `posixgid` -> GID of the user
* `posixhomedir` -> Home directory
* `posixshell` -> Desired shell
* `posixgecos` -> Gecos (defaults to username)

`posixuid` is the only required extended attribute, this is needed to recognize a SecurePass user as a Unix user. For any other parameter, you need to set defaults in `/etc/securepass.conf`

```[nss]
realm = domain.com
default_gid = 100
default_home = "/home"
default_shell = "/bin/bash"
```

## PAM module

The PAM module works both for **authentication** and for **password changing**.
In order to be able to change your password with the PAM module, the API key must be read-write.
Read-only API keys will result in an error.

An example of PAM configuration under /etc/pam.d/:

```password   required   /lib/security/pam_sp.so
auth       required   /lib/security/pam_sp.so
```

# Author
gplll1818@gmail.com, Oct 2014 - Aug 2015
