NSS and PAM modules for SecurePass
===============================================

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

Author
===========================================
gplll1818@gmail.com, Oct 2014 - Aug 2015
