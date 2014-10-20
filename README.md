NSS (Name Service Switch) module for SecurePass
===============================================

This is a NSS module for users defined on SecurePass.
SecurePass provides web single sign-on through the CAS protocol.

More on SecurePass at http://www.secure-pass.net

To install and configure the module:
- Install libcurl development package (e.g. libcurl4-gnutls-dev under Ubuntu)
- ./configure
- make
- make install
- Copy file securepass.conf.template into /etc/securepass.conf (uid=root, gid=root, perms=600)
- See the instructions into the file to configure the module
- Edit file /etc/nssswitch.conf and add service 'sp' to the passwd line (e.g. 'passwd: compat sp')
- (optional) start nscd (Name Service Cache Daemon)

Author
===========================================
gplll1818@gmail.com, Oct 2014
