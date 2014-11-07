Summary: NSS library for SecurePass.
Name: nss-securepass
Version: 0.1
Release: 1
Source0: https://github.com/garlsecurity/nss_securepass/%{name}-%{version}.tar.gz
URL: https://github.com/garlsecurity/nss_securepass
Group: System Environment/Base
License: GPLv2+
BuildRoot: %{_tmppath}/%{name}-root
BuildRequires: libcurl-devel
Requires: libcurl

%description
NSS (Name Service Switch) module for SecurePass

SecurePass provides identity management and web single sign-on.

%prep
%setup -n nss_securepass


%build
./configure 
make 

%install
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/{etc,lib}
mkdir -p $RPM_BUILD_ROOT/usr/%{_lib}

/usr/bin/install -c -o root -g root libnss_sp.so.2 $RPM_BUILD_ROOT/usr/%{_lib}/libnss_sp.so.2
ln -sf libnss_sp.so.2 /usr/%{_lib}/libnss_sp.so

install -m 644 securepass.conf.template $RPM_BUILD_ROOT/etc/securepass.conf

chmod 755 $RPM_BUILD_ROOT/usr/%{_lib}/*.so*

%clean
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%attr(0755,root,root) /usr/%{_lib}/*.so*
%attr(0600,root,root) %config(noreplace) /etc/securepass.conf
%doc LICENSE LICENSE_APACHE2 LICENSE_GNUGPL LICENSE_MIT README.md
%doc securepass.conf.template

%changelog
* Fri Nov 7 2014 Giuseppe Paterno' (gpaterno@garl.ch)
- First RPM of the SecurePass NSS module
