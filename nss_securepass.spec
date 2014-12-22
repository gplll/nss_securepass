%global commit c1bf10da1873bc212caa857653bef0b1e899703a
%global shortcommit %(c=%{commit}; echo ${c:0:7})

Summary: NSS library for SecurePass.
Name: nss-securepass
Version: 0.2
Release: 1%{?dist}
Source0: https://github.com/garlsecurity/nss_securepass/archive/%{commit}/nss_securepass-%{commit}.tar.gz
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
%setup -qn nss_securepass-%{commit}


%build
./configure 
make 

%install
[ "%{buildroot}" != "/" ] && rm -rf $RPM_BUILD_ROOT
mkdir -p %{buildroot}/{etc,lib}
mkdir -p %{buildroot}/usr/%{_lib}

/usr/bin/install -c libnss_sp.so.2 %{buildroot}/usr/%{_lib}/libnss_sp.so.2
ln -sf libnss_sp.so.2 %{buildroot}/usr/%{_lib}/libnss_sp.so

install -m 644 securepass.conf.template %{buildroot}/etc/securepass.conf

chmod 755 %{buildroot}/usr/%{_lib}/*.so*

%clean
[ "%{buildroot}" != "/" ] && rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%attr(0755,root,root) /usr/%{_lib}/*.so*
%attr(0600,root,root) %config(noreplace) /etc/securepass.conf
%doc LICENSE LICENSE_APACHE2 LICENSE_GNUGPL LICENSE_MIT README.md
%doc securepass.conf.template

%changelog
* Fri Nov 14 2014 Giuseppe Paterno' (gpaterno@garl.ch)
- Fixed lookup from UID
- Changed buildroot variable to macro

* Fri Nov 7 2014 Giuseppe Paterno' (gpaterno@garl.ch)
- First RPM of the SecurePass NSS module
