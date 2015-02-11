Summary: NSS library for SecurePass
Name: nss-securepass
Version: 0.2.1
Release: 6%{?dist}
Source0: https://github.com/garlsecurity/nss_securepass/archive/v%{version}/nss_securepass-v%{version}.tar.gz
URL: https://github.com/garlsecurity/nss_securepass
License: GPLv2+
BuildRequires: libcurl-devel

%description
NSS (Name Service Switch) module for SecurePass

SecurePass provides identity management and web single sign-on.

%prep
%setup -qn nss_securepass-%{version}
sed -i 's|-o root -g root||g' Makefile.in

%build
%configure
make  %{?_smp_mflags}

%install
make install DESTDIR=%{buildroot} INSTALL="install -p"
mkdir -p %{buildroot}/%{_sysconfdir}
install -m 644 securepass.conf.template %{buildroot}/etc/securepass.conf


%files
%{_libdir}/*.so*
%attr(0600,root,root) %config(noreplace) /etc/securepass.conf
%doc README.md
%doc securepass.conf.template

%if 0%{?rhel} <= 6
   %doc LICENSE LICENSE_APACHE2 LICENSE_GNUGPL LICENSE_MIT
%else 
   %license LICENSE LICENSE_APACHE2 LICENSE_GNUGPL LICENSE_MIT
%endif

%post -p /sbin/ldconfig
%postun -p /sbin/ldconfig

%changelog
* Wed Feb 11 2015 Giuseppe Paterno' <gpaterno@gpaterno.com> 0.2-6
* Sync'ed SPEC with upstream

* Tue Feb 10 2015 Giuseppe Paterno' <gpaterno@gpaterno.com> 0.2-5
- Changed to tags in RPM, following now tags upstream
- More fixes coming from bug #1162234

* Wed Feb 4 2015 Giuseppe Paterno' <gpaterno@gpaterno.com> 0.2-4
- Converted licenses to Unix format
- Modified spec to comply with Fedora rules

* Wed Feb 4 2015 Marina Latini <deneb_alpha@opensuse.org> 0.2-4
- Fixed LICENSES files permissions
- Fixed license identifier accordig to https://spdx.org/licenses/
- Fixed spec name
- Added _service file for auto download (Suse OBS)

* Thu Jan 29 2015 Giuseppe Paterno' <gpaterno@gpaterno.com> 0.2-3
- More changes to the SPEC for bug #1162234

* Wed Jan 28 2015 Giuseppe Paterno' <gpaterno@garl.ch> 0.2-2
- Fixed SPEC files for bug #1162234

* Fri Nov 14 2014 Giuseppe Paterno' <gpaterno@garl.ch> 0.2-1
- Fixed lookup from UID
- Changed buildroot variable to macro
 
* Fri Nov 7 2014 Giuseppe Paterno' <gpaterno@garl.ch> 0.1-1
- First RPM of the SecurePass NSS module
