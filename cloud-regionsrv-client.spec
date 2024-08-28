#
# spec file for package cloud-regionsrv-client
#
# Copyright (c) 2022 SUSE LLC
#
# All modifications and additions to the file contributed by third parties
# remain the property of their copyright owners, unless otherwise agreed
# upon. The license for this file, and modifications and additions to the
# file, is the same license as for the pristine package itself (unless the
# license for the pristine package is not an Open Source License, in which
# case the license is the MIT License). An "Open Source License" is a
# license that conforms to the Open Source Definition (Version 1.9)
# published by the Open Source Initiative.

# Please submit bugfixes or comments via https://bugs.opensuse.org/
#


%define base_version 10.3.4
Name:           cloud-regionsrv-client
Version:        %{base_version}
Release:        0
Summary:        Cloud Environment Guest Registration
License:        LGPL-3.0-only
Group:          Productivity/Networking/Web/Servers
URL:            http://www.github.com/SUSE-Enceladus/cloud-regionsrv-client
Source0:        %{name}-%{version}.tar.bz2
# PATCH-FIX-SLES12 bsc#1203382 fix-for-sles12-disable-ipv6.patch
Patch0:         fix-for-sles12-disable-ipv6.patch
# PATCH-FIX-SLES12 fix-for-sles12-disable-registry.patch
Patch1:         fix-for-sles12-disable-registry.patch
Requires:       SUSEConnect > 0.3.31
Requires:       ca-certificates
Requires:       cloud-regionsrv-client-config
%ifarch %ix86 x86_64
Requires:       dmidecode
%endif
Requires:       pciutils
Requires:       procps
Requires:       python3
Requires:       python3-PyYAML
Requires:       python3-M2Crypto
Requires:       python3-lxml
Requires:       python3-requests
Requires:       python3-urllib3
Requires:       python3-zypp-plugin
%if 0%{?suse_version} > 1315
Requires:       python3-toml
%endif
Requires:       regionsrv-certs
Requires:       sudo
Requires:       zypper
BuildRequires:  systemd
Conflicts:      container-suseconnect
%if 0%{?suse_version} == 1315
%{?systemd_requires}
%else
%{?systemd_ordering}
%endif
BuildRequires:  python-rpm-macros
BuildRequires:  python3-PyYAML
BuildRequires:  python3-M2Crypto
BuildRequires:  python3-devel
BuildRequires:  python3-lxml
BuildRequires:  python3-requests
BuildRequires:  python3-setuptools
BuildRequires:  python3-zypp-plugin
%if 0%{?suse_version} > 1315
BuildRequires:  python3-toml
%endif
BuildRequires:  sudo
BuildRequires:  systemd-rpm-macros
BuildRoot:      %{_tmppath}/%{name}-%{version}-build
BuildArch:      noarch

%description
Obtain cloud SMT server information from the region server configured in
/etc/regionserverclnt.cfg

%package generic-config
Version:        1.0.0
Release:        0
Summary:        Cloud Environment Guest Registration Configuration
Group:          Productivity/Networking/Web/Servers
Provides:       cloud-regionsrv-client-config
Provides:       regionsrv-certs
Conflicts:      otherproviders(cloud-regionsrv-client-config)

%description generic-config
Generic configuration for the registration client. The configuration needs
to be adapted for the specific cloud framework after installation.

%package plugin-gce
Version:        1.0.0
Release:        0
Summary:        Cloud Environment Guest Registration Plugin for GCE
Group:          Productivity/Networking/Web/Servers
Requires:       cloud-regionsrv-client >= 6.0.0

%description plugin-gce
Guest registration plugin for images intended for Google Compute Engine

%package plugin-ec2
Version:        1.0.4
Release:        0
Summary:        Cloud Environment Guest Registration Plugin for Amazon EC2
Group:          Productivity/Networking/Web/Servers
Requires:       cloud-regionsrv-client >= 6.0.0

%description plugin-ec2
Guest registration plugin for images intended for Amazon EC2

%package plugin-azure
Version:        2.0.0
Release:        0
Summary:        Cloud Environment Guest Registration Plugin for Microsoft Azure
Group:          Productivity/Networking/Web/Servers
Requires:       cloud-regionsrv-client >= 6.0.0
Requires:       python3-dnspython

%description plugin-azure
Guest registration plugin for images intended for Microsoft Azure

%package addon-azure
Version:	1.0.5
Release:	0
Summary:	Enable/Disable Guest Registration for Microsoft Azure
Group:		Productivity/Networking/Web/Servers
Requires:	cloud-regionsrv-client >= 9.0.0
Requires:	cloud-regionsrv-client-plugin-azure

BuildArch:      noarch

%description addon-azure
Enable/Disable Guest Registration for Microsoft Azure

%prep
%setup -q
%if 0%{?suse_version} == 1315
%patch -P 0
%patch -P 1
test -e usr/sbin/registercloudguest.orig && rm usr/sbin/registercloudguest.orig
test -e lib/cloudregister/registerutils.py.orig && rm lib/cloudregister/registerutils.py.orig
%endif

%build
python3 setup.py build

%install
cp -r etc %{buildroot}
cp -r usr %{buildroot}
python3 setup.py install --prefix=%{_prefix} --root=%{buildroot}
# The location of the regionserver certs
mkdir -p %{buildroot}/usr/lib/regionService/certs
# The directory for the cache data
mkdir -p %{buildroot}/var/cache/cloudregister
# The directory for sudoers
mkdir -p %{buildroot}%{_sysconfdir}/sudoers.d
install -d -m 755 %{buildroot}/%{_mandir}/man1
install -m 644 man/man1/* %{buildroot}/%{_mandir}/man1
install -m 644 usr/lib/systemd/system/regionsrv-enabler-azure.service %{buildroot}%{_unitdir}
install -m 644 usr/lib/systemd/system/regionsrv-enabler-azure.timer %{buildroot}%{_unitdir}
install -m 644 etc/sudoers.d/* %{buildroot}%{_sysconfdir}/sudoers.d/cloudguestregistryauth
gzip %{buildroot}/%{_mandir}/man1/*

%pre
%service_add_pre guestregister.service containerbuild-regionsrv.service

%pre addon-azure
%service_add_pre regionsrv-enabler.timer

%post
# Scripts need access to the update infrastructure, do not execute them
# in the build service.
if [ "$YAST_IS_RUNNING" != "instsys" ] ; then
# On initial install we do not need to handle existing data, only on update
if [ "$1" -gt 1 ] ; then
    %{_sbindir}/switchcloudguestservices
    %{_sbindir}/updatesmtcache
    %{_sbindir}/createregioninfo
fi
fi
%service_add_post guestregister.service containerbuild-regionsrv.service

%post addon-azure
%service_add_post regionsrv-enabler.timer

%preun
%service_del_preun guestregister.service containerbuild-regionsrv.service

%preun addon-azure
%service_del_preun regionsrv-enabler-azure.timer

%postun
%service_del_postun guestregister.service containerbuild-regionsrv.service

%postun addon-azure
%service_del_postun regionsrv-enabler-azure.timer

%files
%defattr(-,root,root,-)
%doc README
%license LICENSE
%dir %{_usr}/lib/zypp
%dir %{_usr}/lib/zypp/plugins
%dir %{_usr}/lib/zypp/plugins/urlresolver
%dir /var/cache/cloudregister
%dir %{_sysconfdir}/sudoers.d
%{_mandir}/man*/*
# Do not expect the user that needs containers to have root access
# on the system
%{_bindir}/cloudguestregistryauth
%{_sbindir}/cloudguest-repo-service
%{_sbindir}/containerbuild-regionsrv
%{_sbindir}/createregioninfo
%{_sbindir}/switchcloudguestservices
%{_sbindir}/registercloudguest
%{_sbindir}/updatesmtcache
%{_usr}/lib/zypp/plugins/urlresolver/susecloud
%{_sysconfdir}/sudoers.d/*
%{python3_sitelib}/cloudregister/__*
%{python3_sitelib}/cloudregister/reg*
%{python3_sitelib}/cloudregister/smt*
%{python3_sitelib}/cloudregister/VERSION
%{_unitdir}/guestregister.service
%{_unitdir}/containerbuild-regionsrv.service
%dir %{python3_sitelib}/cloudregister-%{base_version}-py%{py3_ver}.egg-info
%dir %{python3_sitelib}/cloudregister/
%{python3_sitelib}/cloudregister-%{base_version}-py%{py3_ver}.egg-info/*

%files generic-config
%defattr(-,root,root,-)
%dir /usr/lib/regionService
%dir /usr/lib/regionService/certs
%config %{_sysconfdir}/regionserverclnt.cfg
%config %{_sysconfdir}/logrotate.d/cloudregionsrvclient

%files plugin-gce
%defattr(-,root,root,-)
%{python3_sitelib}/cloudregister/google*

%files plugin-ec2
%defattr(-,root,root,-)
%{python3_sitelib}/cloudregister/amazon*

%files plugin-azure
%defattr(-,root,root,-)
%{python3_sitelib}/cloudregister/msft*

%files addon-azure
%defattr(-,root,root,-)
%{_unitdir}/regionsrv-enabler-azure.service
%{_unitdir}/regionsrv-enabler-azure.timer
%attr(744, root, root) %{_sbindir}/regionsrv-enabler-azure


%changelog
