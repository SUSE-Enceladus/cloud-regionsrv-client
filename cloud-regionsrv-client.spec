#
# spec file for package cloud-regionsrv-client
#
# Copyright (c) 2024 SUSE LLC
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

%if 0%{?suse_version} >= 1600
%define pythons %{primary_python}
%else
%define pythons python3
%endif
%global _sitelibdir %{%{pythons}_sitelib}

%define base_version 10.3.11
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
# PATCH-FIX-SLES12 fix-for-sles12-no-trans_update.patch
Patch2:         fix-for-sles12-no-trans_update.patch
Requires:       SUSEConnect > 0.3.31
Requires:       ca-certificates
Requires:       cloud-regionsrv-client-config
%ifarch %ix86 x86_64
Requires:       dmidecode
%endif
Requires:       pciutils
Requires:       procps
Requires:       %{pythons}
Requires:       %{pythons}-PyYAML
Requires:       %{pythons}-M2Crypto
Requires:       %{pythons}-lxml
Requires:       %{pythons}-requests
Requires:       %{pythons}-urllib3
Requires:       %{pythons}-zypp-plugin
%if 0%{?suse_version} > 1315
Requires:       %{pythons}-toml
# Add requirement for libcontainers-common to make sure all
# podman related config files gets pulled in. We modify
# /etc/containers/registries.conf
Requires:       libcontainers-common
# Add requirement for docker to make sure all docker related
# config files gets pulled in. We modify
# /etc/docker/daemon.json
Requires:       docker
%endif
Requires:       regionsrv-certs
Requires:       sudo
Requires:       zypper
BuildRequires:  systemd
BuildRequires:  findutils
Conflicts:      container-suseconnect
%if 0%{?suse_version} == 1315
%{?systemd_requires}
%else
%{?systemd_ordering}
%endif
BuildRequires:  python-rpm-macros
BuildRequires:  %{pythons}-PyYAML
BuildRequires:  %{pythons}-M2Crypto
BuildRequires:  %{pythons}-devel
BuildRequires:  %{pythons}-lxml
BuildRequires:  %{pythons}-requests
BuildRequires:  %{pythons}-setuptools
BuildRequires:  %{pythons}-zypp-plugin
%if 0%{?suse_version} >= 1600
BuildRequires:  %{pythons}-pip
BuildRequires:  %{pythons}-wheel
%endif
%if 0%{?suse_version} > 1315
BuildRequires:  %{pythons}-toml
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
providing information to get the appropriate data form the region server.

%package plugin-ec2
Version:        1.0.5
Release:        0
Summary:        Cloud Environment Guest Registration Plugin for Amazon EC2
Group:          Productivity/Networking/Web/Servers
Requires:       cloud-regionsrv-client >= 6.0.0

%description plugin-ec2
Guest registration plugin for images intended for Amazon EC2 providing
information to get the appropriate data form the region server.

%package plugin-azure
Version:        2.0.0
Release:        0
Summary:        Cloud Environment Guest Registration Plugin for Microsoft Azure
Group:          Productivity/Networking/Web/Servers
Requires:       cloud-regionsrv-client >= 6.0.0
Requires:       python3-dnspython

%description plugin-azure
Guest registration plugin for images intended for Microsoft Azure providing
information to get the appropriate data form the region server.

%prep
%setup -q
%if 0%{?suse_version} == 1315
%patch -P 0 -p1
%patch -P 1 -p1
%patch -P 2 -p1

# %patch macro does not support to call patch such that it
# does not create .orig files. Under certain conditions patch
# creates them and this will break the build for files found
# but not packaged
find . -name *.orig -delete

%endif

%build
%if 0%{?suse_version} >= 1600
%pyproject_wheel
%else
%{pythons} setup.py build
%endif

%install
cp -r etc %{buildroot}
cp -r usr %{buildroot}
%if 0%{?suse_version} >= 1600
%pyproject_install
%else
%{pythons} setup.py install --prefix=%{_prefix} --root=%{buildroot}
%endif
# The location of the regionserver certs
mkdir -p %{buildroot}/usr/lib/regionService/certs
# The directory for the cache data
mkdir -p %{buildroot}/var/cache/cloudregister
install -d -m 755 %{buildroot}/%{_mandir}/man1
install -m 644 man/man1/* %{buildroot}/%{_mandir}/man1
install -m 644 usr/lib/systemd/system/regionsrv-enabler-azure.service %{buildroot}%{_unitdir}
install -m 644 usr/lib/systemd/system/regionsrv-enabler-azure.timer %{buildroot}%{_unitdir}
install -m 440 etc/sudoers.d/cloudguestregistryauth %{buildroot}%{_sysconfdir}/sudoers.d/cloudguestregistryauth
%if 0%{?suse_version} == 1315
rm -rf %{buildroot}%{_sysconfdir}/sudoers.d/cloudguestregistryauth
rm -rf %{buildroot}%{_bindir}/cloudguestregistryauth
%endif
gzip %{buildroot}/%{_mandir}/man1/*

%pre
%service_add_pre guestregister.service containerbuild-regionsrv.service

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

%preun
%service_del_preun guestregister.service containerbuild-regionsrv.service

%postun
%service_del_postun guestregister.service containerbuild-regionsrv.service

%files
%defattr(-,root,root,-)
%doc README
%license LICENSE
%dir %{_usr}/lib/zypp
%dir %{_usr}/lib/zypp/plugins
%dir %{_usr}/lib/zypp/plugins/urlresolver
%dir /var/cache/cloudregister
%{_mandir}/man*/*
# Do not expect the user that needs containers to have root access
# on the system
%if 0%{?suse_version} > 1315
%{_bindir}/cloudguestregistryauth
%endif
%{_sbindir}/cloudguest-repo-service
%{_sbindir}/containerbuild-regionsrv
%{_sbindir}/createregioninfo
%{_sbindir}/switchcloudguestservices
%{_sbindir}/registercloudguest
%{_sbindir}/updatesmtcache
%{_usr}/lib/zypp/plugins/urlresolver/susecloud
%if 0%{?suse_version} > 1315
%config %{_sysconfdir}/sudoers.d/*
%endif
%{_unitdir}/guestregister.service
%{_unitdir}/containerbuild-regionsrv.service
%exclude %{_sitelibdir}/cloudregister/google*
%exclude %{_sitelibdir}/cloudregister/amazon*
%exclude %{_sitelibdir}/cloudregister/msft*
%{_sitelibdir}/cloudregister/
%if 0%{?suse_version} >= 1600
%{_sitelibdir}/cloudregister-*.dist-info/
%else
%dir %{_sitelibdir}/cloudregister-%{base_version}-py%{py3_ver}.egg-info
%dir %{_sitelibdir}/cloudregister/
%{_sitelibdir}/cloudregister-%{base_version}-py%{py3_ver}.egg-info/*
%endif

%files generic-config
%defattr(-,root,root,-)
%dir /usr/lib/regionService
%dir /usr/lib/regionService/certs
%config %{_sysconfdir}/regionserverclnt.cfg
%config %{_sysconfdir}/logrotate.d/cloudregionsrvclient

%files plugin-gce
%defattr(-,root,root,-)
%{_sitelibdir}/cloudregister/google*

%files plugin-ec2
%defattr(-,root,root,-)
%{_sitelibdir}/cloudregister/amazon*

%files plugin-azure
%defattr(-,root,root,-)
%{_sitelibdir}/cloudregister/msft*

%changelog
