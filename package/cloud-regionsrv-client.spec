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

%define eflag /run/azuretimer-was-enabled
%define aflag /run/azuretimer-was-running

%define base_version 10.5.3
Name:           cloud-regionsrv-client
Version:        %{base_version}
Release:        0
Summary:        Cloud Environment Guest Registration
License:        LGPL-3.0-only
Group:          Productivity/Networking/Web/Servers
URL:            http://www.github.com/SUSE-Enceladus/cloud-regionsrv-client
Source0:        %{name}-%{version}.tar.gz
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
# Add recommendation for docker to make sure all docker related
# config files get pulled in. If present we modify
# /etc/docker/daemon.json
Recommends:     docker
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
BuildRequires:  %{pythons}-poetry-core >= 1.2.0
%endif
%if 0%{?suse_version} > 1315
BuildRequires:  %{pythons}-toml
%endif
%if 0%{?suse_version} && 0%{?suse_version} < 1600 && 0%{?suse_version} > 1315
BuildRequires:  python311-poetry-core >= 1.2.0
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

%package license-watcher
Version:	1.0.0
Release:	0
Summary:	Enable/Disable Guest Registration for a running instance
Group:		Productivity/Networking/Web/Servers
Requires:	cloud-regionsrv-client >= 9.0.0
Requires:       python-instance-billing-flavor-check >= 1.0.0
Provides:       cloud-regionsrv-client-addon-azure = 1.0.6
Obsoletes:      cloud-regionsrv-client-addon-azure <= 1.0.5

BuildArch:      noarch

%description license-watcher
Monitors the status of the billing model of the cloud instance. Switch
registration to the update infrastructure on or off depending on the billing
model change direction.


%prep
%setup -n cloudregister-%{base_version}

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

# The location of the binaries
mkdir -p %{buildroot}/usr/sbin
mv %{buildroot}/usr/bin/* %{buildroot}/usr/sbin
mv %{buildroot}/usr/sbin/cloudguestregistryauth %{buildroot}/usr/bin
# The location of the regionserver certs
mkdir -p %{buildroot}/usr/lib/regionService/certs
# The directory for the cache data
mkdir -p %{buildroot}/var/cache/cloudregister
# The man pages
install -d -m 755 %{buildroot}/%{_mandir}/man1
install -m 644 doc/man/man1/* %{buildroot}/%{_mandir}/man1
# The sudo setup for cloudguestregistryauth
install -m 440 etc/sudoers.d/cloudguestregistryauth %{buildroot}%{_sysconfdir}/sudoers.d/cloudguestregistryauth
%if 0%{?suse_version} == 1315
rm -rf %{buildroot}%{_sysconfdir}/sudoers.d/cloudguestregistryauth
rm -rf %{buildroot}%{_bindir}/cloudguestregistryauth
%endif
gzip %{buildroot}/%{_mandir}/man1/*

%pre
%service_add_pre guestregister.service containerbuild-regionsrv.service

%pre license-watcher
%service_add_pre guestregister-lic-watcher.timer
# Save the "enabled" and "active" state of the previously existing
# addon-azure package which is being replaced by the license-watcher
# package. If the old service was enabled and active we want to enable the
# new service.
if [ $1 -ge 1 ]; then \
    if [ x$(systemctl is-enabled regionsrv-enabler-azure.timer 2>/dev/null ||:) = "xenabled" ]; then
		touch %eflag
	fi
	systemctl is-active regionsrv-enabler-azure.timer &>/dev/null && touch %aflag ||:
fi

%preun
%service_del_preun guestregister.service containerbuild-regionsrv.service
# When the package is removed (do not run during an upgrade) we need
# to clean up or we will leave repositories with "plugin://" behind
# while the plugin we supply is being removed (bsc#1240310)
if [ "$1" -eq 0 ] && [ -e "%{_sysconfdir}/regionserverclnt.cfg" ]; then
    %{_sbindir}/registercloudguest --clean
fi
# Avoid unpredictable errors in the build service. The build service check
# that removes packages does not guarantee that the generic config package
# gets removed during install/remove testing prior to removing the
# cloud-regionsrv-client package. The generic example configuration
# triggers errors during the clean operation. Therefore we force the exit
# code to be 0 during build. If a user installs this package on a system with
# and invalid config they have to uninstall the package with the "--noscripts"
# option.
if [ -e "/.buildenv" ]; then
    exit 0
fi

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

%post license-watcher
%service_add_post guestregister-lic-watcher.timer

%posttrans license-watcher
if test -f %eflag; then
    rm -f %eflag
    systemctl enable guestregister-lic-watcher.timer
fi

if test -f %aflag; then
    rm -f %aflag
    systemctl start guestregister-lic-watcher.timer
fi

%preun license-watcher
%service_del_preun guestregister-lic-watcher.timer

%postun
%service_del_postun guestregister.service containerbuild-regionsrv.service

%postun license-watcher
%service_del_postun guestregister-lic-watcher.timer

%files
%defattr(-,root,root,-)
%doc README.rst
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
%exclude %{_sitelibdir}/cloudregister/cloudguest_lic_watcher.py
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

%files license-watcher
%defattr(-,root,root,-)
%{_unitdir}/guestregister-lic-watcher.service
%{_unitdir}/guestregister-lic-watcher.timer
%{_sitelibdir}/cloudregister/cloudguest_lic_watcher.py
%attr(744, root, root) %{_sbindir}/cloudguest-lic-watcher


%changelog
