Summary:	Nstreams-ng - a tcpdump output analyzer
Name:		nstreams-ng
Version:	1.0.4
Release:	1%{?dist}
License:	GPLv2+
URL:		https://github.com/stevegrubb/nstreams-ng
Packager:	Steve Grubb <sgrubb@redhat.com>
Source:		%{name}-%{version}.tar.gz
Buildroot:	%{_tmppath}/%{name}-%{version}-root
BuildRequires:	libpcap-devel
BuildRequires:	gcc make


%description
nstreams is a utility designed to identify the IP streams that are occuring on a network

%prep
%setup -q

%build
%configure
make CFLAGS="%{optflags}" %{?_smp_mflags}

%install
make DESTDIR="%{buildroot}" INSTALL='install -p' install

%clean
rm -rf ${RPM_BUILD_ROOT}

%files
%defattr(755, root, root)
%{_bindir}/*
%attr(755,root,root) /etc/nstreams-services
%config(noreplace) /etc/nstreams-networks
%{_mandir}/*

%changelog
* Wed Jan 06 2021 Steve Grubb <sgrubb@redhat.com>
-Created initial package.

