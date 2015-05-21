%{!?python_sitelib: %define python_sitelib %(%{__python} -c "from distutils.sysconfig import get_python_lib; print get_python_lib()")}
%define _binaries_in_noarch_packages_terminate_build 0

Name:                   redhat-access-insights
Summary:                Uploads Insights information to Red Hat on a periodic basis
Version:                1.0.3
Release:                0%{?dist}
Source0:                https://github.com/redhataccess/redhat-access-insights/archive/redhat-access-insights-%{version}.tar.gz
Epoch:                  0
License:                GPLv2+
URL:                    http://access.redhat.com/labs/insights
Group:                  Applications/System
Vendor:                 Red Hat, Inc.

Obsoletes: redhat-access-proactive

Requires: python
Requires: python-setuptools
Requires: python-requests >= 2.4
Requires: python-magic
Requires: libcgroup
Requires: pciutils
%if 0%{?rhel} && 0%{?rhel} > 6
Requires: libcgroup-tools
%endif
BuildArch: noarch

BuildRequires: python2-devel
BuildRequires: python-setuptools

%description
Sends insightful information to Red Hat for automated analysis

%prep
%setup -q

%install
test "x$RPM_BUILD_ROOT" != "x" && rm -rf $RPM_BUILD_ROOT
%{__python} setup.py install --root=$RPM_BUILD_ROOT $PREFIX

%post
#Migrate existing config if we can
if  [ -f "/etc/redhat_access_proactive/redhat_access_proactive.conf" ]; then
mkdir -p /etc/redhat-access-insights/
sed 's/redhat_access_proactive/redhat-access-insights/' /etc/redhat_access_proactive/redhat_access_proactive.conf > /etc/redhat-access-insights/redhat-access-insights.conf
fi

%postun
if [ "$1" -eq 0 ]; then
rm -f /etc/cron.daily/redhat-access-insights
rm -f /etc/cron.weekly/redhat-access-insights
rm -f /etc/redhat-access-insights/.cache*
fi

%clean
test "x$RPM_BUILD_ROOT" != "x" && rm -rf $RPM_BUILD_ROOT

%files
%defattr(755,root,root)
%{_bindir}/redhat-access-insights
/etc/redhat-access-insights/redhat-access-insights.cron

%defattr(0600, root, root)
%dir /etc/redhat-access-insights
%config(noreplace) /etc/redhat-access-insights/*.conf
/etc/redhat-access-insights/.fallback.json
/etc/redhat-access-insights/.fallback.json.asc
/etc/redhat-access-insights/redhattools.pub.gpg
/etc/redhat-access-insights/*.pem

%defattr(-,root,root)
%{python_sitelib}/redhat_access_insights*.egg-info
%{python_sitelib}/redhat_access_insights/*.py*

%doc
/usr/share/man/man8/*.8.gz

%changelog
* Wed May 20 2015 Dan Varga <dvarga@redhat.com> - 1.0.3-0
- New default URLs

* Mon May 18 2015 Dan Varga <dvarga@redhat.com> - 1.0.2-0
- Update man pages

* Thu May 07 2015 Dan Varga <dvarga@redhat.com> - 1.0.1-0
- Add man pages
- New certificate chain for cert-api.access.redhat.com
- Better auto configuration for satellite installations

* Wed Apr 29 2015 Dan Varga <dvarga@redhat.com> - 1.0.0-2
- Drop min python-requests version to 2.4

* Mon Apr 27 2015 Dan Varga <dvarga@redhat.com> - 1.0.0-1
- Add LICENSE file
- Resolves: bz1215002

* Thu Apr 23 2015 Dan Varga <dvarga@redhat.com> - 1.0.0-0
- Initial build
- Resolves: bz1176237
