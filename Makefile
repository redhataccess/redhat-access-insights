RPMTOP=$(shell bash -c "pwd -P")/dist
PKGNAME=redhat-access-insights
SRPM=$(RPMTOP)/SRPMS/$(PKGNAME)-*.src.rpm
TARBALL=$(RPMTOP)/$(PKGNAME)-*.tar.gz
RPM=$(RPMTOP)/RPMS/noarch/$(PKGNAME)*.rpm

all: rpm

.PHONY: tarball
tarball: $(TARBALL)
$(TARBALL): Makefile
	python setup.py sdist

.PHONY: srpm rpm 
srpm: $(SRPM)
$(SRPM): $(TARBALL) $(SPEC_FILE_IN)
	mkdir -p $(RPMTOP)/{RPMS,SPECS,SRPMS,SOURCES,BUILD,BUILDROOT}
	rpmbuild -ts --define="_topdir $(RPMTOP)" --define="_sourcedir dist" $(TARBALL)

.PHONY: rpm
rpm: $(RPM)
$(RPM): $(SRPM)
	rpmbuild --buildroot $(RPMTOP)/BUILDROOT --define="_topdir $(RPMTOP)" --rebuild $<

install: $(RPM)
	if ! sudo yum install -y $(RPM); then \
	  sudo yum reinstall -y $(RPM);      \
	fi



install-docker-image:
	sudo docker build -t redhat-insights/insights-client .

uninstall-docker-image:
	sudo docker rmi redhat-insights/insights-client

clean:
	rm -rf dist
	rm -f MANIFEST
	rm -rf *.egg*
	find . -type f -name '*.pyc' -delete
