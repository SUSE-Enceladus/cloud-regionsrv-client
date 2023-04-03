DESTDIR=
PREFIX=
dirs = etc man usr
files = Makefile README LICENSE setup.py

nv = $(shell rpm -q --specfile --qf '%{NAME}-%{VERSION}|' *.spec | cut -d'|' -f1)
verSpec = $(shell rpm -q --specfile --qf '%{VERSION}|' *.spec | cut -d'|' -f1)
verSrc = $(shell cat lib/cloudregister/VERSION)
ifneq "$(verSpec)" "$(verSrc)"
$(error "Version mismatch, will not take any action")
endif

tar:
	mkdir "$(nv)"
	cp -r $(dirs) lib $(files) "$(nv)"
	find "$(nv)" -type f -name '*.py[co]' -delete -o -type d -name __pycache__ -delete
	find "$(nv)" -path "*/lib/cloudregister.egg-info/*" -delete
	find "$(nv)" -type d -name "cloudregister.egg-info" -delete
	tar -cjf "$(nv).tar.bz2" "$(nv)"
	rm -rf "$(nv)"

install:
	cp -r $(dirs) "$(DESTDIR)/"
	python3 setup.py install --prefix="$(PREFIX)" --root="$(DESTDIR)"
	gzip "$(DESTDIR)"/"$(MANDIR)"/man1/registercloudguest.1
