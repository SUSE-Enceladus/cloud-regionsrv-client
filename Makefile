DESTDIR=
PREFIX=
dirs = etc man src usr
files = Makefile README LICENSE setup.py cloud-regionsrv-client.spec

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
	find "$(nv)" -type f -name cloudguestregistryauth -delete
	tar -cjf "$(nv).tar.bz2" "$(nv)"
	rm -rf "$(nv)"

exec:
	mkdir -p usr/bin
	gcc -I/usr/include/python3.6m  -Wno-unused-result -Wsign-compare -fmessage-length=0 -grecord-gcc-switches -O2 -Wall -D_FORTIFY_SOURCE=2 -fstack-protector-strong -funwind-tables -fasynchronous-unwind-tables -fstack-clash-protection -g -DNDEBUG -fmessage-length=0 -grecord-gcc-switches -O2 -Wall -D_FORTIFY_SOURCE=2 -fstack-protector-strong -funwind-tables -fasynchronous-unwind-tables -fstack-clash-protection -g -DOPENSSL_LOAD_CONF -fwrapv -fno-semantic-interposition -L/usr/lib64 -lpython3.6m src/reauth.c -o usr/bin/cloudguestregistryauth

install:
	cp -r $(dirs) "$(DESTDIR)/"
	python3 setup.py install --prefix="$(PREFIX)" --root="$(DESTDIR)"
	gzip "$(DESTDIR)"/"$(MANDIR)"/man1/registercloudguest.1
