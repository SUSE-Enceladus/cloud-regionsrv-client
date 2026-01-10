buildroot = /

clean:
	rm -rf dist

package: clean check test
	$(eval version := $(shell poetry run python -c 'from cloudregister.registercloudguest import __version__; print(__version__)'))
	# build the sdist source tarball
	poetry build --format=sdist
	# provide rpm source tarball
	mv dist/cloudregister-${version}.tar.gz dist/cloud-regionsrv-client-${version}.tar.gz
	cp package/* dist/
	@echo "Find package files for submission below dist/"

setup:
	poetry install --all-extras

check: setup
	# python flake tests
	poetry run flake8 --statistics -j auto --count cloudregister
	poetry run flake8 --statistics -j auto --count test/unit
	poetry run flake8 --statistics -j auto --count usr/lib/zypp/plugins/urlresolver

black: setup
	poetry run black --skip-string-normalization --line-length 80 cloudregister test/unit/
	poetry run black --skip-string-normalization --line-length 80 usr/lib/zypp/plugins/urlresolver/susecloud

test: setup
	# unit tests
	poetry run bash -c 'pushd test/unit && pytest \
		--doctest-modules --no-cov-on-fail --cov=cloudregister \
		--cov-report=term-missing --cov-fail-under=100 \
		--cov-config .coveragerc'
