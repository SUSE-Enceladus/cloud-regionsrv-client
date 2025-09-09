buildroot = /

python_version = 3
python_lookup_name = python$(python_version)
python = $(shell which $(python_lookup_name))

version := $(shell \
    $(python) -c \
    'from cloudregister.registercloudguest import __version__; print(__version__)'\
)

clean:
	rm -rf dist

package: clean
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

test: setup
	# unit tests
	poetry run bash -c 'pushd test/unit && pytest \
		--doctest-modules --no-cov-on-fail --cov=cloudregister \
		--cov-report=term-missing --cov-fail-under=100 \
		--cov-config .coveragerc'
