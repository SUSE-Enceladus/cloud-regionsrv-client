buildroot = /

clean:
	rm -rf dist

package: clean
	poetry build --format=sdist
	cp package/* dist/
	@echo "Find package files for submission below dist/"

install:
	install -d -m 755 ${buildroot}usr/share/man/man1
	for man in doc/man/man1/*.1; do \
		install -m 644 $$man ${buildroot}usr/share/man/man1 ;\
	done

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
