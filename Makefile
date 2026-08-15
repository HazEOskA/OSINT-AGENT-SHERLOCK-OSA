.PHONY: install run test verify smoke

install:
	python3 -m pip install -e .

run:
	python3 -m sherlock_osa

test:
	python3 -m unittest discover -s tests -v

verify:
	python3 scripts/verify.py

smoke:
	python3 scripts/smoke.py
