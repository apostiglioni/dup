.PHONY: test python3 python

test: python3 python

python3:
	python3 -m unittest test_dupclean


python:
	python -m unittest test_dupclean
