.PHONY: test python3 python t

test: python3 python

python3:
	python3 -m unittest test_dupclean


python:
	python -m unittest test_dupclean

scenario:
	python3 -m unittest "test_dupclean.${SCENARIO}"

expected: clean
	python3 -m unittest test_dupclean
	tree -paJ .test-data | perl -pe 's|test_(.*)\.(.*?)"|test_\1"|'

clean:
	sudo rm -rf .test-data
