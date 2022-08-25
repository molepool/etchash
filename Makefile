.PHONY: clean test
test:
	./test/test.sh

clean:
	rm -rf *.so pyetchash.egg-info/ build/ test/python/python-virtual-env/ test/c/build/ pyetchash.so test/python/*.pyc dist/ MANIFEST
