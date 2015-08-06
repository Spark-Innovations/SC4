build:
	cd tweetnacl-py && make build
	rm -f nacl
	ln -s tweetnacl-py/build/lib*/nacl .

test: build
	cd tweetnacl-py && make test
	python sc4test.py

clean:
	rm -f nacl
	rm -rf tweetnacl-py/build
	rm -f *.pyc
	rm -rf __pycache__
