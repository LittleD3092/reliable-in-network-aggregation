start: build
	sudo python3 src/topology/topology.py

build:
	if [ ! -d "build" ]; then mkdir build; fi
	p4c src/adder.p4 -o build/

clean:
	sudo mn -c
	rm -rf build