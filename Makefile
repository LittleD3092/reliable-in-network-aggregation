all:
	cd src/two-host-adder; make

clean:
	cd src/two-host-adder; make clean

plot:
	cd src/two-host-adder && python3 plot.py