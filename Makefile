all:
	cd src/two-host-adder; make

clean:
	cd src/two-host-adder; make clean

plot:
	cd src/two-host-adder && python3 plot.py

parse-logs:
	cd src/two-host-adder && python3 parse-switch-log.py

check:
	cd src/two-host-adder && python3 check-min-seq-and-ack.py