obj-m += htp-protocol.o
htp-protocol-objs := ./src/htp-protocol.o ./src/htp-impl.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

