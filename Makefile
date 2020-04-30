ifdef SYNGATE
  obj-m += SYNgate.o
endif
ifdef SYNWALL
  obj-m += SYNwall.o
endif

ifndef SYNGATE
  ifndef SYNWALL
    obj-m += SYNwall.o
  endif
endif

PWD := $(shell pwd)
KERNEL := /lib/modules/$(shell uname -r)/build
#
# Enable messages in Kernel log (uncomment following line)
#
#DEBUG := -DDEBUG
#
# Increase from 0 to 5 to increase verbosity in Kernel log
# WARNING: high level may impact performances
# Requires DEBUG variable set
#
DBGLVL := -DDBGLVL=1

SYNwall-objs += SYNwall_netfilter.o SYNquark.o SYNauth.o
SYNgate-objs += SYNgate_netfilter.o SYNquark.o SYNauth.o
ccflags-y += -O2 -Wall $(DEBUG) $(DBGLVL)

all:
	make -C $(KERNEL) M=$(PWD) modules
	strip --strip-debug *.ko
	rm -r -f *.mod.c .*.cmd *.symvers *.o *.order

clean:
	make -C $(KERNEL) M=$(PWD) clean

test:
	$(info **** REMEMBER TO REMOVE MODULE (sudo rmmod SYNwall) if test fails ****)
	$(info )
	sudo insmod SYNwall.ko psk="12345678901234567890123456789012" load_delay=0 precision=8
	sleep 2
	python tests/test.py `ip route get 8.8.8.8 | head -1 | sed -n "s/.*src \([0-9.]\+\).*/\1/p"`
	sudo rmmod SYNwall
