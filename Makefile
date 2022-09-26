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

ifdef ARCH
  EXT_ARCH = ARCH=$(ARCH)
endif

ifdef CROSS_COMPILE
  EXT_CROSS = CROSS_COMPILE=$(CROSS_COMPILE)
endif

ifndef KERNEL
  KERNEL := /lib/modules/$(shell uname -r)/build
endif

PWD := $(shell pwd)

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

SYNwall-objs += SYNwall_netfilter.o SYNquark.o SYNauth.o SYNhelpers.o
SYNgate-objs += SYNgate_netfilter.o SYNquark.o SYNauth.o SYNhelpers.o
ccflags-y += -O2 -Wall $(DEBUG) $(DBGLVL)

all:
	make $(EXT_ARCH) $(EXT_CROSS) -C $(KERNEL) M=$(PWD) modules
        ifndef CROSS_COMPILE
	  strip --strip-debug *.ko
        endif
	rm -r -f *.mod.c .*.cmd *.symvers *.o *.order

clean:
	make -C $(KERNEL) M=$(PWD) clean

test:
        ifndef CROSS_COMPILE
	  $(info **** REMEMBER TO REMOVE MODULE (sudo rmmod SYNwall) if test fails ****)
	  $(info )
	  $(info **** In case of errors, review Kernel logs as well (/var/log/messages or /var/log/kern.log) ****)
	  $(info )
	  sudo insmod SYNwall.ko psk=12345678901234567890123456789012 load_delay=0 precision=8
	  sleep 2
	  python tests/test.py tcp `ip route get 8.8.8.8 | head -1 | sed -n "s/.*src \([0-9.]\+\).*/\1/p"`
	  sudo rmmod SYNwall
	  sleep 1
	  sudo insmod SYNwall.ko psk=12345678901234567890123456789012 load_delay=0 precision=8 enable_udp=1
	  sleep 2
	  python tests/test.py udp `ip route get 8.8.8.8 | head -1 | sed -n "s/.*src \([0-9.]\+\).*/\1/p"`
	  sudo rmmod SYNwall
        else
	  $(info Tests can not be done in CROSS_COMPILE env)
        endif
