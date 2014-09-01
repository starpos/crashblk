# Debug options. Choose one of the followings.
DEBUG = 0
DYNAMIC_DEBUG = 0
# You can specify the following parameters.
ASSERT = 0 # enable ASSERT even with relase build.
PERF = 0 # enable performacne analysis of each bio wrapper.

# Add your debugging flag (or not) to CFLAGS
ifeq ($(DYNAMIC_DEBUG),1)
  DEBFLAGS = -O -g -DDEBUG -DUSE_DYNAMIC_DEBUG
endif
ifeq ($(DEBUG),1)
  DEBFLAGS = -O -g -DDEBUG
endif
DEBFLAGS ?= -O2

ifeq ($(ASSERT),1)
  DEBFLAGS += -DASSERT_ON
endif

ifeq ($(PERF),1)
  DEBFLAGS += -DPERF_ANALYSIS
endif

EXTRA_CFLAGS += $(DEBFLAGS)
EXTRA_CFLAGS += -I$(obj)/include/ -I$(obj)

ifneq ($(KERNELRELEASE),)
# call from kernel build system

obj-m := bdevt.o

else

KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD       := $(shell pwd)

default:
	@echo DEBUG=$(DEBUG) DYNAMIC_DEBUG=$(DYNAMIC_DEBUG) PERF=$(PERF)
	@echo DEBFLAGS=$(DEBFLAGS)
	$(MAKE) clean
	$(MAKE) buildmodule

buildmodule: build_date_h
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

clean: clean_build_date
	rm -rf *.o *~ core .depend .*.cmd *.ko *.mod.c .tmp_versions

depend .depend dep:
	$(CC) $(CFLAGS) -M *.c > .depend

build_date_h: build_date.h.template
	cat $< | sed "s/XXXXX/`env LC_ALL=C date`/" > build_date.h

clean_build_date:
	rm -f build_date.h

endif

ifeq (.depend,$(wildcard .depend))
include .depend
endif
