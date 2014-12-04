
KERNEL_DIR=/lib/modules/`uname -r`/build/
EXTRA_CFLAGS+=-g
CUR_DIR=$(shell pwd)
KBUILD_EXTRA_SYMBOLS+=$(CUR_DIR)/tecent/driver/Module.symvers
export KBUILD_EXTRA_SYMBOLS

eblaze-objs := eblaze-blk.o eblaze-tfd.o eblaze-core.o
obj-m += eblaze.o

default:
	echo $(KBUILD_EXTRA_SYMBOLS)
	$(MAKE) -C $(KERNEL_DIR) M=`pwd` modules
clean:
	rm -rf *.o *.ko *.ko.* *.mod.* .*.*.cmd modules.order Module.* .tmp_versions
