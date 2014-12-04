
TOP_DIR=`pwd`
INSTALL_DIR=/usr/bin

CC=g++
CFLAGS=-O2 -g

PROGS=ebctl
all:$(PROGS)

$(PROGS):%:%.c
	$(CC) $(CFLAGS) $^ -o $@ $(LIB)

clean:
	rm -f $(PROGS)
	
install:
	cp -f $(PROGS) $(INSTALL_DIR)/

uninstall:
	cd $(INSTALL_DIR)
	rm -f $(PROGS)
	cd $(TOP_DIR)
