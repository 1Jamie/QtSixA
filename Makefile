# You know, there are pre-compile DEBs of this...

all: build

build:
	$(MAKE) -C sixad
	$(MAKE) -C qtsixa
	$(MAKE) -C utils

clean:
	$(MAKE) clean -C sixad
	$(MAKE) clean -C qtsixa
	$(MAKE) clean -C utils

install:
	$(MAKE) install -C sixad
	$(MAKE) install -C qtsixa
	$(MAKE) install -C utils

uninstall:
	$(MAKE) uninstall -C sixad
	$(MAKE) uninstall -C utils
	$(MAKE) uninstall -C qtsixa

