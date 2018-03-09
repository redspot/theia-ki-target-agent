# Theia Target Host manual installation

Firstly, you can install the Theia target host subsystems using deb packages. But, for developers, you can build and install the subsystems manually. This guide gives rough guide on how to do so.

## clone repo

	git clone git@tc.gtisc.gatech.edu:theia-ki-target-agent
	cd theia-ki-target-agent

## build custom kernel

The kernel build script will take advantage of ```ccache``` if you have it installed.

	cd linux-lts-quantal-3.5.0
	./compile

## install kernel and base kernel modules

	sudo ./install.sh

Or, if you want to just install the kernel, since the modules don't change:

	sudo ./install-kernel.sh

Then, you can install the modules separately, which usually needs to be done once:

	sudo ./install-modules.sh

## build and install ```spec``` module

	cd ../test/dev
	make
	sudo make install


## build and install custom ```eglibc```

	cd ../eglibc-2.15
	mkdir -p build
	CFLAGS='-g3 -O2' ../configure --prefix=/usr/local/eglibc --enable-add-on --enable-kernel=3.2.0
	make
	sudo make install
	cat /etc/ld.so.conf.d/*.conf | sudo tee /usr/local/eglibc/etc/ld.so.conf
	sudo /usr/local/eglibc/sbin/ldconfig

## build and install relay-reader

	cd ../relay-reader
	make
	sudo make install

## build and install custom command-line tools

	cd ../test
	make
	sudo make install

