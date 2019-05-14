# Theia Target Host manual installation

Firstly, you can install the Theia target host subsystems using deb packages. But, for developers, you can build and install the subsystems manually. This guide gives rough guide on how to do so.

## base image

you can download the ISO for installing Ubuntu 12.04 from here:

<http://old-releases.ubuntu.com/releases/12.04.2/ubuntu-12.04.2-desktop-amd64.iso>

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
	mkdir -p build && cd build
    ../configure \
        --prefix=/usr/local/eglibc \
        --disable-profile \
        --enable-add-on \
        --without-gd \
        --without-selinux \
        --without-cvs \
        --enable-kernel=3.2.0 \
        --target=x86_64-linux-gnu \
        --host=x86_64-linux-gnu \
        CFLAGS='-g3 -O2'
	make  # or make -j8 # or -jnumber_of_cores
	sudo make install
    sudo cp ../ld.so.conf.theia /usr/local/eglibc/etc/ld.so.conf
    sudo rm -f /usr/local/eglibc/etc/ld.so.cache
	sudo /usr/local/eglibc/sbin/ldconfig

## build and install relay-reader

	cd ../relay-reader
	make
	sudo make install

## build and install custom command-line tools

	cd ../test
	make
	sudo make install

