p0f version 3 dlfunc for Exim
=============================

This is p0f version 3 dlfunc library for Exim. It implements an interface
between Exim access control lists and the p0f daemon which does passive
OS fingerprinting. This can be useful for greylisting or scoring IP
addresses of SMTP senders according to sender's operating system. p0f
version 3 and this dlfunc supports IPv6. Note that the interface is *not*
compatible with p0f versions 2.x or older.

- Download:	http://dist.epipe.com/exim/
- GitHub:	https://github.com/snabb/exim-p0f3-dlfunc
- Author:	Janne Snabb, snabb at epipe.com
- License:	LGPL version 2.1 or later


## Installation

The build system is based on GNU autoconf, automake and libtool. That
makes the size of this software tarball enormously big, but it is
supposedly the best somewhat portable way for creating shared libraries
without getting a headache from thinking about compiler and linker flags.

Exim's local_scan.h header file is needed for compilation. On Debian
and Ubuntu it is supplied by `exim4-dev` package:
```
apt-get install exim4-dev
```

Alternatively you may point the include path in CPPFLAGS to some other
directory where Exim's local_scan.h is located (such as Exim build directory).

You may want to alter some settings at the start of exim-p0f3-dlfunc.c
to suit your local needs.

The following commands can be used to compile and install the library
on Debian and Ubuntu Linux:
```
CPPFLAGS="-I/usr/include/exim4" ./configure --libdir=/usr/local/lib/exim4/
make
make install
```


## Usage

Exim must be compiled with the "dlfunc" feature enabled. On Debian
and Ubuntu this is available in `exim4-daemon-heavy` package but *not*
in `exim4-daemon-light` package.

Start p0f (version 3) in daemon mode and make the API socket available
in some suitable location.

You can add something such as the following in Exim connect ACL:
```
warn    set acl_c_p0f_os = \
                ${dlfunc{/usr/local/lib/exim4/exim-p0f3-dlfunc.so}\
                       {p0f3_os}{/run/p0f/api-socket}{$sender_host_address}}
```

After that you can use $acl_c_p0f_os variable in ACL conditions,
for example:
```
deny    condition = ${if match{$acl_c_p0f_os}{Windows}}
        message = Non-free operating systems are prohibited here.
```

You can also add something like the following in the DATA ACL to add
a message header which indicates the connecting OS:
```
warn    condition = ${if def:acl_c_p0f_os}
        add_header = X-p0f-OS: $acl_c_p0f_os
```

## Working with the development version

If you check out the development version from GitHub, you need to have
GNU autotools, libtool, etc. installed.

To generate all the automatically created files you need to run the
`bootstrap` script.

