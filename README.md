# nstreams-ng
nstreams is a utility designed to identify the IP streams that are occuring on a network. The program is one of the early network sniffing programs from the early 2000's. This version has been fixed so that modern compilers don't complain so much and the services have been updated to reflect the 2020 protocols.

BUILDING
--------
To build from the repo after cloning:

```
$ cd nstreams-ng
$ ./autogen.sh
$ ./configure
$ make
```

To use it do:

```
nstreams -l <interface>
```

It does not fully support IPv6 at the moment, port information is missing.
