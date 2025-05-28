## Introduction


This program monitors a FreeBSD Berkeley Packet Filter interface and blocks hosts once they perform a TCP half-open scan.  

The idea is to block mindless zombie bots as opposed to a sophisticated attacker.   It is not meant as a holistic security solution by any means, and it is certainly not suitable for large web sites or enterprises.  The pitfalls of this approach are obvious, but this program was a weekend network programming exercise, not a revelation in IPS software.  It's a hobbyist toy.

<img align="right" width="10%" src="https://www.freebsd.org/gifs/daemon_hammer.jpg" />

Initially, I wanted to make this work across FreeBSD and Linux, but Linux reads TCP packets on raw sockets whereas BSD does not, so this is a pure BSD implementation. 

Here are some great references I used for inspiration:

* Using FreeBSD’s BPF device with C/C++ - https://bastian.rieck.me/blog/posts/2009/bpf/
* Beej's Guide to Network Programming - http://beej.us/guide/bgnet/html/#structs
* An Overview of Raw Sockets Programming with FreeBSD - http://www.infosecwriters.com/text_resources/pdf/raw_tcp.pdf


## Configuration

The set of blocked ports is defined in the Makefile as `BLOCKED_PORTS`.  Ports 80 and 443 are the default host discovery ports used by nmap.

When a half-open scan is detected, a rule is inserted similar to the following:

```
20000 deny tcp from 192.241.196.110 to any 80,443 // 1633209181690
```

The comment at the end is the timestamp in milliseconds in case you want to write a reaper process (left as an exercise for the reader).

The `BASE_RULE` number that starts the block of ipfw rules is defined as `20000` in the source; you may need to alter this for your configuration.  You'll also need to ensure that any preceding ipfw rules do not impact the function of the newly created rules (like `established` for example).


## Building & Installing

Build:

```
% make
```

You can install the binary in /usr/local/bin:

```
# make install
```

## Usage

To run in the foreground, invoke it as root and provide the name of the ethernet interface to monitor.  For example:

```
# ./halfbaked bce1
```

To run it as a daemon, copy the rc.example file to /usr/local/etc/rc.d/halfbaked and edit /etc/rc.conf as specified at the beginning of the example.  The nice thing about FreeBSD's daemon(8) facility is that it takes care of all the details like logging and pid files.  You can then issue start/stop/restart commands like you would with any other daemon.

There are logging options:

```
USAGE: halfbaked [OPTIONS] ifname
 -q     quiet
 -v     verbose (default)
 -d     debug (implies -v)
 ifname interface name like eth0
```



