# nident
Copyright (C) 2010-2017 Nicholas J. Kain.

License: Two-clause BSD.

## Introduction

nident is designed as a secure and paranoid ident daemon.  It is designed
to not provide any information to clients unless instructed otherwise
by users.  It provides a flexible mechanism for configuring per-user
responses to particular hostmasks and ports, as well as syslog logging
of replies.

Buzzword compliance:

* supports IPv6 and IPv4: IPv6 is used internally
* designed with security as a main goal
* designed with privacy as a main goal
* supports fine-grained response control
* supports configurably hashed responses
* supports validated spoofed responses
* does not require inetd
* syslog logging of responses
* supports chrooting the ident daemon
* uses seccomp syscall filters
* uses netlink sockets instead of procfs

I have tried to pay particular attention to ensuring that nident is not
only paranoid, but also secure.  nident will refuse to run with root
privileges, requiring the user to provide it with an unprivileged uid
and gid.  Malformed queries should not affect nident, and nor should
poorly constructed `.ident` files.

Special attention has been paid to make nident resistant to any form
of remote DoS attempt by forcing excessive memory use.  All connections
that send malformed input are terminated as soon as is possible (limited
by the size of socket buffers in the kernel -- nident stops and replies
with error at the first byte that is invalid).  nident also limits the
number of concurrent connections allowed.

## Requirements

* Linux kernel
* GCC or Clang
* CMake
* [Ragel 6](https://www.colm.net/open-source/ragel)
* [ASIO 1.11](https://think-async.com)
* [ncmlib](https://github.com/niklata/ncmlib)
* [fmtlib](https://github.com/fmtlib/fmt)

## Standard Usage

Install dependencies.  In the nident directory, symlinks should be created.
Assuming that asio, ncmlib, and fmtlib live in the same directory as
the nident directory:
```
$ ls
asio fmt ncmlib nident
$ cd nident
$ ln -s ../asio/include asio
$ ln -s ../ncmlib .
$ ln -s ../fmt/format.[ch]pp fmt/
```
* Create a build directory: `mkdir build && cd build`
* Create the makefiles: `cmake ..`
* Build nident: `make`
* Install the `nident/nident` executable in a normal place.  I would
  suggest `/usr/sbin` or `/usr/local/sbin`.

Set up the user account for nident.

Run nident.  Use `nident --help` to see all possible options.

`nident -p -u ident -g ident`

The above would run nident under the uid and default gid for user
`ident` so that it was listening for connections on all interfaces
on port `113` (auth).  All errors except for `ERROR:INVALID-PORT` would
be reported as `ERROR:UNKNOWN-ERROR` for extra security.

`nident -u ident -g ident 127.0.0.1:156 ::1:777`

The above would run nident under the uid and default gid for user `ident`
so that it was listening for connections on two address and port pairs:
`127.0.0.1` (v4 loopback) port `156` and `::1` (v6 loopback) port `777`.

## Using chroot

First, set up nident as described above, and make sure that it is working.
Setting up chroots can be tricky, and it's best to start from a working
setup.

Decide on a directory to use for the chroot.  This directory will need to
contain your per-user ident configuration files.  It should be readable
and executable for the ident user, and the configuration files within
should only be readable by the ident user.  Each configuration file
should be owned by the matching user account, and the chroot directory
should be owned by root.

### Example

This assumes that the ident daemon is running with a user account id that
does not equal `0` or `1000`, and that there is a single user, with user account
id equal to `1000`, that is allowed to specify proper ident replies.
```
   mkdir -p /var/jail/ident
   chown root.root /var/jail/ident
   chmod 755 /var/jail/ident
   touch /var/jail/ident/1000
   chown 1000 /var/jail/ident/1000
   chmod 644  /var/jail/ident/1000
```

For convenience, the user should have an .ident symlink in their home
directory to the configuration file.

The uid must be used for the configuration file names, not the actual
string name of the user.  This restriction exists because the ident
daemon does not have access to `/etc/passwd` from within the jail.

## User Configuration

Users who wish to reply to .ident queries should create a `.ident` file in their
home directory.  It must be readable by the user that runs the nident process.
`.ident` files are matched in an eager fashion -- the first rule that matches
ends evaluation of further rules.  Each line of `.ident` is an individual rule
with the syntax:

`HOST[/MASK] LOCAL-PORTRANGE REMOTE-PORTRANGE -> POLICY`

Specifically, for IPv4 addresses:

`d.d.d.d[/n] (*|l[:h]) (*|l[:h]) -> POLICY`

and for IPv6 addresses:

`xxxx::xxxx[/n] (*|l[:h]) (*|l[:h]) -> POLICY`

Each field is described in more detail below.

`HOST`

* IPv4 dotted decimal format only (eg: `127.0.0.1`)
* All IPv6 RFC-valid formats should be accepted, including IPv4-in-IPv6.

`MASK`

Optional network mask that will be applied to HOST when comparing to
the IP addresses of clients.  Not valid when applied to DNS names.

`LOCAL-PORTRANGE`

Port range that will be applied to the machine on which nident is running.
`*` implies any port.  A single number `l` implies one specific port.
A range of two numbers `l:h` implies all ports between and including port
`l` and port `h`.

`LOCAL-PORTRANGE`

Port range that will be applied to the machine that is connecting
to nident.  `*` implies any port.  A single number `l` implies one
specific port.  A range of two numbers `l:h` implies all ports between
and including port `l` and port `h`.

`POLICY`
* `deny`
* `accept`
* `spoof string`
* `hash [uid] [ip] [sp] [cp]`

Hash will send a reply constructed from any combination of the user's name/id
(`uid`), the ip of the remote client (`ip`), the local server port of the query
(`sp`), or the remote client port of the query (`cp`).

Spoof will send an arbitrary string as a response.  It will not allow the
spoofed string to be the same as a real user account name.

Accept will send the RFC compliant response of the user's uid/name.

Deny is somewhat redundant, as it is the default behavior, but it will send
an `ERROR:HIDDEN-USER` as a response.

## Example .ident file
```
:: * 6667:7000 -> hash uid ip cp
::1 113 * -> hash uid sp
10.0.0.0/8 25 * -> spoof foobar
192.168.0.0/16 * * -> accept
```

The first rule will match any host asking about any of our connections
to its ports `6667`, `6668`, `6669`, or `7000`.  nident will reply to these
queries with a 56-bit crypto hash constructed from the username that
owns the connection, the ip of the machine making the query, and the port
number to which we are connected.  This rule would perhaps be useful for
connecting to irc servers that demand an ident response, as the hash will
be the same on subsequent connections to the same port on the same server.
Note that because the IPv4 space is a strict subset of the IPv6 address
space (`A.B.C.D` -> `::ffff:AB:CD`), this rule will match both IPv4 and
IPv6 connections.

The second rule is rather more simple than the first.  It will only match
queries from the local machine (`::1`) asking who owns connections to port
`113` on our local machine (conveniently, this will by default be nident,
as auth runs on `113`).  nident will reply with a hash constructed from
the username that owns the nident process and the local port (`113`).
Subsequent queries will return the same hash on each attempt.

The third rule will match any host on a class A subnet of `10.x.x.x`
asking about connections to our port `25` (SMTP).  nident will always
give a response of `foobar` as the user name, unless a user exists on
the local machine named `foobar`, in which case nident will return an
`ERROR:HIDDEN-USER`.

The fourth rule is a rather trusting one.  It will return the true
username of a port's owner as long as the machine making the query is
on the `192.168.x.x` class B subnet.  This would be the default behavior
of most common identds to all queries.

## Downloads

* [GitLab](https://gitlab.com/niklata/nident)
* [BitBucket](https://bitbucket.com/niklata/nident)
* [GitHub](https://github.com/niklata/nident)

## Portability

nidentd could be ported to non-Linux systems, but will require new code
to replace the netlink mechanism used in Linux.
