# thc-ssl-dos mod

This is a fork from the original `thc-ssl-dos` tool written by The Hacker's Choice in 2011.

Original source code was found in Kali Linux repository here https://gitlab.com/kalilinux/packages/thc-ssl-dos

This fork supports all SSL/TLS implementations, UDP protocol (using DTLS) and both renegotiation and reconnect attacks.

It also includes a [docker lab](docker-lab-test) to test the exploit.

## Compile and execute

Same instructions as for original tool:
```
./configure
make all
src/thc-ssl-dos -h
```


## Main changes
* Code refactoring (more readable IMHO)
* SSL/TLS connection protocol choice (using `-p` or `--protocol` option)
* Cipher list choice (using `-c` or `--cipher` option)
* Reconnect attack (using `-r` or `--reconnect` option)
* UDP protocol support (using `DTLSv1` or `DTLSv1_2` on protocol choice)
* SOCKS5 proxy support (using `-s` or `--socks-proxy` option)

## Features added
* A [docker lab](docker-lab-test) (using `docker-compose`) to test the exploit (Tomcat 6.0.48 with self-signed SSL certificate, TLS1.2 and Secure Client-Initiated Renegotiation enabled)
* A [little script](flood.sh) to launch infinite instances to flood target and a [oneliner](stop_flood.sh) to kill all spawned instances

## To do
One thing i still have to do is implement multithreading, in order to spawn multiple threads to attack target, but this will require a lot of time...