# Dnstap streams receiver

![Testing](https://github.com/dmachard/dnstap_receiver/workflows/Testing/badge.svg) ![Build](https://github.com/dmachard/dnstap_receiver/workflows/Build/badge.svg) ![Pypi](https://github.com/dmachard/dnstap_receiver/workflows/PyPI/badge.svg) ![Dockerhub](https://github.com/dmachard/dnstap_receiver/workflows/DockerHub/badge.svg) 

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/dnstap_receiver)

This Python module acts as a DNS tap streams receiver for DNS servers.
Input streams can be a unix socket or multiple remote dns servers.
The output is printed directly to stdout or send to remote tcp address 
in JSON, YAML or one line text format and more. 

## Table of contents
* [Installation](#installation)
    * [PyPI](#pypi)
    * [Docker Hub](#docker-hub)
* [Inputs handler](#inputs-handler)
    * [TCP socket](#tcp-socket)
    * [Unix socket](#unix-socket)
* [Outputs handler](#outputs-handler)
    * [Stdout](#stdout)
    * [File](#file)
    * [TCP socket](#tcp-socket)
    * [Syslog](#syslog)
    * [Metrics](#stdout-metrics)
* [More options](#more-options)
    * [External config file](#external-config-file)
    * [Verbose mode](#verbose-mode)
    * [Filtering feature](#filtering-feature)
* [API](#api)
    * [Configuration](#configuration)
    * [Security](#security)
    * [URL endpoints](#url-endpoints)
* [Tested DNS servers](#tested-dns-servers)
    * [ISC - bind](#bind)
    * [PowerDNS - pdns-recursor](#pdns-recursor)
    * [PowerDNS - dnsdist](#dnsdist)
    * [NLnet Labs - nsd](#nsd)
    * [NLnet Labs - unbound](#unbound)
* [About](#about)

## Installation

### PyPI

Deploy the dnstap receiver in your DNS server with the pip command.

```python
pip install dnstap_receiver
```

After installation, you can execute the `dnstap_receiver` to start-it.

Usage:

```
usage: dnstap_receiver [-h] [-l L] [-p P] [-u U] [-v] [-c C]

optional arguments:
  -h, --help  show this help message and exit
  -l L        IP of the dnsptap server to receive dnstap payloads (default: '0.0.0.0')
  -p P        Port the dnstap receiver is listening on (default: 6000)
  -u U        read dnstap payloads from unix socket
  -v          verbose mode
  -c C        external config file
```


### Docker Hub

Pull the dnstap receiver image from Docker Hub.

```bash
docker pull dmachard/dnstap-receiver:latest
```

Deploy the container

```bash
docker run -d -p 6000:6000 --name=dnstap01 dmachard/dnstap-receiver
```

Follow containers logs 

```bash
docker logs dnstap01 -f
```

## Inputs handler

Severals inputs handler are supported to read incoming dnstap messages:
- [TCP socket](#tcp-socket)
- [Unix socket](#unix-socket)

### TCP socket

The TCP socket input enable to receive dnstap messages from multiple dns servers.
This is the default input if you execute the binary without arguments.
The receiver is listening on `localhost` interface and the tcp port `6000`.
You can change binding options with `-l` and `-p` arguments.

```
./dnstap_receiver -l 0.0.0.0 -p 6000
```

You can also activate `TLS` on the socket, add the following config as external config file
to activate the tls support, configure the path of the certificate and key to use.

```yaml
input:
  tcp-socket:
    # enable tls support
    tls-support: true
    # provide certificate server path
    tls-server-cert: /etc/dnstap_receiver/server.crt
    # provide certificate key path
    tls-server-key: /etc/dnstap_receiver/server.key
```

Then execute the dnstap receiver with the configuration file:

```
./dnstap_receiver -c /etc/dnstap-receiver/dnstap.conf
```

### Unix socket

The unix socket input enables read dnstap message from a unix socket. 
Configure the path of the socket with the `-u` argument.

```
./dnstap_receiver -u /var/run/dnstap.sock
```

## Outputs handler

Outputs handler can be configured to forward messages in several modes.
- [Stdout](#stdout)
- [File](#file)
- [Metrics](#metrics)
- [TCP socket](#tcp-socket)
- [Syslog](#syslog)

### Stdout

This output enables to forward dnstap messages directly to Stdout.
Add the following configuration as external config to activate this output:

```yaml
output:
  stdout:
    # enable or disable
    enable: true
    # format available text|json|yaml
    format: text
```

Output can be formatted in different way:
- text (default one)
- json 
- yaml

Text format:

```
2020-09-16T18:51:53.547352+00:00 centos RESOLVER_QUERY NOERROR - - INET UDP 43b ns2.google.com. A
2020-09-16T18:51:53.591736+00:00 centos RESOLVER_RESPONSE NOERROR - - INET UDP 59b ns2.google.com. A
```

JSON format:

```json
{
    "identity": "dev-centos8",
    "qname": "www.google.com.",
    "rrtype": "A",
    "source-ip": "192.168.1.114",
    "message": "CLIENT_QUERY",
    "family": "INET",
    "protocol": "UDP",
    "source-port": 42222,
    "length": 43,
    "timestamp": "2020-09-16T18:51:53.591736+00:00",
    "rcode": "NOERROR"
}
```

YAML format:

```yaml
rcode: NOERROR
length: 49
message: RESOLVER_QUERY
family: INET
qname: dns4.comlaude-dns.eu.
rrtype: AAAA
source-ip: '-'
source-port: '-'
timestamp: '2020-09-16T18:51:53.591736+00:00'
protocol: UDP

```

### File

This output enables to forward dnstap messages directly to a log file.
Add the following configuration as external config to activate this output:

```yaml
  # forward to log file
  file:
    # enable or disable
    enable: true
    # format available text|json|yaml
    format: text
    # log file path or null to print to stdout
    file: /var/log/dnstap.log
    # max size for log file
    file-max-size: 10M
    # number of max log files
    file-count: 10
```

### TCP socket

This output enables to forward dnstap message to a remote tcp collector.
Add the following configuration as external config to activate this output:

```yaml
output:
  # forward to remote tcp destination
  tcp-socket:
    # enable or disable
    enable: true
    # format available text|json|yaml
    format: text
    # delimiter
    delimiter: "\n"
    # retry interval in seconds to connect
    retry: 5
    # remote ipv4 or ipv6 address
    remote-address: 10.0.0.2
    # remote tcp port
    remote-port: 8192
```

### Syslog

This output enables to forward dnstap message to a syslog server.
Add the following configuration as external config to activate this output:


```yaml
output:
  syslog:
    # enable or disable
    enable: false
    # syslog over tcp or udp
    transport: udp
    # format available text|json
    format: text
    # retry interval in seconds to connect
    retry: 5
    # remote ipv4 or ipv6 address of the syslog server
    remote-address: 10.0.0.2
    # remote port of the syslog server
    remote-port: 514
```

Example of output on syslog server

```
Sep 22 12:43:01 bind CLIENT_RESPONSE NOERROR 192.168.1.100 51717 INET UDP 173b www.netflix.fr. A
Sep 22 12:43:01 bind CLIENT_RESPONSE NOERROR 192.168.1.100 51718 INET UDP 203b www.netflix.fr. AAAA
```

### Metrics

This output enables to generate metrics in one line and print-it to stdout. Add the following configuration as external config to activate this output:

```
output:
  metrics:
    # enable or disable
    enable: true
    # print every N seconds.
    interval: 300
    # cumulative statistics, without clearing them after printing
    cumulative: true
    # log file path or null to print to stdout
    file: null
    # max size for log file
    file-max-size: 10M
    # number of max log files
    file-count: 10
```

Example of output

```
2020-10-13 05:19:35,522 18 QUERIES, 3.6 QPS, 1 CLIENTS, 18 INET, 0 INET6, 
18 UDP, 0 TCP, 17 DOMAINS
```

## More options

### External config file

The `dnstap_receiver` binary can takes an external config file with the `-c` argument
See [config file](https://github.com/dmachard/dnstap-receiver/blob/master/dnstap_receiver/dnstap.conf) example.

```
./dnstap_receiver -c /etc/dnstap-receiver/dnstap.conf
```

### Verbose mode

You can execute the binary in verbose mode with the `-v` argument:

```
./dnstap_receiver -v
2020-11-25 20:26:59,790 DEBUG Start receiver...
2020-11-25 20:26:59,790 DEBUG Output handler: stdout
2020-11-25 20:26:59,790 DEBUG Input handler: tcp socket
2020-11-25 20:26:59,790 DEBUG Input handler: listening on 0.0.0.0:6000
2020-11-25 20:26:59,790 DEBUG Api rest: listening on 0.0.0.0:8080
```

### Filtering feature

This feature can be useful if you want to ignore some messages and keep just what you want.
Several filter are available:
- by qname field
- by dnstap identity field.

#### By dnstap identity

You can filtering incoming dnstap messages according to the dnstap identity field.
A regex can be configured in the external configuration file to do that

```yaml
filter:
  # dnstap identify filtering feature with regex support
  dnstap-identities: dnsdist01|unbound01
```

#### By qname

You can filtering incoming dnstap messages according to the query name.
A regex can be configured in the external configuration file to do that

```yaml
filter: 
  # qname filtering feature with regex support
  qname-regex: ".*.com"
```

## API

### Configuration

Enable the REST API 

```yaml
# rest api
web-api:
    # enable or disable
    enable: true
    # web api key
    api-key: changeme
    # listening address ipv4 0.0.0.0 or ipv6 [::]
    local-address: 127.0.0.1
    # listing on port
    local-port: 8080
```

### Security

To access to the API, key must be sent in the X-API-Key request header.
An HTTP 401 response is returned when a wrong or no API key is received.

```
X-API-Key: secret
```

### URL Endpoints

**GET /streams**

Get streams list by dnstap identity.

Example request:

```
GET /streams
```

Example JSON response:

```json
{
  "streams": [
               "dnsdist1", 
               "unbound1"
             ]
}
```

**GET /count**

Get some counters like number of queries, clients, ...
This endpoint accepts optional arguments in the query:
- **more** (optional): additional counters to return
    - query|response: total of queries or response
    - qps: query per second
    - clients: total unique clients ip
    - domains: total unique domains
    - query|response/[inet|inet6] : total of IPv4 or IPv6 queries or responses
    - query|response/[udp|tcp]: total of queries or responses with UDP or TCP protocol
    - query|response/[rcode]: total of queries or responses according to the rcode (noerror, nxdomain, ...)
    - query|response/[rrtype]: total of queries or responses acccording to the record resource type (a, aaaa, ...)
                               
Example request:

```
GET /count
```

Example JSON response:

```json
{
  "stream": null,
  "counters": {
                "clients": 2,
                "domains": 13,
                "query": 5983,
                "response": 5983,
                "qps": 0,
                "response/noerror": 5983,
                "response/nxdomain": 0
               }
}
```

**GET /top**

Get top statistics from the dnstap-receiver in JSON format.
This endpoint accepts optional arguments in the query:
- **n** (default is 10): number of elements to return
- **stream** (optional): return statistic according to the dnstap identity or all if not provided
- **more** (optional): additional criteria to return for top domain
    - [rcode]/response|query: top n domains according to the rcode (noerror, nxdomain, refused, ...)
    - [rrtype]/response|query: top n domains according to the rrtype (aa, aaaa, cname, ...)
    
Example request:

```
GET /top
```

Example JSON response:

```json
{
  "stream": null, 
  "top-domain": {
                  "noerror/response": [
                                        ["www.google.fr.", 2969], 
                                        ["d220140hrb0h87.cloudfront.net.", 3],
                                        ["uu.net.", 1], 
                                        ["fr.uu.net.", 1], 
                                        ["nan2.fr.uu.net.", 1], 
                                        ["cloudfront.net.", 1], 
                                        ["awsdns-53.net.", 1], 
                                        ["ns-942.awsdns-53.net.", 1]
                                        ], 
                   "nxdomain/response": []
                 }, 
   "top-client": {
                  "hit/ip": [
                             ["127.0.0.1", 11938],
                             ["-", 28]
                            ],
                  "length/ip": [
                                ["127.0.0.1", 969528],
                                ["-", 7048]
                               ]
                 }, 
   "top-rcode": {
                  "hit/query": [
                                ["query/noerror", 5983]
                               ], 
                  "hit/response": [
                                   ["response/noerror", 5983]
                                  ]
                }, 
   "top-rrtype": {
                  "hit/query": [
                                 ["query/a", 3982], 
                                 ["query/aaaa", 2001]
                               ], 
                  "hit/response": [
                                    ["response/a", 3982], 
                                    ["response/aaaa", 2001]
                                   ]
                 }
}
```

**DELETE /reset**

Reset statistics

Example request:

```
DELETE /reset
```

Example response:

```
204 No Content
```

## Tested DNS servers

This dnstap receiver has been tested with success with the following dns servers:
 - **ISC - bind**
 - **PowerDNS - dnsdist, pdns-recursor**
 - **NLnet Labs - nsd, unbound**

### bind

![pdns-recursor 9.11.22](https://img.shields.io/badge/9.11.22-tested-green)

Dnstap messages supported:
 - RESOLVER_QUERY
 - RESOLVER_RESPONSE
 - CLIENT_QUERY
 - CLIENT_RESPONSE
 - AUTH_QUERY
 - AUTH_RESPONSE

#### Build with dnstap support

Download latest source and build-it with dnstap support:

```bash
./configure --enable-dnstap
make && make install
```

#### Unix socket

Update the configuration file `/etc/named.conf` to activate the dnstap feature:

```
options {
    dnstap { client; auth; resolver; forwarder; };
    dnstap-output unix "/var/run/named/dnstap.sock";
    dnstap-identity "dns-bind";
    dnstap-version "bind";
}
```

Execute the dnstap receiver with `named` user:

```bash
su - named -s /bin/bash -c "dnstap_receiver -u "/var/run/named/dnstap.sock""
```

### pdns-recursor

![pdns-recursor 4.3.4](https://img.shields.io/badge/4.3.4-tested-green) ![pdns-recursor 4.4.0](https://img.shields.io/badge/4.4.0-tested-green)

Dnstap messages supported:
 - RESOLVER_QUERY
 - RESOLVER_RESPONSE

#### Unix socket

Update the configuration file to activate the dnstap feature:

```
vim /etc/pdns-recursor/recursor.conf
lua-config-file=/etc/pdns-recursor/recursor.lua

vim /etc/pdns-recursor/recursor.lua
dnstapFrameStreamServer("/var/run/pdns-recursor/dnstap.sock")
```

Execute the dnstap receiver with `pdns-recursor` user:

```bash
su - pdns-recursor -s /bin/bash -c "dnstap_receiver -u "/var/run/pdns-recursor/dnstap.sock""
```

#### TCP stream

Update the configuration file to activate the dnstap feature with tcp mode 
and execute the dnstap receiver in listening tcp socket mode:

```
vim /etc/pdns-recursor/recursor.conf
lua-config-file=/etc/pdns-recursor/recursor.lua

vim /etc/pdns-recursor/recursor.lua
dnstapFrameStreamServer("10.0.0.100:6000")
```

Note: TCP stream are only supported with a recent version of libfstrm.
 
### dnsdist

![dnsdist 1.4.0](https://img.shields.io/badge/1.4.0-tested-green) ![dnsdist 1.5.0](https://img.shields.io/badge/1.5.0-tested-green)

Dnstap messages supported:
 - CLIENT_QUERY
 - CLIENT_RESPONSE

#### Unix socket

Create the dnsdist folder where the unix socket will be created:

```bash
mkdir -p /var/run/dnsdist/
chown dnsdist.dnsdist /var/run/dnsdist/
```

Update the configuration file `/etc/dnsdist/dnsdist.conf` to activate the dnstap feature:

```
fsul = newFrameStreamUnixLogger("/var/run/dnsdist/dnstap.sock")
addAction(AllRule(), DnstapLogAction("dnsdist", fsul))
addResponseAction(AllRule(), DnstapLogResponseAction("dnsdist", fsul))
```

Execute the dnstap receiver with `dnsdist` user:

```bash
su - dnsdist -s /bin/bash -c "dnstap_receiver -u "/var/run/dnsdist/dnstap.sock""
```

#### TCP stream

Update the configuration file `/etc/dnsdist/dnsdist.conf` to activate the dnstap feature
with tcp stream and execute the dnstap receiver in listening tcp socket mode:

```
fsul = newFrameStreamTcpLogger("127.0.0.1:8888")
addAction(AllRule(), DnstapLogAction("dnsdist", fsul))
addResponseAction(AllRule(), DnstapLogResponseAction("dnsdist", fsul))
```

### nsd

![nsd 4.3.2](https://img.shields.io/badge/4.3.2-tested-green)

Dnstap messages supported:
 - AUTH_QUERY
 - AUTH_RESPONSE

#### Build with dnstap support

Download latest source and build-it with dnstap support:

```bash
./configure --enable-dnstap
make && make install
```

#### Unix socket

Update the configuration file `/etc/nsd/nsd.conf` to activate the dnstap feature:

```yaml
dnstap:
    dnstap-enable: yes
    dnstap-socket-path: "/var/run/nsd/dnstap.sock"
    dnstap-send-identity: yes
    dnstap-send-version: yes
    dnstap-log-auth-query-messages: yes
    dnstap-log-auth-response-messages: yes
```

Execute the dnstap receiver with `nsd` user:

```bash
su - nsd -s /bin/bash -c "dnstap_receiver -u "/var/run/nsd/dnstap.sock""
```


### unbound

![unbound 1.11.0](https://img.shields.io/badge/1.11.0-tested-green) ![unbound 1.112.0](https://img.shields.io/badge/1.12.0-tested-green)

Dnstap messages supported:
 - CLIENT_QUERY
 - CLIENT_RESPONSE
 - RESOLVER_QUERY
 - RESOLVER_RESPONSE
 - CLIENT_QUERY
 - CLIENT_RESPONSE
 
#### Build with dnstap support

Download latest source and build-it with dnstap support:

```bash
./configure --enable-dnstap
make && make install
```

#### Unix socket

Update the configuration file `/etc/unbound/unbound.conf` to activate the dnstap feature:

```yaml
dnstap:
    dnstap-enable: yes
    dnstap-socket-path: "dnstap.sock"
    dnstap-send-identity: yes
    dnstap-send-version: yes
    dnstap-log-resolver-query-messages: yes
    dnstap-log-resolver-response-messages: yes
    dnstap-log-client-query-messages: yes
    dnstap-log-client-response-messages: yes
    dnstap-log-forwarder-query-messages: yes
    dnstap-log-forwarder-response-messages: yes
```

Execute the dnstap receiver with `unbound` user:

```bash
su - unbound -s /bin/bash -c "dnstap_receiver -u "/usr/local/etc/unbound/dnstap.sock""
```

#### TCP stream

Update the configuration file `/etc/unbound/unbound.conf` to activate the dnstap feature 
with tcp mode and execute the dnstap receiver in listening tcp socket mode:

```yaml
dnstap:
    dnstap-enable: yes
    dnstap-socket-path: ""
    dnstap-ip: "10.0.0.100@6000"
    dnstap-tls: no
    dnstap-send-identity: yes
    dnstap-send-version: yes
    dnstap-log-client-query-messages: yes
    dnstap-log-client-response-messages: yes
```

#### TLS stream

Update the configuration file `/etc/unbound/unbound.conf` to activate the dnstap feature 
with tls mode and execute the dnstap receiver in listening tcp/tls socket mode:

```yaml
dnstap:
    dnstap-enable: yes
    dnstap-socket-path: ""
    dnstap-ip: "10.0.0.100@6000"
    dnstap-tls: yes
    dnstap-send-identity: yes
    dnstap-send-version: yes
    dnstap-log-client-query-messages: yes
    dnstap-log-client-response-messages: yes
```

# About

| | |
| ------------- | ------------- |
| Author | Denis Machard <d.machard@gmail.com> |
| PyPI | https://pypi.org/project/dnstap_receiver/ |
| Github | https://github.com/dmachard/dnstap-receiver |
| DockerHub | https://hub.docker.com/r/dmachard/dnstap-receiver |
| | |
