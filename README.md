# Dnstap streams receiver

![Testing](https://github.com/dmachard/dnstap_receiver/workflows/Testing/badge.svg) ![Build](https://github.com/dmachard/dnstap_receiver/workflows/Build/badge.svg) ![Pypi](https://github.com/dmachard/dnstap_receiver/workflows/PyPI/badge.svg) ![Dockerhub](https://github.com/dmachard/dnstap_receiver/workflows/DockerHub/badge.svg) 

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/dnstap_receiver)

This Python module acts as a [dnstap](https://dnstap.info/) streams receiver for DNS servers.
Input streams can be a unix, tcp or raw socket.
The output is printed directly on stdout or sent to remote tcp address 
in JSON, YAML or one line text format and more. 

## Table of contents
* [Installation](#installation)
    * [PyPI](#pypi)
    * [Docker Hub](#docker-hub)
* [Inputs handler](#inputs-handler)
    * [TCP socket (server)](#tcp-socket-server)
    * [TCP socket (client)](#tcp-socket-client)
    * [Unix socket](#unix-socket)
    * [Raw socket (sniffer)](#raw-socket-sniffer)
* [Outputs handler](#outputs-handler)
    * [Stdout](#stdout)
    * [File](#file)
    * [TCP](#tcp)
    * [Syslog](#syslog)
    * [Metrics](#metrics)
    * [Dnstap](#dnstap)
    * [Kafka](#kafka)
* [More options](#more-options)
    * [External config file](#external-config-file)
    * [Verbose mode](#verbose-mode)
    * [Filtering feature](#filtering-feature)
    * [GeoIP support](#geoip-support)
* [Statistics](#statistics)
    * [Counters](#counters)
    * [Tables](#tables)
    * [Metrics](#metrics-1)
* [Build-in Webserver](#build-in-webserver)
    * [Configuration](#configuration)
    * [Security](#security)
    * [HTTP API](#http-api)
* [Tested DNS servers](#tested-dns-servers)
    * [ISC - bind](#bind)
    * [PowerDNS - pdns-recursor](#pdns-recursor)
    * [PowerDNS - dnsdist](#dnsdist)
    * [NLnet Labs - nsd](#nsd)
    * [NLnet Labs - unbound](#unbound)
    * [CoreDNS](#coredns)
* [Benchmark](#benchmark)
* [Development](#development)
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
docker run -d -p 6000:6000 -p 8080:8080 --name=dnstap01 dmachard/dnstap-receiver
```

Add the following argument to your container if you want to provide your own [configuration](#external-config-file) file.

```bash
-v /home/dnstap.conf:/etc/dnstap_receiver/dnstap.conf
```

Follow containers logs 

```bash
docker logs dnstap01 -f
```

## Inputs handler

Severals inputs handler are supported to read incoming dnstap messages:
- [TCP socket (server)](#tcp-socket-server)
- [TCP socket (client)](#tcp-socket-client)
- [Unix socket](#unix-socket)
- [Raw socket (sniffer)](#raw-socket-sniffer)

### TCP socket (server)

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

### TCP socket (client)

The TCP socket input enable to receive dnstap messages from remote dns servers.
The communication is initiated by the dnstap receiver.

Configure this input as below

```yaml
input:
  # tcp client
  tcp-client:
    # enable or disable
    enable: true
    # retry interval in seconds to connect
    retry: 1
    # remote dns server address
    remote-address: 10.0.0.2
    # remote dns server port
    remote-port: 6000
```

### Unix socket

The unix socket input enables read dnstap message from a unix socket. 
Configure the path of the socket with the `-u` argument.

```
./dnstap_receiver -u /var/run/dnstap.sock
```

### Raw socket (sniffer)

This input enable to sniff a network interface.
Configure this input as below, you need to provide the name of your interface and associated ip.

```yaml
input:
  # sniff dns messages from network interface 
  sniffer:
    # enable or disable
    enable: true
    # interface name to sniff
    eth-name: ens18
    # ip interface to sniff
    eth-ip: [ 10.0.0.2 ]
    # dnstap identity
    dnstap-identity: sniffer
    # sniff on the list of dns port
    dns-port: [ 53 ]
    # record incoming dns client queries
    record-client-query: true
    # record outgoing dns client responses
    record-client-response: true
```

## Outputs handler

Outputs handler can be configured to forward messages in several modes.
- [Stdout](#stdout)
- [File](#file)
- [Metrics](#metrics)
- [TCP](#tcp)
- [Syslog](#syslog)
- [Dnstap](#dnstap)

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
2020-09-16T18:51:53.547352+00:00 lb1 CLIENT_QUERY NOERROR - - INET UDP 43b ns2.google.com. A -
2020-09-16T18:51:53.591736+00:00 lb2 CLIENT_RESPONSE NOERROR - - INET UDP 59b ns2.google.com. A 0.048
```

JSON format:

```json
{
    "identity": "lb1",
    "qname": "www.google.com.",
    "rrtype": "A",
    "query-ip": "192.168.1.114",
    "message": "CLIENT_QUERY",
    "family": "INET",
    "protocol": "UDP",
    "query-port": 42222,
    "length": 43,
    "timestamp": "2020-09-16T18:51:53.591736+00:00",
    "rcode": "NOERROR",
    "id": 33422,
    "flags": "RD",
    "latency": "-"
}
```

YAML format:

```yaml
identity: lb1
rcode: NOERROR
length: 49
message: CLIENT_QUERY
family: INET
qname: dns4.comlaude-dns.eu.
rrtype: AAAA
query-ip: '-'
query-port: '-'
timestamp: '2020-09-16T18:51:53.591736+00:00'
protocol: UDP
id: 33422
flags: RD
latency: '-'

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

If you are running the dnstap in a container, follow this procedure to save logs in your host instead of the container.

First one, create the folder in the host:

```
mkdir /var/dnstap/
chown 1000:1000 /var/dnstap/
```

Create the following configuration for your dnstap receiver

```
trace:
    verbose: true
output:
  stdout:
    enable: false
  file:
    enable: true
    format: text
    file: /home/dnstap/logs/dnstap.log
    file-max-size: 10M
    file-count: 10
```


Then execute the container with volume

```
docker run -d -p 6000:6000 -p 8080:8080 -v ${PWD}/dnstap.conf:/etc/dnstap_receiver/dnstap.conf \
-v /var/dnstap:/home/dnstap/logs/ --name=dnstap01 dmachard/dnstap-receiver
```


### TCP

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
Sep 22 12:43:01 bind CLIENT_RESPONSE NOERROR 192.168.1.100 51717 INET UDP 173b www.netflix.fr. A 0.040
Sep 22 12:43:01 bind CLIENT_RESPONSE NOERROR 192.168.1.100 51718 INET UDP 203b www.netflix.fr. AAAA 0.060
```

### Metrics

This output enables to generate metrics in one line and print-it to stdout. Add the following configuration as external config to activate this output:

```yaml
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

### Dnstap

This output enables to send dnstap messages to a remote dnstap receiver. Add the following configuration as external config to activate this output:

```yaml
  # forward to another remote dnstap receiver
  dnstap:
    # enable or disable
    enable: true
    # retry interval in seconds to connect
    retry: 1
    # remote ipv4 or ipv6 address of the remote dnstap receiver
    remote-address: 10.0.0.51
    # remote port of the remote dnstap receiver
    remote-port: 6000
    # dnstap identity
    dnstap-identity: dnstap-receiver
```

### Kafka

This output enables to send dnstap messages to a Kafka topic.

```yaml
  # forward to a Kafka topic
  kafka:
    # enable or disable
    enable: false
    # format available text|json|yaml
    format: json
    # configuration object to pass to librdkafka
    rdkafka-config:
      "bootstrap.servers": null
      "security.protocol": null
      "sasl.mechanism": null
      "sasl.username": null
      "sasl.password": null
    # Kafka topic to forward messages to
    topic: null
```

## More options

### External config file

The `dnstap_receiver` binary can takes an external config file with the `-c` argument or searches for a config file named dnstap.conf in /etc/dnstap_receiver/.

See [config file](/dnstap_receiver/dnstap.conf) example.

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

### GeoIP support

The `dnstap receiver` can be extended with GeoIP. To do that, you need to configure your own city database in binary format.

```yaml
# geoip support, can be used to get the country, and city
# according to the source ip in the dnstap message
geoip:
    # enable or disable
    enable: true
    # city database path in binary format
    city-database: /var/geoip/GeoLite2-City.mmdb
    # represent country in iso mode
    country-iso: false
```

With the GeoIP support, the following new fields will be added:
 - country
 - city

## Statistics

Some statistics are computed [on the fly](/dnstap_receiver/statistics.py) and stored in memory, you can get them: 
- directly from the [web server](#web-server) through the HTTP API. 
- with the [dnstap-dashboard](https://github.com/dmachard/dnstap-dashboard), a top-like command
- from your [Prometheus](https://prometheus.io/) instance

### Counters

- **query**: number of queries
- **response**: number of answers
- **qps**: number of queries per second
- **clients**: number of unique clients ip
- **domains**: number of unique domains
- **query/inet**: number of IPv4 queries
- **query/inet6**: number of IPv6 queries
- **response/inet**: number of IPv4 answers
- **response/inet6**: number of IPv6 answers
- **query/udp**: number of queries with UDP protocol
- **query/tcp**: number of queries with TCP protocol
- **response/udp**: number of answers with UDP protocol
- **response/tcp**: number of answers with TCP protocol
- **response/[rcode]**: number of answers per specific rcode = noerror, nxdomain, refused,...
- **query/[rrtype]**: number of queries per record resource type = = a, aaaa, cname,...
- **query/bytes**: total number of bytes with queries
- **response/bytes**: total number of bytes with answers
- **response/latency0_1**: number of queries answered in less than 1ms
- **response/latency1_10**: number of queries answered in 1-10 ms
- **response/latency10_50**: number of queries answered in 10-50 ms
- **response/latency50_100**: number of queries answered in 50-100 ms
- **response/latency100_1000**: number of queries answered in 100-1000 ms
- **response/latency_slow**: number of queries answered in more than 1 second

### Tables

- **tlds**: 
  - **hit/query**: table of [n] tlds sorted by number of queries
  - **hit/response**: table of [n] tlds sorted by number of answers
- **domains**: 
  - **[rcode]/query**: table of [n] domains sorted by number of queries
  - **[rcode]/response**: table of [n] domains sorted by number of answers
- **clients**: 
  - **hit/client**: table of [n] ip addresses sorted by number of queries
  - **length/ip**: table of [n] ip addresses sorted by number of bytes
- **rrtypes** 
  - **hit/query**: table of [n] resources record types sorted by the number of queries
  - **hit/response**: table of [n] resources record types sorted by the number of answers
- **top-rcodes**:
  - **hit/query**: table of [n] return codes sorted by the number of queries
  - **hit/response**: table of [n] return codes sorted by the number of answers
  
### Metrics

Metrics in [Prometheus](https://prometheus.io/) format with global counters and specific by dnstap stream.

See [metrics file](/metrics.txt) example.
```
# HELP dnstap_queries Number of queries received
# TYPE dnstap_queries counter
dnstap_queries 0
# HELP dnstap_responses Number of responses received
# TYPE dnstap_responses counter
dnstap_responses 0
# HELP dnstap_responses_noerror Number of NOERROR answers
# TYPE dnstap_responses_noerror counter
dnstap_responses_noerror 0
# HELP dnstap_responses_nxdomain Number of NXDomain answers
# TYPE dnstap_responses_nxdomain counter
dnstap_responses_nxdomain 0
# HELP dnstap_responses_servfail Number of SERVFAIL  answers
# TYPE dnstap_responses_servfail counter
dnstap_responses_servfail 0
...
```

## Build-in Webserver

The build-in web server can be used to get statistics computed by the dnstap receiver.

### Configuration

Enable the HTTP API, don't forget to change the default password.

```yaml
# rest api
web-api:
    # enable or disable
    enable: true
    # web api key
    api-key: changeme
    # basicauth login
    login: admin
    # basicauth password
    password: changeme
    # listening address ipv4 0.0.0.0 or ipv6 [::]
    local-address: 0.0.0.0
    # listing on port
    local-port: 8080
```

### Security

The following authentication methods are supported:
- BasicAuth
- X-API-Key

To access to the API, one of them method must be used in the request header.
An HTTP 401 response is returned when the authentication failed.

### HTTP API

See the [swagger](https://generator.swagger.io/?url=https://raw.githubusercontent.com/dmachard/dnstap-receiver/master/swagger.yml) documentation.

## Tested DNS servers

This dnstap receiver has been tested with success with the following dns servers:
 - [ISC](https://www.isc.org/bind/) - **bind**
 - [PowerDNS](https://github.com/PowerDNS) - **dnsdist, pdns-recursor**
 - [NLnet Labs](https://github.com/NLnetLabs) - **nsd, unbound**
 - [CoreDNS](https://github.com/coredns)

### bind

![pdns-recursor 9.11.22](https://img.shields.io/badge/9.11.22-tested-green) ![pdns-recursor 9.16.10](https://img.shields.io/badge/9.16.10-tested-green)

Dnstap messages supported:
 - RESOLVER_QUERY
 - RESOLVER_RESPONSE
 - CLIENT_QUERY
 - CLIENT_RESPONSE
 - AUTH_QUERY
 - AUTH_RESPONSE

#### Build with dnstap support

Since 9.16 version, the dnstap feature is enabled before that you need to download latest source and build-it with dnstap support:

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

If you have some troubles take a look to [selinux](https://gitlab.isc.org/isc-projects/bind9/-/issues/2356#note_185516)
 
#### TCP stream

Not supported on Bind! You can apply the following workaround with the `socat` command.

```
while true; do socat unix-listen:/var/run/dnsdist/dnstap.sock tcp4-connect:<ip_dnstap_receiver>:<port_dnstap_receiver>,forever,interval=10, fork; sleep 1; done
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

![dnsdist 1.6](https://img.shields.io/badge/1.6-tested-green) ![dnsdist 1.5](https://img.shields.io/badge/1.5-tested-green) ![dnsdist 1.4](https://img.shields.io/badge/1.4.0-tested-green) 

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
-- Cache Hits
addCacheHitResponseAction(AllRule(), DnstapLogResponseAction("dnsdist", fsul))
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
-- Cache Hits
addCacheHitResponseAction(AllRule(), DnstapLogResponseAction("dnsdist", fsul))
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

![unbound 1.11.0](https://img.shields.io/badge/1.11.0-tested-green) ![unbound 1.12.0](https://img.shields.io/badge/1.12.0-tested-green) ![unbound 1.13.0](https://img.shields.io/badge/1.13.0-tested-green)

Dnstap messages supported:
 - CLIENT_QUERY
 - CLIENT_RESPONSE
 - RESOLVER_QUERY
 - RESOLVER_RESPONSE
 
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

### CoreDNS

![coredns 1.8.4](https://img.shields.io/badge/1.8.4-tested-green) ![coredns 1.8.0](https://img.shields.io/badge/1.8.0-tested-green)

Dnstap messages supported:
 - CLIENT_QUERY
 - CLIENT_RESPONSE
 - FORWARDER_QUERY
 - FORWARDER_RESPONSE

#### Unix socket

corefile example

```
.:53 {
    dnstap /tmp/dnstap.sock full
    forward . 8.8.8.8:53
}
```

Then execute CoreDNS with your corefile

```bash
 ./coredns -conf corefile
```

#### TCP stream

corefile example

```
.:53 {
        dnstap tcp://10.0.0.51:6000 full
        forward . 8.8.8.8:53
}
```

Then execute CoreDNS with your corefile

```bash
 ./coredns -conf corefile
```

# Benchmark

## Limited lab

Tested on a limited lab with the following processor: Intel Core i5-7200U @2,50GHz 

Metrics are extracted every second:

```bash
watch -n 1 "time curl --user admin:changeme http://[ip_dnstap_receiver]:8080/metrics"
```

Dns generator used:

```bash
docker pull ns1labs/flame
docker run ns1labs/flame [ip_dns_server]
```

Result:

| Parameters| Values | 
| ------------- | ------------- |
| Query per seconds | ~11000 |
| Domains | ~40000 |
| Clients | 1 |
| CPU usage | ~30% |
| Memory usage | ~100Mo |
| Network usage | ~5.7Mb |


# Development

## Run 

the dnstap receiver from source

```bash
python3 -c "from dnstap_receiver.receiver import start_receiver; start_receiver()" -v
```

## Testunits

```bash
python3 -m unittest tests.test_receiver_tcpsocket -v
```

# About

| | |
| ------------- | ------------- |
| Author | Denis Machard <d.machard@gmail.com> |
| PyPI | https://pypi.org/project/dnstap-receiver/ |
| Github | https://github.com/dmachard/dnstap-receiver |
| DockerHub | https://hub.docker.com/r/dmachard/dnstap-receiver |
| | |
