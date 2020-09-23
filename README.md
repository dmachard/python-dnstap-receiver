# Dnstap streams receiver
 
![](https://github.com/dmachard/dnstap_receiver/workflows/Publish%20to%20PyPI/badge.svg)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/dnstap_receiver)

This Python module acts as a DNS tap streams receiver for DNS servers.
Input streams can be a unix socket or multiple remote dns servers.
The output is printed directly to stdout or send to remote tcp address in JSON, YAML or one line text format. 

## Table of contents
* [Installation](#installation)
* [Start dnstap receiver](#start-dnstap-receiver)
    * [Unix socket mode](#unix-socket-mode)
    * [TCP socket mode](#tcp-socket-mode)
    * [TLS socket mode](#tls-socket-mode)
* [More options](#more-options)
    * [Verbose mode](#verbose-mode)
    * [External config file](#external-config-file)
    * [Formatted output](#formatted-output)
    * [Filtering feature](#filtering-feature)
    * [Forward feature](#forward-feature)
* [Tested DNS servers](#tested-dns-servers)
    * [ISC - bind](#bind)
        * [Build with dnstap support](#build-with-dnstap-support)
        * [Unix socket](#unix-socket)
    * [PowerDNS - pdns-recursor](#pdns-recursor)
        * [Unix socket](#unix-socket-1)
        * [TCP stream](#tcp-stream)
    * [PowerDNS - dnsdist](#dnsdist)
        * [Unix socket](#unix-socket-2)
        * [TCP stream](#tcp-stream-1)
    * [NLnet Labs - nsd](#nsd)
        * [Build with dnstap support](#build-with-dnstap-support-1)
        * [Unix socket](#unix-socket-3)
        * [TCP stream](#tcp-stream-2)
    * [NLnet Labs - unbound](#unbound)
        * [Build with dnstap support](#build-with-dnstap-support-2)
        * [Unix socket](#unix-socket-4)
        * [TCP stream](#tcp-stream-3)
        * [TLS stream](#tls-stream)
* [Tested Logs Collectors](#tested-dns-servers)
    * [Logstash](#logstash-with-json-input)
* [Systemd service file configuration](#systemd-service-file-configuration)
* [About](#about)

## Installation

Deploy the dnstap receiver in your DNS server with the pip command.

```python
pip install dnstap_receiver
```

## Start dnstap receiver

### TCP socket mode

This mode enable to receive dnstap messages from multiple dns servers.
By default, the receiver is listening on the ip `0.0.0.0` and the tcp port `6000`.

```
./dnstap_receiver
```

### Unix socket mode

In this mode, the `dnstap_receiver` binary takes in input a unix socket 

```
./dnstap_receiver -u /var/run/dnstap.sock
```

### TLS socket mode

This mode enable to receive dnstap messages from multiple dns servers with tcp/tls transport.
By default, the receiver is listening on the ip `0.0.0.0` and the tcp port `6000`.

Generate a certificate and private key for the dnstap receiver:

```
openssl req -x509 -newkey rsa:4096 -sha256  -nodes -keyout server.key -out server.crt  -subj "/CN=dnstap_receiver.com" -days 3650
```

Create the external configuration file and enable tls:

```yaml
input:
  tcp-socket:
    local-address: 0.0.0.0
    local-port: 6000
    # enable tls on socket
    tls-support: true
    tls-server-cert: /etc/dnstap_receiver/server.crt
    tls-server-key: /etc/dnstap_receiver/server.key
```

Finally execute the dnstap receiver with the configuration file:

```
./dnstap_receiver -c /etc/dnstap-receiver/dnstap.conf
```

## More options

### Verbose mode

You can execute the binary in verbose mode with the `-v` argument

```
./dnstap_receiver -v
2020-09-12 23:47:35,833 Start dnstap receiver...
2020-09-12 23:47:35,833 Using selector: EpollSelector
2020-09-12 23:47:35,834 Listening on 0.0.0.0:6000
```

### External config file

The `dnstap_receiver` binary can takes an external config file with the `-c` argument
See [config file](https://github.com/dmachard/dnstap-receiver/blob/master/dnstap_receiver/dnstap.conf) example.

```
./dnstap_receiver -c /etc/dnstap-receiver/dnstap.conf
```

### Formatted output

Output can be formatted in different way:
- quiet text(default one)
- json 
- yaml.

#### Quiet text

By default the output will be print in quiet text format.

```
2020-09-16T18:51:53.547352+00:00 dev-centos8 RESOLVER_QUERY NOERROR - - IP4 UDP 43b ns2.google.com. A
2020-09-16T18:51:53.591736+00:00 dev-centos8 RESOLVER_RESPONSE NOERROR - - IP4 UDP 59b ns2.google.com. A
```


```yaml
output:
  sdtout:
    format: text
```


#### JSON-formatted

JSON output can be activated through the external configuration file

```yaml
output:
  sdtout:
    format: json
```

Output example:

```json
{
    "identity": "dev-centos8",
    "query-name": "www.google.com.",
    "query-type": "A",
    "source-ip": "192.168.1.114",
    "message": "CLIENT_QUERY",
    "protocol": "IP4",
    "transport": "UDP",
    "source-port": 42222,
    "length": 43,
    "timestamp": "2020-09-12 22:24:34.132",
    "code": "NOERROR"
}
```

#### YAML-formatted

YAML output can be activated through the external configuration file

```yaml
output:
  sdtout:
    format: yaml
```

Output example:

```yaml
code: NOERROR
length: 49
message: RESOLVER_QUERY
protocol: IP4
query-name: dns4.comlaude-dns.eu.
query-type: AAAA
source-ip: '-'
source-port: '-'
timestamp: '2020-09-12 14:13:53.948'
transport: UDP

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


### Forward feature

Output can be configured to forward messages in several modes.
- stdout
- remote tcp socket

#### Forward to STDOUT

This mode is the default one.

#### Forward to remote TCP socket

Forward dnstap message to a remote tcp collector can be done through the 
external configuration file 
 
```yaml
output:
  tcp-socket:
    remote-address: 10.0.0.2
    remote-port: 8192
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

![pdns-recursor 4.3.4](https://img.shields.io/badge/4.3.4-tested-green)

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

![unbound 1.11.0](https://img.shields.io/badge/1.11.0-tested-green)

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


## Tested Logs Collectors

### Logstash with json input

vim /etc/logstash/conf.d/00-dnstap.conf

```
input {
  tcp {
      port => 8192
      codec => json
  }
}

filter {
  date {
     match => [ "dt_query" , "yyyy-MM-dd HH:mm:ss.SSS" ]
     target => "@timestamp"
  }
}

output {
   elasticsearch {
    hosts => ["http://localhost:9200"]
    index => "dnstap-lb"
  }
}
```

## Systemd service file configuration

System service file for CentOS:

```bash
vim /etc/systemd/system/dnstap_receiver.service

[Unit]
Description=Python DNS tap Service
After=network.target

[Service]
ExecStart=/usr/local/bin/dnstap_receiver -u /etc/dnsdist/dnstap.sock -f 10.0.0.2:8192
Restart=on-abort
Type=simple
User=root

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl start dnstap_receiver
systemctl status dnstap_receiver
systemctl enable dnstap_receiver
```

# About

| | |
| ------------- | ------------- |
| Author |  Denis Machard <d.machard@gmail.com> |
| License |  MIT | 
| PyPI |  https://pypi.org/project/dnstap_receiver/ |
| | |
