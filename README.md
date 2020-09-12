# Dnstap to JSON stream receiver
 
![](https://github.com/dmachard/dnstap_receiver/workflows/Publish%20to%20PyPI/badge.svg)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/dnstap_receiver)

This Python module acts as a DNS tap receiver and streams as JSON payload to remote address or stdout. 

## Table of contents
* [Installation](#installation)
* [Show help usage](#show-help-usage)
* [Start dnstap receiver](#start-dnstap-receiver)
* [Output JSON format](#output-json-format)
* [Systemd service file configuration](#systemd-service-file-configuration)
* [Tested DNS servers](#tested-dns-servers)
* [Tested Logs Collectors](#tested-dns-servers)
* [About](#about)

## Installation

Deploy the dnstap receiver in your DNS server with the pip command.

```python
pip install dnstap_receiver
```

## Show help usage

```
dnstap_receiver --help
usage: dnstap_receiver.py [-h] -u U -j J

optional arguments:
  -h, --help  show this help message and exit
  -u U        read dnstap payloads from unix socket
  -j J        write JSON payload to tcp/ip address 
```

## Start dnstap receiver

The 'dnstap_receiver' binary takes in input a unix socket 

```
dnstap_receiver -u /var/run/dnstap.sock
```

You can also add a remote tcp json collector to forward the log to another destination

```
dnstap_receiver -u /var/run/dnstap.sock -j 10.0.0.2:8192
```

## Output JSON format

CLIENT_QUERY

```json
{
    "message": "CLIENT_QUERY",
    "s_family": "IPv4",
    "s_proto": "TCP",
    "q_addr": "127.0.0.1",
    "q_port": 43935, 
    "dt_query": "2020-09-12 10:41:36.591",
    "q_name": "www.google.com.",
    "q_type": "A"
}
```

CLIENT_RESPONSE

```json
{
    "r_code": "NOERROR",
    "port": 52782,
    "q_name":"rpc.gandi.net.",
    "s_family":"IPv4",
    "r_bytes": 47,
    "dt_reply": "2020-05-24 03:30:01.411",
    "q_addr": "10.0.0.235",
    "host": "10.0.0.97",
    "message": "CLIENT_RESPONSE",
    "q_type": "A",
    "s_proto": "UDP",
    "dt_query": "2020-05-24 03:30:01.376",
    "q_port": 40311,
    "q_time": 0.035
}
```

RESOLVER_QUERY

```json
{
    "message": "RESOLVER_QUERY",
    "s_family": "IPv4",
    "s_proto": "UDP",
    "q_addr": "?",
    "q_port": 0,
    "dt_query": "2020-09-12 10:43:45.902",
    "q_name": "n6dsce9.akamaiedge.net.",
    "q_type": "AAAA"
}
```

RESOLVER_RESPONSE

```json
{
    "message": "RESOLVER_RESPONSE",
    "s_family": "IPv4",
    "s_proto": "UDP",
    "q_addr": "?",
    "q_port": 0,
    "dt_query": "2020-09-12 10:43:45.866",
    "dt_reply": "2020-09-12 10:43:45.920",
    "q_time": 0.054,
    "q_name": "n2dsce9.akamaiedge.net.",
    "q_type": "A",
    "r_code": "NOERROR",
    "r_bytes": 67
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
ExecStart=/usr/local/bin/dnstap_receiver -u /etc/dnsdist/dnstap.sock -j 10.0.0.2:8192
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

## Tested DNS servers

This dnstap receiver has been tested with success with the following dns servers:
 - PowerDNS - dnsdist 
 - NLnet Labs - unbound
 
*dnsdist*

The following file `/etc/dnsdist/dnsdist.conf` must be updated like below:
```
fsul = newFrameStreamUnixLogger("/var/run/dnstap.sock")
addAction(AllRule(), DnstapLogAction(fsul))
addResponseAction(AllRule(), DnstapLogResponseAction(fsul))
```

*unbound*

![unbound 1.11.0](https://img.shields.io/badge/version-1.11.0-green)

Unbound must build with dnstap support `./configure --enable-dnstap`.
The following file `/etc/unbound/unbound.conf` must be updated too:

```
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

## Tested Logs Collectors

### Logstash

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

# About

| | |
| ------------- | ------------- |
| Author |  Denis Machard <d.machard@gmail.com> |
| License |  MIT | 
| PyPI |  https://pypi.org/project/dnstap_receiver/ |
| | |
