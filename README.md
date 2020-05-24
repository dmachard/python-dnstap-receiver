# Dnstap to JSON stream receiver
 
![](https://github.com/dmachard/dnstap_receiver/workflows/Publish%20to%20PyPI/badge.svg)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/dnstap_receiver)

| | |
| ------------- | ------------- |
| Author |  Denis Machard <d.machard@gmail.com> |
| License |  MIT | 
| PyPI |  https://pypi.org/project/dnstap_receiver/ |
| | |

This Python module acts as a DNS tap receiver and streams as JSON payload to remote address. 

## Table of contents
* [Installation](#installation)
* [Start dnstap receiver](#start-dnstap-receiver)
* [Systemd service](#systemd-service)
* [Tests with DNS servers](#tests-with-dns-servers)

## Installation

Deploy the dnstap receiver in your DNS server with the pip command.

```python
pip install dnstap_receiver
```

## Start dnstap receiver

```
dnstap_receiver -u /var/run/dnstap.sock -j 10.0.0.2:8000
```

```
dnstap_receiver --help
usage: test_receiver.py [-h] -u U -j J

optional arguments:
  -h, --help  show this help message and exit
  -u U        read dnstap payloads from unix socket
  -j J        write JSON payload to tcp/ip address 
```

## Systemd service

Example of system service file for Centos7

```bash
vim /etc/systemd/system/dnstap_receiver.service

[Unit]
Description=Python DNS tap Service
After=network.target

[Service]
ExecStart=/usr/local/bin/dnstap_receiver -u /etc/dnsdist/dnstap.sock -j 10.0.0.2:6000
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

## Tests with DNS servers

### PowerDNS

PowerDNS's configuration

```
vim /etc/dnsdist/dnsdist.conf

fsul = newFrameStreamUnixLogger("/var/run/dnstap.sock")
addResponseAction(AllRule(), DnstapLogResponseAction("dns", fsul))
```

