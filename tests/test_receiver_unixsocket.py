
import time
import unittest
import subprocess
import shlex
import dns.resolver
import os

DNS_SERVER_PORT = os.getenv('DNS_SERVER_PORT')
DNS_SERVER_IP = os.getenv('DNS_SERVER_IP')

my_resolver = dns.resolver.Resolver(configure=False)
my_resolver.nameservers = ['127.0.0.1']
my_resolver.port = 5553

# overwrite settings with environment variables
if DNS_SERVER_PORT is not None:
    my_resolver.port = int(DNS_SERVER_PORT)
if DNS_SERVER_IP is not None:
    my_resolver.nameservers= [DNS_SERVER_IP]

class TestUnixSocket(unittest.TestCase):
    def test1_listening(self):
        """test listening unix socket"""
        cmd = 'sudo -u pdns python3 -c "from dnstap_receiver.receiver import start_receiver; start_receiver()" -u /tmp/dnsdist/dnstap.sock -v'

        args = shlex.split(cmd)

        with subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as proc:
            time.sleep(2)
            proc.terminate()
            
            o = proc.stdout.read()
            print(o)
        self.assertRegex(o, b"listening on /tmp/dnsdist/dnstap.sock")
        
    def test2_incoming_dnstap(self):
        """test to receive dnstap message"""
        cmd = 'sudo -u pdns python3 -c "from dnstap_receiver.receiver import start_receiver; start_receiver()" -u /tmp/dnsdist/dnstap.sock -v'

        args = shlex.split(cmd)
        
        with subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as proc:
            for i in range(10):
                r = my_resolver.resolve('www.github.com', 'a')
                time.sleep(1)

            proc.terminate()
            
            o = proc.stdout.read()
            print(o)
        self.assertRegex(o, b"dnsdist-unix CLIENT_RESPONSE")
        