
import time
import unittest
import subprocess
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
    my_resolver.nameservers = [DNS_SERVER_IP]

print("--variables--")
print("dns server port: %s" % my_resolver.port)
print("dns server address: %s" % my_resolver.nameservers)
print("--")

class TestTcpSocket(unittest.TestCase):
    def test1_listening(self):
        """test listening tcp socket"""
        cmd = ["python3", "-c", 
               "from dnstap_receiver.receiver import start_receiver; start_receiver()",
               "-v"]
        with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as proc:
            time.sleep(2)
            proc.kill()
            
            o = proc.stdout.read()
            print(o)
        self.assertRegex(o, b"listening on")
        
    def test2_incoming_dnstap(self):
        """test to receive dnstap message"""
        cmd = ["python3", "-c", 
               "from dnstap_receiver.receiver import start_receiver; start_receiver()"]

        with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as proc:
            print("run dns resolution to generate dnstap message")
            for i in range(10):
                print("make dns resolution %s" % i)
                r = my_resolver.resolve('www.github.com', 'a')
                time.sleep(1)

            proc.kill()
            
            o = proc.stdout.read()
            print(o)
        self.assertRegex(o, b"CLIENT_RESPONSE")
        