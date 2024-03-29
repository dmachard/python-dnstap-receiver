
import time
import unittest
import subprocess
import shlex
import dns.resolver
import os
import sys
import signal

DNS_SERVER_PORT = os.getenv('DNS_SERVER_PORT')
DNS_SERVER_IP = os.getenv('DNS_SERVER_IP')
DNS_USER = os.getenv('DNS_USER')

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
        # prepare command to execute
        cmd = 'sudo -u pdns -s python -c "from dnstap_receiver.receiver import start_receiver; start_receiver()" -u /tmp/dnsdist/dnstap.sock -v > /tmp/test1.out'
        #args = shlex.split(cmd)

        # start receiver
        p = subprocess.Popen(cmd, shell=True)
        time.sleep(2)

        # kill properly child processes
        output = subprocess.check_output("pgrep -P %s" % p.pid, shell=True, text=True)
        child_p = int(output)
        os.system("sudo pkill -9 -P %s" % child_p)

        # kill the main process
        try:
            p.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            p.terminate()
            p.kill()
        
        # read output
        with open("/tmp/test1.out") as f:
            o = f.read()
        print(o)

        # assert output
        self.assertRegex(o, "listening on /tmp/dnsdist/dnstap.sock")

        
    def test2_incoming_dnstap(self):
        """test to receive dnstap message"""
        cmd = 'sudo -u pdns -s python -c "from dnstap_receiver.receiver import start_receiver; start_receiver()" -u /tmp/dnsdist/dnstap.sock -v > /tmp/test2.out'

        #args = shlex.split(cmd)
        
        p = subprocess.Popen(cmd, shell=True)

        for i in range(10):
            print("make dns resolution %s" % i)
            r = my_resolver.resolve('www.github.com', 'a')
            time.sleep(1)

        # kill properly child processes
        output = subprocess.check_output("pgrep -P %s" % p.pid, shell=True, text=True)
        child_p = int(output)
        os.system("sudo pkill -9 -P %s" % child_p)

        # kill the main process
        try:
            p.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            p.terminate()
            p.kill()

        # read output
        with open("/tmp/test2.out") as f:
            o = f.read()
        print(o)

        self.assertRegex(o, "_RESPONSE")
        
