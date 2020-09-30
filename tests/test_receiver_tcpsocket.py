
import time
import unittest
import subprocess
import dns.resolver

my_resolver = dns.resolver.Resolver(configure=False)
my_resolver.nameservers = ['127.0.0.1']

class TestTcpSocket(unittest.TestCase):
    def test1_listening(self):
        """test listening tcp socket"""
        cmd = 'sudo python3 -c "from dnstap_receiver.receiver import start_receiver; start_receiver()" -v'

        with subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as proc:
            time.sleep(2)
            proc.kill()
            
            o = proc.stdout.read()
            print(o)
        self.assertRegex(o, b"listening on")
        
    def test2_incoming_dnstap(self):
        """test to receive dnstap message"""
        cmd = 'sudo python3 -c "from dnstap_receiver.receiver import start_receiver; start_receiver()"'

        with subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as proc:
            for i in range(10):
                r = my_resolver.resolve('www.github.com', 'a')
                time.sleep(1)

            proc.kill()
            
            o = proc.stdout.read()
            print(o)
        self.assertRegex(o, b"dnsdist-tcp CLIENT_RESPONSE")
        