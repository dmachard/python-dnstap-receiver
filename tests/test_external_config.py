
import time
import unittest
import subprocess
import shlex

def execute_dnstap(cmd):
    args = shlex.split(cmd)
    with subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as proc:
        time.sleep(2)
        proc.terminate()
        o = proc.stdout.read()
        print(o)
        
class TestExternalConfig(unittest.TestCase):
    def test1_verbose_enable(self):
        """test to load an external file"""
        cmd = 'python3 -c "from dnstap_receiver.receiver import start_receiver; start_receiver()" -c ./tests/dnstap_verbose.conf'
        execute_dnstap(cmd)
        
        self.assertRegex(o, b"External config file loaded")
        
    def test2_output_stdout_enable(self):
        """test to enable stdout output"""
        cmd = 'python3 -c "from dnstap_receiver.receiver import start_receiver; start_receiver()" -c ./tests/dnstap_verbose.conf'
        execute_dnstap(cmd)
        
        self.assertRegex(o, b"Output handler: stdout")
        
    def test2_output_metrics_enable(self):
        """test to enable metrics output"""
        cmd = 'python3 -c "from dnstap_receiver.receiver import start_receiver; start_receiver()" -c ./tests/dnstap_metrics.conf'
        execute_dnstap(cmd)
        
        self.assertRegex(o, b"Output handler: metrics")
        
    def test3_output_syslog_enable(self):
        """test to enable syslog output"""
        cmd = 'python3 -c "from dnstap_receiver.receiver import start_receiver; start_receiver()" -c ./tests/dnstap_syslog.conf'
        execute_dnstap(cmd)
        
        self.assertRegex(o, b"Output handler: syslog")
        
    def test4_output_tcp_enable(self):
        """test to enable tcp output"""
        cmd = 'python3 -c "from dnstap_receiver.receiver import start_receiver; start_receiver()" -c ./tests/dnstap_tcp.conf'
        execute_dnstap(cmd)
        
        self.assertRegex(o, b"Output handler: tcp")