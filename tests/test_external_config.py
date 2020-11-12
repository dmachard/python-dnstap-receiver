
import time
import unittest
import subprocess
import shlex

class TestExternalConfig(unittest.TestCase):
    def test1_external_cfg(self):
        """test external config"""
        cmd = 'su - _dnsdist -s /bin/bash -c \'python3 -c "from dnstap_receiver.receiver import start_receiver; start_receiver()" -c ./tests/dnstap.conf\''

        args = shlex.split(cmd)

        with subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as proc:
            time.sleep(2)
            proc.terminate()
            
            o = proc.stdout.read()
            print(o)
        self.assertRegex(o, b"Output handler: metrics")