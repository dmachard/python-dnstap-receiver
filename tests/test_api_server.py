
import time
import unittest
import requests
import subprocess
import shlex

api_url = "http://127.0.0.1:8081/top"
api_key = "changeme"

class TestApiServer(unittest.TestCase):
    def setUp(self):
        """start the receiver"""
        cmd = 'python3 -c "from dnstap_receiver.receiver '
        cmd += 'import start_receiver; start_receiver()"'
        self.proc = subprocess.Popen(shlex.split(cmd), 
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT)
    def tearDown(self):
        """kill the process"""
        self.proc.kill()
        
    def test1_api_running(self):
        """check if the api is running properly"""
        time.sleep(2)
        
        o = self.proc.stdout.read()
        print(o)
        self.assertRegex(o, b"Api rest: listening on 127.0.0.1:8080")
