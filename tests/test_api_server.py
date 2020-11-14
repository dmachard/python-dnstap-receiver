
import time
import unittest
import requests
import subprocess
import shlex

api_url = "http://127.0.0.1:8080/top"
api_key = "changeme"

class TestApiServer(unittest.TestCase):
    @classmethod
    def setUpClass(self):
        """start the receiver"""
        print("starting receiver")
        cmd = 'python3 -c "from dnstap_receiver.receiver '
        cmd += 'import start_receiver; start_receiver()"'
        self.proc = subprocess.Popen(shlex.split(cmd), 
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT)
        time.sleep(2)
    @classmethod
    def tearDownClass(self):
        """kill the process"""
        print("stop receiver")
        self.proc.kill()
        
    def test1_authvalid(self):
        """test valid authentication"""
        r = requests.get(url=api_url, timeout=1,
                         headers={'X-API-Key': api_key})
        self.assertTrue(r.status_code == 200)
        
    def test2_authinvalid(self):
        """test invalid authentication"""
        r = requests.get(url=api_url, timeout=1,
                         headers={'X-API-Key': "hello"})
        self.assertTrue(r.status_code == 401)