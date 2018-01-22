"""
Copyright ArxanFintech Technology Ltd. 2018 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

                 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import unittest
import os
import sys

ROOT_PATH = os.path.join(os.path.dirname(__file__), \
        "..")
IMPORT_PATH = os.path.join(ROOT_PATH, "crypto")
sys.path.append(IMPORT_PATH)

from ecc.ec import ECCCryptoLib
from cryption import load_private_key, load_x509_cert

MESSAGE = b"Hello World!"

# Create your tests here.
class ECCTest(unittest.TestCase):
    def setUp(self):
        # Every test needs access to the request factory.
        cert_path = os.path.join(ROOT_PATH, "crypto/ecc/certs")
        self.private_key = load_private_key(os.path.join(cert_path, "client/alice.key"))
        self.cert = load_x509_cert(os.path.join(cert_path, "client/alice.cert"))
        self.ecc = ECCCryptoLib(self.private_key, self.cert)

    def test_encrypt_and_decrypt(self):
        encrypted = self.ecc.encrypt(MESSAGE)
        self.assertEqual(self.ecc.decrypt(encrypted), MESSAGE)

    def test_sign_and_verify(self):
        signed = self.ecc.sign(MESSAGE)
        self.assertEqual(self.ecc.verify(MESSAGE, signed), True)

if __name__ == '__main__':
    unittest.main()
