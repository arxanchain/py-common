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
IMPORT_PATH = os.path.join(ROOT_PATH, \
        "crypto")
sys.path.append(IMPORT_PATH)
from ecc.ec import ECCCryptoLib
from cryption import load_private_key, load_x509_cert , \
        decrypt_and_verify, sign_and_encrypt

MESSAGE = b"""{"Method":"","ErrCode":0,"ErrMessage":"",""" + \
           """Payload":{"id":"did:axn:8uQhQMGzWxR8vw5P3UWH1j",""" + \
           """endpoint":"xxxxx","key_pair":""" + \
           """{"private_key":"cHJpdmF0ZSBrZXk=",""" + \
           """public_key":"cHVibGljIGtleQ=="},"created":123}}"""

# Create your tests here.
class CryptTest(unittest.TestCase):
    """Crypto test. """
    def setUp(self):
        # Every test needs access to the request factory.
        cert_path = os.path.join(ROOT_PATH, "crypto/ecc/certs")
        cust_private_key = load_private_key(os.path.join(cert_path, "client/alice.key"))
        cust_cert = load_x509_cert(os.path.join(cert_path, "client/alice.cert"))

        serv_private_key = load_private_key(os.path.join(cert_path, "server/tls.key"))
        serv_cert = load_x509_cert(os.path.join(cert_path, "server/tls.cert"))
        self.cust_ecc = ECCCryptoLib(cust_private_key, serv_cert)
        self.serv_ecc = ECCCryptoLib(serv_private_key, cust_cert)

    def tearDown(self):
        pass

    def test_ca(self):
        """Test CA procedure. """
        cipher = sign_and_encrypt(MESSAGE, self.cust_ecc)
        self.assertEqual(decrypt_and_verify(cipher, self.serv_ecc), MESSAGE)

if __name__ == '__main__':
    unittest.main()
