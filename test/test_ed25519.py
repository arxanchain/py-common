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
import hashlib
from crypto.sign.ed25519_ import create_keypair, \
        sign, verify, signing_key, get_verifying_key

ROOT_PATH = os.path.join(os.path.dirname(__file__), \
        "..")
IMPORT_PATH = os.path.join(ROOT_PATH, "crypto")
sys.path.append(IMPORT_PATH)

MESSAGE = b"Hello World!"

# Create your tests here.
class EdTest(unittest.TestCase):
    """ed25519 test. """
    def setUp(self):
        # Every test needs access to the request factory.
        pass

    def test_sign_and_verify(self):
        """Test sign and verify. """
        sig, verifier = create_keypair()
        signed_message = sign(sig, MESSAGE, encoding="base64")
        self.assertEqual(verify(verifier, signed_message, MESSAGE, "base64"), \
                None)

    def test_sign_and_verify_sequence(self):
        """Test sign and verify in sequence. """
        master = os.urandom(87)
        seed = hashlib.sha256(master).digest()
        sign_key = signing_key(seed)
        signed_message = sign(sign_key, MESSAGE, "hex")
        verifier = get_verifying_key(sign_key)
        self.assertEqual(verify(verifier, signed_message, MESSAGE, "hex"), None)


if __name__ == '__main__':
    unittest.main()
