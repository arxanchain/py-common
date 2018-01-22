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

from ecies import ecies
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import sys
sys.path.append("..")
from interfaces import ICryptoLib

CURVE_P_256_SIZE = 256
SHA2 = "SHA2"

class ECCCryptoLib(ICryptoLib):
    """ A crypto implementation based on ECDSA and SHA. """

    def __init__(self, private_key, peer_cert):
        """ Init private key and public key.

        :param private_key: private key
        :param peer_cert: peer certificate
        """
        self._ecies = ecies(security_level=CURVE_P_256_SIZE, \
                hash_algorithm=SHA2)
        self._private_key = private_key
        self._cert = peer_cert
        self._public_key = self._cert.public_key()

    def sign(self, message):
        """ECDSA sign message.

        :param message: message to sign
        :Returns: signature
        """
        return self._ecies.sign(self._private_key, message)

    def verify(self, message, signature):
        """ECDSA verify signature.

        :param message: Origin message
        :param signature: Signature of message
        :Returns: verify result boolean, True means valid
        """
        return self._ecies.verify(self._public_key, message, signature)

    def decrypt(self, cipher_text):
        """Ecies decrypt cipher text.

        :param cipher_text: cipher text
        :Returns: plain text
        """
        return self._ecies.decrypt(self._private_key, cipher_text)

    def encrypt(self, plain_text):
        """Ecies encrypt plain text.

        :param plain_text: plain text
        :Returns: cipher text
        """
        return self._ecies.encrypt(self._public_key, plain_text)
