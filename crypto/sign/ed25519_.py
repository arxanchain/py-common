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
import ed25519

def create_keypair():
    """Create key pair.

    :Returns signing key and verifying key
    """
    return ed25519.create_keypair()

def signing_key(keydata):
    """Create signing key.

    :param keydata: keydata used for generating signing key.
    :Returns signing key
    """
    return ed25519.SigningKey(keydata)

def sign(sign_key, message, encoding="hex"):
    """Signature message with signing key.

    :param sign_key: signing keydata
    :param message: plain message
    :param encoding: specify output encoding
    :Returns: signed message
    """
    return sign_key.sign(message, encoding)

def get_verifying_key(sign_key):
    """Get verifying key from signing key.

    :param sign_key: signing key
    :Returns: verifying key
    """
    return sign_key.get_verifying_key()

def verify(verifying_key, sig_data, plain_data, encoding="base64"):
    """Validate if verified sig data equals to plain data.

    :param verifying_key: verifying keyd
    :param sig_data: signed data
    :param plain_data: plain data
    :param encoding: sig_data encoding
    :Returns: None if euqal, else raise error
    """
    return verifying_key.verify(sig_data, plain_data, encoding)
