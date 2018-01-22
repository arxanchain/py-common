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

import logging
import json
from base64 import b64encode, b64decode
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key

IS_SIGN = True
IS_ENCRYPT = True

class SignedData(object):
    """ A signed data implementation"""

    def __init__(self, data, signature):
        """ Init signed data with raw data and signature of data"""

        self.Data = data
        self.Signature = signature

def load_x509_cert(filename):
    """Load cert file.

    :param filename: File name of cert file
    :Returns: certficate
    """
    return load_pem_x509_certificate(open(filename).read(), \
            default_backend())

def load_private_key(filename):
    """Load private key

    :param fillename: File name of private key
    :Returns: private key
    """
    return load_pem_private_key(open(filename).read(), \
            None, default_backend())

def decrypt_and_verify(data, crypto_lib):
    """Decrypt and verify date with ICryptoLib instance

    :param data: data to be decrypted and verified
    :param crypto_lib: crypto instance that impliments decrypt and verify
    :Returns: decoded and verified message
    """
    ## Decrypt
    b64_crypted_data = b64decode(data)
    raw_data_with_sign = ""
    if IS_ENCRYPT:
        logging.debug("Decrypt data...")
        try:
            raw_data_with_sign = crypto_lib.decrypt(b64_crypted_data)
        except Exception, e:
            raise Exception("call Decrypt failed, ", e.message)
    else:
        raw_data_with_sign = b64_crypted_data

    logging.debug("Data after decrypt: %s" %raw_data_with_sign)
    print("Data after decrypt: %s" %raw_data_with_sign)
    signed_data = json.loads(raw_data_with_sign)

    logging.debug("dataBase64: [%s]" %signed_data["Data"])
    logging.debug("signBase64: [%s]" %signed_data["Signature"])
    print("dataBase64: [%s]" %signed_data["Data"])
    print("signBase64: [%s]" %signed_data["Signature"])

    raw_data = b64decode(signed_data["Data"])
    raw_signature = b64decode(signed_data["Signature"])

    ## Verify
    if IS_SIGN:
        verified = crypto_lib.verify(raw_data, raw_signature)
        if verified:
            return raw_data
        else:
            raise Exception("verify failed.")
    return raw_data

def sign_and_encrypt(data, crypto_lib):
    """Sign and encrypt date with ICryptoLib instance

    :param data: data to be signed and encrypted
    :param crypto_lib: crypto instance that impliments sign and encrypt
    :Returns: signed and encrypted cipher
    """
    ## Sign
    signature = ""
    if IS_SIGN:
        logging.debug("Sign data...")
        try:
            signature = crypto_lib.sign(data)
        except Exception, e:
            raise Exception("call sign failed, %s" %e.message)

    ## To base64
    data_b64 = b64encode(data)
    sign_b64 = b64encode(signature)
    logging.debug("signed base64: %s" %sign_b64)
    logging.debug("data base64: %s" %data_b64)

    signed_data = SignedData(data_b64, sign_b64)
    data = json.dumps(signed_data.__dict__)
    print "before crypt: %s" %data
    out = ""
    if IS_ENCRYPT:
        try:
            out = crypto_lib.encrypt(data)
        except Exception, e:
            logging.error("Encrypt error: %s" %e.message)
            raise Exception("call encrypt failed, %s" %e.message)
    else:
        out = data
    print "sign_and_encrypt result: %s" %b64encode(out)
    return b64encode(out)
