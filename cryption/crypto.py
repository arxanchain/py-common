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
import ctypes
import os
from base64 import b64encode, b64decode

CUR_PATH = os.path.dirname(__file__)
UTILS_LIB_PATH = "utils/utils.so"
DECRYPT_MODE = "2"
ENCRYPT_MODE = "1"

def decrypt_and_verify(cipher, apikey, cert_path):
    """Decrypt and verify date with executable
    generated from crypto tools in sdk-go-common

    :param cipher: data to be decrypted and verified
    :param apikey: api key generated from server
    :param cert_path: private key file and cert file
    :Returns: decoded and verified message
    """
    if len(cipher) <= 0:
        return ""
    
    params = [
        DECRYPT_MODE,
        apikey,
        cert_path,
        "{}".format(cipher)
    ]
    path = os.path.join(CUR_PATH, UTILS_LIB_PATH)
    encrypt = ctypes.CDLL(path).encrypt
    encrypt.argtypes = [ctypes.c_char_p] * 4
    encrypt.restype = ctypes.c_char_p
    result = encrypt(*params)
    if result is None or len(result)<=0:
        raise Exception("failed to run decrypt, result empty")

    return result.strip()

def sign_and_encrypt(plain_text, apikey, cert_path):
    """Sign and encrypt date with executable
    generated from crypto tools in sdk-go-common

    :param plain_text: plain text to be signed and encrypted
    :param apikey: api key generated from server
    :param cert_path: private key file and cert file
    :Returns: signed and encrypted message
    """
    if len(plain_text) <= 0:
        return ""

    params = [
        ENCRYPT_MODE,
        apikey,
        cert_path,
        "{}".format(b64encode(plain_text))
    ]
    path = os.path.join(CUR_PATH, UTILS_LIB_PATH)
    encrypt = ctypes.CDLL(path).encrypt
    encrypt.argtypes = [ctypes.c_char_p] * 4
    encrypt.restype = ctypes.c_char_p
    result = encrypt(*params)
    if result is None or len(result)<=0:
        raise Exception("failed to run decrypt, result empty")

    return result

def sign(plain_text, secret_key, did, nonce):
    """ Sign date with executable generated
        from sign tools in sdk-go-common

    :param plain_text: plain text to be signed and encrypted
    :param secret_key: secret key generated from server
    :param did: did
    :param nonce: nonce
    :Returns: signed message
    """
    if len(plain_text) <= 0:
        return ""
    
    params = [
        secret_key,
        nonce,
        did,
        "{}".format(b64encode(plain_text))
    ]
    path = os.path.join(CUR_PATH, UTILS_LIB_PATH)
    sign = ctypes.CDLL(path).sign
    sign.argtypes = [ctypes.c_char_p] * 4
    sign.restype = ctypes.c_char_p
    result = sign(*params)
    if result is None or len(result)<=0:
        raise Exception("failed to run sign, result empty")

    return result

