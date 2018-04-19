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
import os
import timeout_decorator
from base64 import b64encode, b64decode

MAX_TIMEOUT = 3
CRYPTO_BIN_PATH = "./utils/crypto-util"
SIGN_BIN_PATH = "./utils/sign-util"
CUR_PATH = os.path.dirname(__file__)
MODE_CRYPTO = "crypt"
MODE_SIGN = "sign"

@timeout_decorator.timeout(MAX_TIMEOUT, timeout_exception=Exception)
def run_cmd(params, mode):
    params_str = " ".join(map(lambda x: "-{0} {1}".format(x, params[x]), params))
    bin_path = ""
    if mode == "crypt":
        bin_path = os.path.join(CUR_PATH, CRYPTO_BIN_PATH)
    elif mode == "sign":
        bin_path = os.path.join(CUR_PATH, SIGN_BIN_PATH)
    else:
        raise Exception("%s, unsupported mode" %mode)

    cmd = " ".join([bin_path, params_str])
    result = os.popen(cmd).read()
    if result.startswith("[ERROR]"):
        raise Exception("{}, failed to run cmd: {}".format(result, cmd))

    return result.strip()
            
def decrypt_and_verify(cipher_b64, apikey, cert_path):
    """Decrypt and verify date with executable
    generated from crypto tools in sdk-go-common

    :param cipher_b64: base64 formatted data to be decrypted and verified
    :param apikey: api key generated from server
    :param cert_path: private key file and cert file
    :Returns: decoded and verified message
    """
    params = {
        "mode": "2",
        "apikey": apikey,
        "path": cert_path,
        "data": cipher_b64
    }
    return run_cmd(params, MODE_CRYPTO)

def sign_and_encrypt(plain_text, apikey, cert_path):
    """Sign and encrypt date with executable
    generated from crypto tools in sdk-go-common

    :param plain_text: plain text to be signed and encrypted
    :param apikey: api key generated from server
    :param cert_path: private key file and cert file
    :Returns: signed and encrypted message
    """
    params = {
        "mode": "1",
        "apikey": apikey,
        "path": cert_path,
        "data": "'{}'".format(b64encode(plain_text))
    }
    result = run_cmd(params, MODE_CRYPTO)
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
    params = {
        "key": secret_key,
        "nonce": nonce,
        "did": did,
        "data": "'{}'".format(b64encode(plain_text))
    }
    signed_data = run_cmd(params, MODE_SIGN)

    return signed_data

