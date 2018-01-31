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

import time
import sys
import os
import json
import logging
import requests
ROOT_PATH = os.path.join(os.path.dirname(__file__),
        "../..")
from cryption.crypto import sign_and_encrypt, decrypt_and_verify, sign

CERT_PATH = os.path.join(ROOT_PATH, "cryption/ecc/certs")

APIKEY = "alice"

def set_body(body, apikey, cert_path):
    """Set body encdypted.

    :param body: body dictionary to be encrypted
    :param apikey: api key generated from server
    :param cert_path: path of private key file and cert file
    :Returns: crypted cipher text
    """
    return sign_and_encrypt(json.dumps(body), apikey, cert_path)

def set_sign_body(body, secret_key, did, nonce, apikey, cert_path):
    """Set body signed.

    :param body: body dictionary to be encrypted
    :param secret_key: secret key generated from server
    :param did: did
    :param nonce: nonce
    :Returns: crypted cipher text
    """
    return sign(json.dumps(body), secret_key, did, nonce, apikey, cert_path)

def do_get(url, headers):
    """Start GET request.

    :param url: URL that request is sent to
    :param headers: headers dictionary
    :Returns: response
    """
    return requests.get(url, headers=headers)

def do_post(url, headers, body):
    """Start POST request.

    :param url: URL that request is sent to
    :param header: header dictionary
    :param body: body dictionary
    :Returns: response
    """
    return requests.post(url, headers=headers, data=body)

def do_put(url, headers, body):
    """Start POST request.

    :param url: URL that request is sent to
    :param header: header dictionary
    :param body: body dictionary
    :Returns: response
    """
    return requests.put(url, headers=headers, data=body)

def require_ok(resp, apikey, cert_path):
    """Validate response.

    :param resp: response
    :param apikey: the api key authorized by the server
    :param cert_path: path of private key file and cert file
    :Returns: plain response body
    """
    if resp.status_code != requests.codes.ok:
        logging.error("Status code: %s, Client Error, body: %s" %(resp.status_code, resp.text))

    if len(resp.text) <= 0:
        logging.error("Respond error: Body empty")
        return None

    ## Decrypt and verify
    plain_body = decrypt_and_verify(resp.text, apikey, cert_path)
    return json.loads(plain_body)

def do_request(req_params, apikey, cert_path, request_func):
    """ Do requst with the given request function.
        And calculate total time used.

    :param req_params: request parameters, including header, body, url
    :param apikey: the api key authorized by the server
    :param cert_path: path of private key file and cert file
    :param request_func: request function to be used
    :Returns: time duration, response
    """
    if len(cert_path) <= 0:
        cert_path = CERT_PATH
    if len(apikey) <= 0:
        apikey = APIKEY
    beg_time = time.time()
    if "body" in req_params:
        req_body = set_body(req_params["body"], apikey, cert_path)
        req_params["body"] = req_body
    resp = require_ok(request_func(**req_params),
            apikey, cert_path)
    time_dur = time.time() - beg_time

    return time_dur, resp

## def do_sign_request(req_params, apikey, cert_path, sign_params, request_func):
def do_sign_request(req_params, sign_params, request_func):
    """ Do requst with the given request function.
        And calculate total time used.

    :param req_params: request parameters, including header, body, url
    :param sign_params: apikey, cert_path, sign parameters, including secret_key, nonce, did
    :Returns: time duration, response
    """
    if len(sign_params["cert_path"]) <= 0:
        sign_params["cert_path"] = CERT_PATH
    if len(sign_params["apikey"]) <= 0:
        sign_params["apikey"] = APIKEY
    beg_time = time.time()
    if "body" in req_params:
        sign_params["body"] = req_params["body"]
        req_body = set_sign_body(**sign_params)
        req_params["body"] = req_body
    resp = require_ok(request_func(**req_params),
            sign_params["apikey"], sign_params["cert_path"])
    time_dur = time.time() - beg_time

    return time_dur, resp

