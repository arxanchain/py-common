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
ROOT_PATH = os.path.join(
    os.path.dirname(__file__),
    "../.."
    )
from cryption.crypto import sign_and_encrypt, decrypt_and_verify, sign

CERT_PATH = os.path.join(ROOT_PATH, "cryption/ecc/certs")
STATUS_CODE_OK = 200

APIKEY = "pWEzB4yMM1518346407"

def set_body(body, apikey, cert_path):
    """Set body encdypted.

    :param body: body dictionary or string to be encrypted
    :param apikey: api key generated from server
    :param cert_path: path of private key file and cert file
    :Returns: crypted cipher text
    """
    if isinstance(body, dict):
        body = json.dumps(body)

    return sign_and_encrypt(body, apikey, cert_path)

def set_sign_body(body, secret_key, did, nonce, apikey, cert_path):
    """Set body signed.

    :param body: body dictionary to be encrypted
    :param secret_key: secret key generated from server
    :param did: did
    :param nonce: nonce
    :Returns: crypted cipher text
    """
    return sign(json.dumps(body), secret_key, did, nonce)

def do_get(url, headers):
    """Start GET request.

    :param url: URL that request is sent to
    :param headers: headers dictionary
    :Returns: response
    """
    return requests.get(url, headers=headers)

def do_post(url, headers, body, files=None):
    """Start POST request.

    :param url: URL that request is sent to
    :param header: header dictionary
    :param body: body dictionary
    :Returns: response
    """
    return requests.post(
            url,
            headers=headers,
            data=body,
            files=files
            )

def do_put(url, headers, body):
    """Start POST request.

    :param url: URL that request is sent to
    :param header: header dictionary
    :param body: body dictionary
    :Returns: response
    """
    return requests.put(url, headers=headers, data=body)

def require_ok(resp, apikey, cert_path, encrypt_switch=True):
    """Validate response.

    :param resp: response
    :param apikey: the api key authorized by the server
    :param cert_path: path of private key file and cert file
    :param encrypt_switch: switch that enables encrypt/decrypt function
    :Returns: plain response body
    """
    result = {}
    client_err_msg = ""
    if resp.status_code != STATUS_CODE_OK:
        logging.error("Status code: {}, Client Error, body: {}".format(
                resp.status_code,
                resp.text))

    if len(resp.text) <= 0:
        result["ClientErrMsg"] = "Respond error: Body empty"
        logging.error(result["ClientErrMsg"])
        return result

    ## Decrypt and verify
    plain_body = ""
    if encrypt_switch:
        try:
            plain_body = decrypt_and_verify(
                    resp.text,
                    apikey,
                    cert_path
                    )
            result.update(json.loads(plain_body))
        except Exception:
            logging.error("cannot decrypt_and_verify response body: {}".format(resp.text))
            result["ClientErrMsg"] = resp.text
        finally:
            return result

    result.update(json.loads(resp.text))

    return result

def do_request(req_params, apikey, cert_path, request_func, encrypt_switch=True):
    """ Do requst with the given request function.
        And calculate total time used.

    :param req_params: request parameters, including header, body, url
    :param apikey: the api key authorized by the server
    :param cert_path: path of private key file and cert file
    :param request_func: request function to be used
    :param encrypt_switch: switch that enables encrypt/decrypt function
    :Returns: time duration, response
    """

    if len(cert_path) <= 0:
        cert_path = CERT_PATH
    if len(apikey) <= 0:
        apikey = APIKEY
    beg_time = time.time()

    if request_func == do_get and "body" in req_params:
        del req_params["body"]
    else:
        req_body = ""
        if encrypt_switch:
            req_body = set_body(
                    req_params["body"],
                    apikey,
                    cert_path
                    )
        else:
            req_body = json.dumps(req_params["body"])
        req_params["body"] = req_body

    resp = require_ok(
            request_func(**req_params),
            apikey,
            cert_path,
            encrypt_switch
            )

    time_dur = time.time() - beg_time

    return time_dur, resp

def do_prepare(prepared, apikey, cert_path):
    """ Do requst with the given request object.
        And calculate total time used.

    :param requests.PreparedRequest object used to do the request
    :param apikey: the api key authorized by the server
    :param cert_path: path of private key file and cert file
    :Returns: time duration, response
    """
    prepared.body = set_body(prepared.body, apikey, cert_path)
    prepared.headers['Content-Length'] = str(len(prepared.body))
    beg_time = time.time()
    resp = require_ok(
            requests.session().send(prepared),
            apikey,
            cert_path
            )
    time_dur = time.time() - beg_time

    return time_dur, resp

