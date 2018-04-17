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

class Config(object):
    """A cert store implementation. """

    def __init__(self, apikey, cert_path, ip_addr="", enable_crypto=True):
        self.__apikey = apikey
        self.__cert_path = cert_path
        self.__ip_addr = ip_addr
        self.__enable_crypto = enable_crypto
        self.__url = ""

    def set_body(self, body):
        """Set body encdypted.

        :param body: body dictionary or string to be encrypted
        :Returns: crypted cipher text
        """
        if not self.__enable_crypto:
            return json.dumps(body)

        if isinstance(body, dict):
            body = json.dumps(body)

        return sign_and_encrypt(body, self.__apikey, self.__cert_path)

    def get_ip(self):
        """ Get ip addr. """
        return self.__ip_addr

    def set_url(self, url=""):
        """ Set url. """
        if len(url) <= 0:
            self.__url = self.__ip_addr
        else:
            self.__url = url


    def get_apikey(self):
        """ Get api key. """
        return self.__apikey


    def set_sign_body(self, body, secret_key, did, nonce):
        """Set body signed.
    
        :param body: body dictionary to be encrypted
        :param secret_key: secret key generated from server
        :param did: did
        :param nonce: nonce
        :Returns: crypted cipher text
        """
        return sign(json.dumps(body), secret_key, did, nonce)


    def require_ok(self, resp):
        """Validate response.
    
        :param resp: response
        :param enable_crypto: switch that enables encrypt/decrypt function
        :Returns: plain response body, if enable_crypto is True, then return
        dict will have field 'ClientErrMsg', otherwise not
        """
        result = {}
        if resp.status_code != STATUS_CODE_OK:
            logging.error("Status code: {}, Client Error, body: {}".format(
                    resp.status_code,
                    resp.text))
    
        if len(resp.text) <= 0:
            logging.error("Respond error: Body empty")
    
            if self.__enable_crypto:
                result["ClientErrMsg"] = "Respond error: Body empty"
            return result
    
        # Decrypt and verify
        if self.__enable_crypto:
            try:
                plain_body = ""
                plain_body = decrypt_and_verify(
                        resp.text,
                        self.__apikey,
                        self.__cert_path
                        )
                result.update(json.loads(plain_body))
                result["ClientErrMsg"] = ""
            except Exception:
                logging.error(
                        "cannot decrypt_and_verify response body: %s",
                        resp.text
                        )
                result["ClientErrMsg"] = resp.text
            finally:
                return result
    
        result.update(json.loads(resp.text))
        return result

    def do_request(self, req_params, request_func):
        """ Do requst with the given request function.
            And calculate total time used.
    
        :param req_params: request parameters, including header, body
        :param request_func: request function to be used
        :Returns: time duration, response
        """
    
        if len(self.__cert_path) <= 0:
            self.__cert_path = CERT_PATH
        if len(self.__apikey) <= 0:
            self.__apikey = APIKEY
        beg_time = time.time()
    
        if request_func == self.do_get and "body" in req_params:
            del req_params["body"]
        else:
            req_body = self.set_body(req_params["body"])
            req_params["body"] = req_body
    
        resp = self.require_ok(
                request_func(**req_params)
                )
    
        time_dur = time.time() - beg_time
    
        return time_dur, resp

    def do_prepare(self, prepared):
        """ Do requst with the given request object.
            And calculate total time used.
    
        :param prepared: requests.PreparedRequest object used
        to do the request
        :Returns: time duration, response
        """
        prepared.body = self.set_body(prepared.body)
        prepared.headers['Content-Length'] = str(len(prepared.body))
        beg_time = time.time()
        result = requests.session().send(prepared)
        resp = self.require_ok(result)
        time_dur = time.time() - beg_time
    
        return time_dur, resp


    def do_get(self, headers):
        """Start GET request.
    
        :param headers: headers dictionary
        :Returns: response
        """
        return requests.get(self.__url, headers=headers)
    
    
    def do_post(self, headers, body, files=None):
        """Start POST request.
    
        :param header: header dictionary
        :param body: body dictionary
        :Returns: response
        """
        return requests.post(
                self.__url,
                headers=headers,
                data=body,
                files=files
                )
    
    
    def do_put(self, headers, body):
        """Start POST request.
    
        :param url: URL that request is sent to
        :param header: header dictionary
        :param body: body dictionary
        :Returns: response
        """
        return requests.put(
                self.__url,
                headers=headers,
                data=body
                )
    
    
