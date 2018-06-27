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
import copy
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
CODE_SERVER_RESP_INVALID = 10000
CODE_DECRYPT_FAILED = 10001
MSG_SERVER_RESP_INVALID = "client error: server response invalid"
MSG_DECRYPT_FAILED = "client error: decrypt and verify failed"
RESP_DICT = {
        "ErrCode":0,
        "ErrMessage":"",
        "Method":"",
        "Payload":""
        }


class Client(object):
    """A client implementation. """

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

        return sign_and_encrypt(
                body, 
                self.__apikey,
                self.__cert_path
                )

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
        return sign(
                json.dumps(body),
                secret_key,
                did,
                nonce
                )

    def require_ok(self, resp):
        """Validate response.
    
        :param resp: response
        :Returns: plain response body. If failing to decrypt
        the json, then will put client error message and error
        code into "ErrMessage" field, and put client error code(
        like 100XX) into "ErrCode" field
        """
        result = RESP_DICT
        if resp.status_code != STATUS_CODE_OK:
            logging.error("Status code: {}, Client Error, body: {}".format(
                    resp.status_code,
                    resp.text))
    
        if len(resp.text) <= 0:
            logging.error("Respond error: Body empty")
            result["ErrCode"] = CODE_SERVER_RESP_INVALID
            result["ErrMessage"] = MSG_SERVER_RESP_INVALID

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
            except Exception:
                logging.error(
                        "cannot decrypt_and_verify response body: %s",
                        resp.text
                        )
                result["ErrCode"] = CODE_DECRYPT_FAILED
                result["ErrMessage"] = MSG_DECRYPT_FAILED
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
    
        resp = self.require_ok(request_func(**req_params))
    
        time_dur = time.time() - beg_time
    
        return time_dur, copy.deepcopy(resp)

    def do_prepare(self, prepared):
        """ Do requst with the given request object.
            And calculate total time used.
    
        :param prepared: requests.PreparedRequest object used
        to do the request
        :Returns: time duration, response
        """
        if self.__enable_crypto:
            prepared.body = self.set_body(prepared.body)
            prepared.headers['Content-Length'] = str(len(prepared.body))
        beg_time = time.time()
        result = requests.session().send(prepared)
        resp = self.require_ok(result)
        time_dur = time.time() - beg_time
    
        return time_dur, resp

    def do_get(self, url, headers):
        """Start GET request.
    
        :param headers: headers dictionary
        :param url: url string
        :Returns: response
        """
        return requests.get(
                url=url,
                headers=headers
                )
    
    def do_post(self, url, headers, body, files=None):
        """Start POST request.
    
        :param header: header dictionary
        :param url: url string
        :param body: body dictionary
        :param files: files to post
        :Returns: response
        """
        return requests.post(
                url=url,
                headers=headers,
                data=body,
                files=files
                )
    
    def do_put(self, url, headers, body):
        """Start POST request.
    
        :param headers: header dictionary
        :param url: url string
        :param body: body dictionary
        :Returns: response
        """
        return requests.put(
                url=url,
                headers=headers,
                data=body
                )

    def do_patch(self, url, headers, body):
        """Start PATCH request.
    
        :param headers: header dictionary
        :param url: url string
        :param body: body dictionary
        :Returns: response
        """
        return requests.patch(
                url=url,
                headers=headers,
                data=body
                )
    
    def do_delete(self, url, headers):
        """Start DELETE request.
    
        :param headers: header dictionary
        :param url: url string
        :Returns: response
        """
        return requests.delete(
                url=url,
                headers=headers,
                )
    
