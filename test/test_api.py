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
import json
import sys
import httpretty
import mock
import requests
ROOTPATH = os.path.join(
    os.path.dirname(__file__),
    "../"
    )
sys.path.append(ROOTPATH)
from rest.api.api import set_body, set_sign_body, do_get, do_post, do_put, require_ok, do_request, do_prepare

class Response(object):
    def __init__(self, status_code, text):
        self.status_code = status_code
        self.text = text

# Create your tests here.
class ApiTest(unittest.TestCase):
    """Rest api test. """
    def setUp(self):
        # Every test needs access to the request factory.
        self.header = {}
        self.url = "http://127.0.0.1"
        self.status_not_found = 404
        self.resp_not_found = "404 Not Found"
        self.nonce = "nonce"
        self.status_ok = 200
        self.apikey = "pWEzB4yMM1518346407"
        self.request = {
            "payload": "", 
            "signature": {
                "nonce": self.nonce,
                "created": "1519726752",
                "signature_value": "7puQKXBJ5PJZei121dqNN4JDbFG4Xw3p6hsxLkAbHV/6lD5uVwF4JX7rdGEJrqLESMTxW6Ddx3lBAe70fTtlDg==",
                "creator": "did:axn:2ef06aa4-05bb-4728-8882-343d42faeb8f"
                }
            }
        self.resp = {"ErrCode":0,"ErrMessage":"","Method":"","Payload":""}
        self.uri = "http://127.0.0.1:9143/v1"
        self.cert_path = os.path.join(
            os.path.dirname(__file__),
            "../cryption/ecc/certs"
            )
        ## response:
        ## {
        ##     "ErrCode": 0,
        ##     "ErrMessage": "",
        ##     "Method": "",
        ##     "Payload": "{\"code\":0,\"message\":\"\",\"id\":\"did:axn:769de30d-2170-453d-81ce-b8f566be1e7a#Organization\",\"endpoint\":\"d9f0f47af158609ef97399a7c38cf7885a0c32da5b4145706361ff6c7a3520e3\",\"key_pair\":{\"private_key\":\"QU9T6vN3g4q3MLAUL8YJxK90bBWvOw+QW4zONXSR1acNCG8tblPVcK/jzKFA/QRyQ+4lv3KN5JfMJRzek05NNw==\",\"public_key\":\"DQhvLW5T1XCv48yhQP0EckPuJb9yjeSXzCUc3pNOTTc=\"},\"created\":1519702836,\"coin_id\":\"\",\"transaction_ids\":[\"1e0edec693c1a22656d5db23d66b91ab9df0dcefef025dd293228e324fc8de4c\",\"bf6e2be1ab2fb0b66be2ee67732c885853524416e4904b6124cc9c5d2b1736d0\"]}"
        ## }
        self.cipher = "BLAA7vB31SPsbQf18zb3Y80NeHfLQk00QZmLKU2T0r/z45xPKelbqvM9C15hKLWaJwlNSLdmjwnVhSeaaYWG/ao80rRHAvEA9nkw1WdOcfC0fAwF4NdHMwz2wuAw+QL5IYAmHOu2fXoiubF6Ay1Hdw0oN6W+RNa+1zFHD9SVdengCT5V7q0mcgUXbmd4YsKHfGG5Pyd17D38E6OIDdUy6skVk2xNSRKehmQ1AS4g2+nMbJS+XvPZzm26WCzT+0zhec7wE8yqzpXR9F45rHZaz5WYcxCTddyPJ31K+wrc7X/Y4UHhjuBuVeU5QJQagoJNuYqeWS3luwN+TVZpBI8sByXc5C+M0vNdJPiiuzD4DUrqusqbso6+J7L4YVF6rgg97q7iuUKQvnmQzsktrdofugbKm6xxdfqp2oiLOmCWf43K+05/wxv1d9iMyBBDy37OGHkwkSzXDtf9sRysW9lKb9rk+9PGdnDnQvmIUBlUYGLue0LcYxqc3dZIAvCvWFrK3FmvV3K6+3reAHx5+Ym7yuQPu721llgaJkhoVdnUJpBCZhxj4oe/t249WnI3t565e6AsFB13IrFaRQd62b+HTAYKHmIRg7aV9VbZHWUEg212R0UWPm5g2ghZ1AcIDBx2zDXDSPSonweNS3OWCEQ+KRTCyo2E3U8Fi0Ob2WIr6WKUiwPubKm101rWfTxKNqqT6uEVW0eVW1syfz8mHztnyZcHU8cfZ7xXNCr38IRpw6+1iUlOCDeWQYn8F5xchmRJ7A8LDf9OTmxZZ+tdj4jjLDBm1K+iI83/QqYk4tVCYBxYrwtb6uWqldaBjRP+5MXuIdkA785nB5kRuzwhF1jxdZJoDIIWDQH+1t1tZN3Z3WCACRRwVGnnK5UgZOrp7Qs/+FNh4C64yiG7X+R+BmbfM1N0frbQb/qK9d1HTi2pAVeGJ49c15EzeVJUuEdRgDUyNRtwYTxioVAZrBOcis2EbcOg2vzzHmUHYE87N08Fm1zrm0dRauTKaghvN+6+uRgj6UF26tl4xsxE2PUQ5OIiVWSTbT8zWSuq9QIVpuEGDh2k42adGXFaz4En36e/OXUPgv1fMDpgDwQFq3KOoIl/U5ZIsyv+tIKNM8998MQpXrDbGoq6yKpt0dGPxC2sc+eeXqXhV0gumB0EhPBzOdJhfdqhn8uCMqS3khcbNkERk5FI+Yw9FDcLVSVfESMdAeZBTT27fDb/QpByQzNm2s6fC7WxKATBZbH+Y0vohxSv1RqXBsQRj8roHiQ+aarEk4R5aTDU2sPvLb3jzAFyPqvnM6hZChQ5i3gS50A1yvAPEwKzEB4vdzUtst1ADpCEpPoF24bgpeYtMELhXBqxgJJl7pPEy+UaDNVlJLXAwszVbhZoyAVVAAL+dxJajJ6N/E3VQKSwMet3DO4myBg="

        httpretty.enable()


    def tearDown(self):
        httpretty.disable()
        httpretty.reset()

    def test_do_get(self):
        httpretty.register_uri(
            httpretty.GET,
            self.uri,
            status=self.status_ok,
            body=json.dumps(self.resp)
            )
        result = do_get(self.uri, self.header)
        self.assertEqual(self.status_ok, result.status_code)
        content = json.loads(result.content)
        self.assertEqual(0, content["ErrCode"])

        httpretty.disable()
        httpretty.reset()

    def test_do_post(self):
        httpretty.register_uri(
            httpretty.POST,
            self.uri,
            status=self.status_ok,
            body=json.dumps(self.resp)
            )
        result = do_post(self.uri, self.header, self.request)
        content = json.loads(result.content)
        self.assertEqual(self.status_ok, result.status_code)
        self.assertEqual(0, content["ErrCode"])


    def test_do_put(self):
        httpretty.register_uri(
            httpretty.PUT,
            self.uri,
            status=self.status_ok,
            body=json.dumps(self.resp)
            )
        result = do_put(self.uri, self.header, self.request)
        content = json.loads(result.content)
        self.assertEqual(self.status_ok, result.status_code)
        self.assertEqual(0, content["ErrCode"])


    def test_do_request_succ(self):
        mock_do_post = mock.Mock(return_value=Response(self.status_ok, json.dumps(self.resp)))
        mock_run_cmd = mock.Mock(side_effect=[self.cipher, json.dumps(self.resp)])
        request_func = do_post
        with mock.patch('cryption.crypto.run_cmd', mock_run_cmd):
            with mock.patch('requests.post', mock_do_post):
                _, result = do_request(
                    {
                        "headers": self.header,
                        "body": self.request,
                        "url": self.uri
                        },
                    self.apikey,
                    self.cert_path,
                    request_func
                    )

                self.assertEqual(0, result["ErrCode"])

    def test_do_request_fail(self):
        mock_do_post = mock.Mock(return_value=Response(self.status_not_found, self.resp_not_found))
        mock_run_cmd = mock.Mock(side_effect=[self.cipher, {}])
        request_func = do_post
        with mock.patch('cryption.crypto.run_cmd', mock_run_cmd):
            with mock.patch('requests.post', mock_do_post):
                _, result = do_request(
                    {
                        "headers": self.header,
                        "body": self.request,
                        "url": self.uri
                        },
                    self.apikey,
                    self.cert_path,
                    request_func
                    )

                self.assertEqual(self.resp_not_found, result["ClientErrMsg"])

    def test_do_prepare_succ(self):
        mock_send = mock.Mock(return_value=Response(self.status_ok, json.dumps(self.resp)))
        mock_run_cmd = mock.Mock(side_effect=[self.cipher, json.dumps(self.resp)])
        with mock.patch('cryption.crypto.run_cmd', mock_run_cmd):
            with mock.patch('requests.Session.send', mock_send):
                poeid_filepart = (
                        "",
                        "poe id",
                        )
                files = {"poe_id": poeid_filepart}

                _, result = do_prepare(
                        requests.Request(
                            "POST",
                            url=self.url,
                            files=files
                            ).prepare(),
                        self.apikey,
                        self.cert_path
                        )

                self.assertEqual(0, result["ErrCode"])

    def test_do_prepare_fail(self):
        mock_send = mock.Mock(return_value=Response(self.status_not_found, self.resp_not_found))
        mock_run_cmd = mock.Mock(side_effect=[self.cipher, {}])
        with mock.patch('cryption.crypto.run_cmd', mock_run_cmd):
            with mock.patch('requests.Session.send', mock_send):
                poeid_filepart = (
                        "",
                        "poe id",
                        )
                files = {
                        "poe_id": poeid_filepart,
                        }

                _, result = do_prepare(
                        requests.Request(
                            "POST",
                            url=self.url,
                            files=files
                            ).prepare(),
                        self.apikey,
                        self.cert_path
                        )

                self.assertEqual(self.resp_not_found, result["ClientErrMsg"])

    def test_do_request_with_no_encrypt_succ(self):
        mock_do_post = mock.Mock(return_value=Response(self.status_ok, json.dumps(self.resp)))
        request_func = do_post
        with mock.patch('requests.post', mock_do_post):
            _, result = do_request(
                {
                    "headers": self.header,
                    "body": self.request,
                    "url": self.uri,
                    },
                self.apikey,
                self.cert_path,
                request_func,
                False
                )

            self.assertEqual(0, result["ErrCode"])