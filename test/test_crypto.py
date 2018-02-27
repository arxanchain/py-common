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
import mock
import sys
ROOTPATH = os.path.join(
    os.path.dirname(__file__),
    "../"
    )
sys.path.append(ROOTPATH)
from cryption.crypto import sign_and_encrypt, decrypt_and_verify, sign, run_cmd

# Create your tests here.
class CryptTest(unittest.TestCase):
    """Crypto test. """
    def setUp(self):
        # Every test needs access to the request factory.
        self.error_code = "[ERROR]"
        self.cur_path = os.path.dirname(__file__)
        self.signed = "WxW9ZfF9hbc2tcRLweiojhR+ZgPwhFRLGqTD9M4vPH5o2qhvOTi0J9INu5ktqReGHE/5lwMntcxJLXdBRhRMAA=="
        self.failed_cert_store = "[ERROR]: Init cert store fail: stat ~/sdk-go-common/rest/api/client_certs/: no such file or directory"
        self.cipher = "eyJFcnJDb2RlIjowLCJFcnJNZXNzYWdlIjoiIiwiTWV0aG9kIjoiIiwiUGF5bG9hZCI6IntcImNvZGVcIjowLFwibWVzc2FnZVwiOlwiXCIsXCJpZFwiOlwiZGlkOmF4bjoxZjI4NDI1Ni0xOTEwLTQxN2UtOWU1Ny0zNzViNjNjNWNmMDRcIixcImVuZHBvaW50XCI6XCJiYjY4MTVjODUwMTZhNTI1ZjljNDA4MDQ5ZDA3YjdlZjY5ZWIyZmU3NzQ4YzVhM2UwNzg5MTBmMTQyNWJlNmM5XCIsXCJrZXlfcGFpclwiOntcInByaXZhdGVfa2V5XCI6XCJEbHB4anY2RzBGcFhJaTN5M21JVVNBZmVSSkFVZDJQYTkxQmQ0alM2OVo5dTdxWSszSGdadXEyM05IQU1nRGZ4N29heGo3ZkZ1c3VqZld1QnVHdUdkUT09XCIsXCJwdWJsaWNfa2V5XCI6XCJidTZtUHR4NEdicXR0elJ3RElBMzhlNkdzWSszeGJyTG8zMXJnYmhyaG5VPVwifSxcImNyZWF0ZWRcIjoxNTE5NzI2NzMxLFwiY29pbl9pZFwiOlwiXCIsXCJ0cmFuc2FjdGlvbl9pZHNcIjpbXCJhZjlkOGRlYjRkMjE3ZjYxYWZkYTM1OTBiYmU2ZmMyY2QwNjVjY2MyYWFlMTVhYWMwYTYxNDAzMTk4ZDFmM2JkXCIsXCJiNzljOGQwOTMxZGE2ZDlhODFkODNiN2FiM2I5MzBhZmZlMDFkYmFmYWY2NzdlOGQ5NmU3OTA1YWNmMTlmYmY3XCIsXCI4NGRiZWE4MDNiMGVmNjI5ZDUxY2YzNzY4NjI5OTBhOWI3ZjU5MmY1NWMwNjlkMWU4ZWFiOGZlZmIzNTQyMDE4XCJdfSJ9"
        self.cipher_body = {
            "ErrCode":0,
            "ErrMessage":"",
            "Method":"",
            "Payload":"{\"code\":0,\"message\":\"\",\"id\":\"did:axn:1f284256-1910-417e-9e57-375b63c5cf04\",\"endpoint\":\"bb6815c85016a525f9c408049d07b7ef69eb2fe7748c5a3e078910f1425be6c9\",\"key_pair\":{\"private_key\":\"Dlpxjv6G0FpXIi3y3mIUSAfeRJAUd2Pa91Bd4jS69Z9u7qY+3HgZuq23NHAMgDfx7oaxj7fFusujfWuBuGuGdQ==\",\"public_key\":\"bu6mPtx4GbqttzRwDIA38e6GsY+3xbrLo31rgbhrhnU=\"},\"created\":1519726731,\"coin_id\":\"\",\"transaction_ids\":[\"af9d8deb4d217f61afda3590bbe6fc2cd065ccc2aae15aac0a61403198d1f3bd\",\"b79c8d0931da6d9a81d83b7ab3b930affe01dbafaf677e8d96e7905acf19fbf7\",\"84dbea803b0ef629d51cf376862990a9b7f592f55c069d1e8eab8fefb3542018\"]}"
            }


    def tearDown(self):
        pass
    
    def test_sign_and_crypt_succ(self):
        """Test sign and crypt success. """
        run_cmd_sign_and_crypto = mock.Mock(return_value=self.cipher)
        apikey = "pWEzB4yMM1518346407"
        plain_text = "Hello world!"
        client_cert_path = os.path.join(
            self.cur_path,
            "../cryption/ecc/certs"
            )
        with mock.patch('cryption.crypto.run_cmd', run_cmd_sign_and_crypto):
            result = sign_and_encrypt(
                plain_text, 
                apikey, 
                client_cert_path
                )
            self.assertTrue(result)

    def test_sign_and_crypt_fail(self):
        """Test sign and crypt success. """
        run_cmd_sign_and_crypto = mock.Mock(return_value=self.failed_cert_store)
        apikey = "pWEzB4yMM1518346407"
        plain_text = "Hello world!"
        client_cert_path = os.path.join(
            self.cur_path,
            "../cryption/ecc/wrong_certs"
            )
        with mock.patch('cryption.crypto.run_cmd', run_cmd_sign_and_crypto):
            result = sign_and_encrypt(
                plain_text,
                apikey,
                client_cert_path
                )
            self.assertTrue(result.startswith(self.error_code))

    def test_decrypt_and_verify(self):
        """Test decrypt and verify. """
        run_cmd_decrypt_and_verify = mock.Mock(return_value=self.cipher_body)
        apikey = "pWEzB4yMM1518346407"
        client_cert_path = os.path.join(
            self.cur_path,
            "../cryption/ecc/certs"
            )
        with mock.patch('cryption.crypto.run_cmd', run_cmd_decrypt_and_verify):
            result = decrypt_and_verify(
                self.cipher, 
                apikey, 
                client_cert_path
                )
            self.assertEqual(0, result["ErrCode"])

    def test_sign(self):
        """Test sign procedure. """
        run_cmd_sign = mock.Mock(return_value=self.signed)
        plain_text = "Hello world!"
        did = "did:axn:93cec4c3-56d5-44ee-aa40-07c975f3e59a"
        nonce = "nonce"
        secretkeyB64 = "Dlpxjv6G0FpXIi3y3mIUSAfeRJAUd2Pa91Bd4jS69Z9u7qY+3HgZuq23NHAMgDfx7oaxj7fFusujfWuBuGuGdQ=="
        with mock.patch("cryption.crypto.run_cmd", run_cmd_sign):
            signed = sign(
                plain_text,
                secretkeyB64,
                did,
                nonce
                )
            self.assertFalse(signed.startswith(self.error_code))
            
