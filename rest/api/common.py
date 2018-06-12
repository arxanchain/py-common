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

from cryption.crypto import sign
from base64 import b64decode

APIKEYHEADER = "API-Key"
FABIOROUTETAGHEADER = "Host"
ROUTETAG = "Route-Tag"
InvokeModeSync = "sync"
InvokeModeAsync = "async"

InvokeModeHeader = "Bc-Invoke-Mode"

def build_signature_body(creator, created, nonce, privateB64, payload):
    """Build signature body dict.

    :param creator: creator string to be signed
    :param created: created timestamp
    :param nonce: nonce
    :param privateB64: secret key used for ed25519 signature
    :param payload: payload dict to be signed
    :Returns: signed body dict
    """
    
    signature = sign(
            payload,
            privateB64,
            creator,
            nonce
            )
    result = {
            "creator": creator,
            "created": created,
            "nonce": nonce,
            "signature_value": signature
            }
    return result

def build_signature_body_base(creator, created, nonce, privateB64, payload):
    result = build_signature_body(creator, created, nonce, privateB64, payload)
    result["signature_value"] = b64decode(result["signature_value"])
    
    return result

