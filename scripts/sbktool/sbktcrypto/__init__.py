# copyright 2019 LaczenJMS
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Cryptographic key management for sbktool.
"""

from Crypto.IO import PEM
from Crypto.PublicKey import ECC

from .sbktcrypto import SBKTCrypto

class PasswordRequired(Exception):
    """Raised to indicate that the key is password protected, but a
    password was not specified."""
    pass

def load(path, passwd=None):
    """Try loading a key from the given path.  Returns None if the password wasn't specified."""
    with open(path, 'r') as f:
        raw_pem = f.read()
    try:
        pk = ECC.import_key(raw_pem, passphrase = passwd)
        return SBKTCrypto(pk, 'p256')
    except:
        try:
            [pk, marker, encrypted] = PEM.decode(raw_pem, passphrase = passwd)
            return SBKTCrypto(pk, 'rpk')
        except:
            return None
