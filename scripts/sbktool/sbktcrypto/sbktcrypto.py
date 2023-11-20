# copyright 2023 LaczenJMS
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

"""sbktool crypto class."""

import sys
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import ECC
from Crypto.IO import PEM

RANDOM_KEY_SIZE = 32

class SBKTCryptoUsageError(Exception):
    pass

class SBKTCrypto(object):
    """
    Wrapper around private keys.
    """

    def __init__(self, key, type):
        self.key = key
        self.type = type

    def _unsupported(self, name):
        raise SBKTCryptoUsageError("Operation {} unsupported on {}".format(name, self.type))

    @staticmethod
    def generate(type):
        if type == 'rpk':
            pk = get_random_bytes(RANDOM_KEY_SIZE)
        elif type == 'p256':
            pk = ECC.generate(curve='P-256')
        else:
            return None

        return SBKTCrypto(pk, type)

    def export_private(self, path, passwd=None):
        if self.type == 'rpk':
            pem = PEM.encode(self.key, "PRIVATE KEY", passphrase=passwd)
        elif self.type == 'p256':
            pem = self.key.export_key(format='PEM', passphrase=passwd,
                                      protection='PBKDF2WithHMAC-SHA1AndAES128-CBC')
        else:
            return

        with open(path, 'w') as f:
            f.write(pem)

    def emit(self, indent="\t"):
        if not self.type in ('rpk', 'p256'):
            self._unsupported(emit)
            return
        if self.type == 'rpk':
            keydata = self.key
            print("#define SBK_PRIVATE_KEY \\")
        if self.type == 'p256':
            keydata = self.key.public_key().export_key(format='raw')
            # drop the first element as this is a indication of the key type
            # (public key raw data: x04)
            keydata = keydata[1:]
            print("#define SBK_PUBLIC_KEY \\")

        for count, b in enumerate(keydata):
            if count % 16 == 0:
                if count != 0:
                    print("\" \\")
                print(indent + "\"", end='')
            print("\\x{:02x}".format(b), end='')
        print("\"" + "\n")
