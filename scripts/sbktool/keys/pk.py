"""
private key management
"""

from Crypto.Random import get_random_bytes
from Crypto.IO import PEM
from .general import KeyClass

KEY_SIZE = 32

class PKUsageError(Exception):
    pass

class PK(KeyClass):
    """
    Wrapper around an private key.
    """

    def __init__(self, key):
        self.key = key

    @staticmethod
    def generate():
        pk = get_random_bytes(KEY_SIZE)

        return PK(pk)

    def get_private_key_size(self):
        return KEY_SIZE

    def get_private_key_bytearray(self):
        return self.key

    def export_private(self, path, passwd=None):
        """Write the private key to the given file, protecting it with the optional password."""
        pem = PEM.encode(self.key, "PRIVATE_KEY", passphrase=passwd)
        with open(path, 'w') as f:
            f.write(pem)
        print("Done export")