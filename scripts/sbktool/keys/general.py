"""General key class."""

import sys

class KeyClass(object):
    def emit_private(self, indent="\t"):
        encoded = self.get_private_key_bytearray()
        for count, b in enumerate(encoded):
            if count % 16 == 0:
                if count != 0:
                    print("\" \\")
                print(indent + "\"", end='')
            print("\\x{:02x}".format(b), end='')
        print("\"" + "\n")