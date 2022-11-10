# Copyright 2019 LaczenJMS
# Copyright 2018 Nordic Semiconductor ASA
# Copyright 2017 Linaro Limited
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
Image signing and management.
"""

from . import version as versmod
from intelhex import IntelHex
import binascii
import hashlib
import struct
import os.path
import sbktool.keys as keys
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

BYTE_ALIGNMENT = 8 # Output hex file is aligned to BYTE_ALIGNMENT
MIN_HDRSIZE = 512
SBK_IMAGE_META_OPENING_INFO = 0x7546,
SBK_IMAGE_META_SIGNATURE_INFO = 0xC918,
SBK_IMAGE_META_IMAGE_INFO = 0xC67C,
SBK_IMAGE_META_IMAGE_DEPENDENCY_INFO = 0x2768,
SBK_IMAGE_META_IMAGE_DEVICE_INFO = 0xBA54,
SBK_IMAGE_META_CLOSING_INFO = 0xA8AC,
INTEL_HEX_EXT = "hex"
STRUCT_ENDIAN_DICT = {
        'little': '<',
        'big':    '>'
}

class Image():
    def __init__(self, hdrsize = None, load_address = None, dest_slot = None,
                 version = 0, endian='little', type = 'image',
                 dep_slot = None, dep_min_ver = None, dep_max_ver = None):
        self.hdrsize = hdrsize
        self.load_address = load_address
        self.dest_slot = dest_slot
        self.version = version or versmod.decode_version("0")
        self.endian = endian
        self.payload = []
        self.size = 0
        self.dep_slot = dep_slot or None
        self.dep_min_ver = dependency[2] or versmod.decode_version("0")
        self.dep_max_ver = dependency[3] or versmod.decode_version("255.255.65535")

    def __repr__(self):
        return "<hdrsize={}, load_address={}, dest_slot={}, \
                Image version={}, endian={}, type={} format={}, \
                payloadlen=0x{:x}>".format(
                    self.hdrsize,
                    self.load_address,
                    self.dest_slot,
                    self.version,
                    self.endian,
                    self.type,
                    self.__class__.__name__,
                    len(self.payload))

    def load(self, path):
        """Load an image from a given file"""
        ext = os.path.splitext(path)[1][1:].lower()

        if ext != INTEL_HEX_EXT:
            raise Exception("Only hex input file supported")
        ih = IntelHex(path)
        self.payload = ih.tobinarray()

        # Padding the payload to aligned size
        if (len(self.payload) % BYTE_ALIGNMENT) != 0:
            padding = BYTE_ALIGNMENT - len(self.payload) % BYTE_ALIGNMENT
            self.payload = bytes(self.payload) + (b'\xff' * padding)

        if self.hdrsize == None:
            self.payload = (b'\x00' * MIN_HDRSIZE) + bytes(self.payload)
            self.hdrsize = MIN_HDRSIZE
            self.run_address = ih.minaddr()
        else:
            self.run_address = ih.minaddr() + self.hdrsize

        if self.dest_slot == None:
            self.dest_slot = 0;

        if self.load_address == None:
            self.load_address = 0;

        self.size = len(self.payload) - self.hdrsize;

        self.check()

    def save(self, path):
        """Save an image from a given file"""
        ext = os.path.splitext(path)[1][1:].lower()

        if ext != INTEL_HEX_EXT:
            raise Exception("Only hex input file supported")

        h = IntelHex()
        h.frombytes(bytes=self.payload, offset=self.load_address)
        h.tofile(path, 'hex')

    def check(self):
        """Perform some sanity checking of the image."""
        # Check that image starts with header of all 0x00.
        if any(v != 0x00 for v in self.payload[0:self.hdrsize]):
            raise Exception("Header size provided, but image does not \
            start with 0x00")


    def create(self, signkey, encrkey):

        # Calculate the image hash.
        sha = hashlib.sha256()
        sha.update(self.payload[self.hdrsize:])
        hash = sha.digest()
        epubk = bytearray(len(signkey.get_public_key_bytearray()))
        ehash = hash

        if encrkey is not None:

            # Generate new encryption key
            tempkey = keys.EC256P1.generate()
            epubk = tempkey.get_public_key_bytearray()

            # Generate shared secret
            shared_secret = tempkey.gen_shared_secret(encrkey._get_public())

            # Key Derivation function: KDF1
            sha = hashlib.sha256()
            sha.update(shared_secret)
            sha.update(b'\x00\x00\x00\x00')
            plainkey = sha.digest()[:16]

            # Encrypt
            nonce = sha.digest()[16:]
            cipher = Cipher(algorithms.AES(plainkey), modes.CTR(nonce),
                            backend=default_backend())
            encryptor = cipher.encryptor()
            msg = bytes(self.payload[self.hdrsize:])

            enc = encryptor.update(msg) + encryptor.finalize()
            self.payload = bytearray(self.payload)
            self.payload[self.hdrsize:] = enc

            # Calculate the encrypted image hash.
            sha = hashlib.sha256()
            sha.update(self.payload[self.hdrsize:])
            ehash = sha.digest()

        self.add_header(hash, epubk, ehash, signkey)

    def add_header(self, hash, epubk, ehash, signkey):
        """Install the image header."""
        # info_hdr struct
        e = STRUCT_ENDIAN_DICT[self.endian]
        info_hdr_fmt = (e +
            # struct info_hdr
            'H' + #uint16_t tag;
            'H' #uint16_t payloadsize;
        )

        # start from the back and keep adding items to the front;
        info_hdr = struct.pack(info_hdr_fmt, SBK_IMAGE_META_CLOSING_INFO, 0);
        hdr = info_hdr;

        dep_fmt = (e +
            # dependency info {
            'I' +   # Image slot
            'BBH' + # Image dep min
            'BBH'   # Image dep max
            ) #}
        dep = struct.pack(dep_fmt,
            self.dest_slot,
            0,0,0,
            self.version.major or 0,
            self.version.minor or 0,
            self.version.revision or 0
            )
        info_hdr = struct.pack(info_hdr_fmt,
            SBK_IMAGE_META_IMAGE_DEPENDENCY_INFO,
            len(dep));
        hdr = info_hdr + dep + hdr;

        filler = bytearray(self.hdr_size - len(hdr) - 4);
        info_hdr = struct.pack(info_hdr_fmt,
            SBK_IMAGE_META_OPENING_INFO,
            len(filler));
        hdr = filler + info_hdr + hdr;

        sha = hashlib.sha256()
        sha.update(hdr)
        hdr_hash = sha.digest()
        hdr_signature = signkey.sign_prehashed(hdr_hash)

        self.payload = bytearray(self.payload)
        self.payload[0:len(hdr)] = hdr