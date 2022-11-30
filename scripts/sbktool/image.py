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

BYTE_ALIGNMENT = 32 # Output hex file is aligned to BYTE_ALIGNMENT
MIN_HDRSIZE = 512
SBK_IMAGE_META_START_TAG = 0x8000
SBK_IMAGE_META_SEAL_TAG = 0x7FFF
SBK_IMAGE_STATE_BOOTABLE = 0x0080
SBK_IMAGE_STATE_ENCRYPTED = 0x8081
SBK_IMAGE_STATE_ZIPPED = 0x8082
SBK_IMAGE_HASH_TYPE_SHA256 = 0x0080
SBK_IMAGE_SEAL_TYPE_EDSA256 = 0x0080

INTEL_HEX_EXT = "hex"
STRUCT_ENDIAN_DICT = {
        'little': '<',
        'big':    '>'
}

class Image():
    def __init__(self, hdrsize = None, load_slot = None, download_slot = None,
                 version = 0, endian='little', type = 'image',
                 dep_slot = None, dep_min_ver = None, dep_max_ver = None):
        self.hdrsize = hdrsize
        self.load_slot = load_slot
        self.download_slot = download_slot
        self.version = version or versmod.decode_version("0")
        self.endian = endian
        self.payload = []
        self.size = 0
        self.dep_slot = dep_slot or None
        self.dep_min_ver = dep_min_ver or versmod.decode_version("0")
        self.dep_max_ver = dep_max_ver or versmod.decode_version("255.255.65535")
        self.meta_cnt = 0;

    def __repr__(self):
        return "<hdrsize={}, load_slot={}, dest_slot={}, \
                Image version={}, endian={}, type={} format={}, \
                payloadlen=0x{:x}>".format(
                    self.hdrsize,
                    self.load_slot,
                    self.download_slot,
                    self.version,
                    self.endian,
                    self.type,
                    self.__class__.__name__,
                    len(self.payload))

    def get_tag(self):
        self.meta_cnt += 1
        value = self.meta_cnt & 0x7FFF
        value ^= value >> 8
        value ^= value >> 4
        value &= 0xf
        if ((0x6996 >> value) & 1) == 0:
            return self.meta_cnt | 0x8000

        return self.meta_cnt

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

        if self.download_slot == None:
            self.download_slot = 0;

        if self.load_slot == None:
            self.load_slot = 0;

        self.size = len(self.payload) - self.hdrsize;

        self.check()

    def save(self, path):
        """Save an image from a given file"""
        ext = os.path.splitext(path)[1][1:].lower()

        if ext != INTEL_HEX_EXT:
            raise Exception("Only hex input file supported")

        h = IntelHex()
        h.frombytes(bytes=self.payload)
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
        epubk = None
        ehash = None

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
        e = STRUCT_ENDIAN_DICT[self.endian]

        image_dep_tag = self.get_tag()
        board_dep_tag = 0
        image_state_tag = [self.get_tag()]
        image_hash_tag = [self.get_tag()]

        start_fmt = (e +
            'HH' +  # rec_tag + rec_len
            'BBH' + # Image version
            'H' +   # Image dep tag
            'H' +   # Board dep tag
            'H' +   # Image state tag
            'H'     # Next tag (set to 0x7FFF)
        )
        hdr = struct.pack(start_fmt,
            SBK_IMAGE_META_START_TAG, struct.calcsize(start_fmt),
            self.version.major or 0, self.version.minor or 0, self.version.revision or 0,
            image_dep_tag,
            board_dep_tag,
            image_state_tag[0],
            0x7FFF,
        )

        image_dep_fmt = (e +
            'HH' +  # rec_tag + rec_len
            'BBH' + # minimum version
            'BBH' + # maximum version
            'H' +   # run slot
            'H'     # next image dependency tag
        )
        hdr += struct.pack(image_dep_fmt,
            image_dep_tag, struct.calcsize(image_dep_fmt),
            0,0,0,
            self.version.major or 0, self.version.minor or 0, self.version.revision or 0,
            self.load_slot,
            0
        )

        image_state_fmt = (e +
            'HH' +  # rec_tag + rec_len
            'H' +   # slot
            'H' +   # offset
            'I' +   # size
            'H' +   # state type
            'H' +   # hash tag
            'H' +   # transform tag
            'H'     # next image state tag
        )
        hdr += struct.pack(image_state_fmt,
            image_state_tag[0], struct.calcsize(image_state_fmt),
            self.load_slot,
            self.hdrsize,
            len(self.payload) - self.hdrsize,
            SBK_IMAGE_STATE_BOOTABLE,
            image_hash_tag[0],
            0,
            0
        )

        image_hash_fmt = (e +
            'HH' +  # rec_tag + rec_len
            'H' +   # type
            'H'     # pad16
        )
        hdr += struct.pack(image_hash_fmt,
            image_hash_tag[0], struct.calcsize(image_hash_fmt) + len(hash),
            SBK_IMAGE_HASH_TYPE_SHA256,
            0
        )
        hdr += hash

        if ((epubk is not None) and (ehash is not None)):
            print("TODO add encryption")

        sha = hashlib.sha256()
        sha.update(hdr)
        seal_msg = sha.digest()
        seal_pubk = signkey.get_public_key_bytearray()
        seal_sign = signkey.sign_prehashed(seal_msg)
        seal_len = len(seal_pubk) + len(seal_msg) + len(seal_sign)
        image_seal_fmt = (e +
            'HH' +  # rec_tag + rec_len
            'H' +   # type
            'H'     # pad16
        )
        hdr += struct.pack(image_seal_fmt,
            SBK_IMAGE_META_SEAL_TAG, struct.calcsize(image_seal_fmt) + seal_len,
            SBK_IMAGE_SEAL_TYPE_EDSA256,
            0
        )
        hdr += seal_pubk
        hdr += seal_sign
        hdr += seal_msg

        self.payload = bytearray(self.payload)
        self.payload[0:len(hdr)] = hdr