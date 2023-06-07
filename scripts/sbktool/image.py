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

from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256, HMAC
from Crypto.Protocol.KDF import HKDF
from Crypto.Cipher import ChaCha20

SBK_IMAGE_META_TAG = 0x8000
SBK_IMAGE_AUTH_TAG = 0x7FFF
SBK_IMAGE_FLAG_CONFIRMED = 0x0001
SBK_IMAGE_FLAG_DOWNGRADE = 0x0002
SBK_IMAGE_FLAG_ENCRYPTED = 0x0010
SBK_IMAGE_FLAG_ZLIB = 0x0020
SBK_IMAGE_FLAG_VCDIFF = 0x0040

SBK_SALT_SIZE = 16
SBK_HMAC_SIZE = 32
SBK_IMAGE_AUTH_CTX = b"SBK AUTHENTICATE"
SBK_IMAGE_ENCR_CTX = b"SBK ENCRYPT"

INTEL_HEX_EXT = "hex"
STRUCT_ENDIAN_DICT = {
        'little': '<',
        'big':    '>'
}

class Image():
    def __init__(self, align = 1, hdrsize = None, version = 0, image_dep = None,
                 product_dep = None, endian = 'little', type = 'image'):
        self.hdrsize = hdrsize
        self.align = align
        self.version = version or versmod.decode_version("0")
        self.payload = []
        self.product_dep = product_dep
        self.image_dep = image_dep
        self.endian = endian
        self.metacnt = 0
        self.salt = get_random_bytes(SBK_SALT_SIZE)
        self.fsl_fhmac = bytearray([0] * SBK_HMAC_SIZE)
        self.ldr_shmac = bytearray([0] * SBK_HMAC_SIZE)
        self.ldr_fhmac = bytearray([0] * SBK_HMAC_SIZE)
        self.flags = 0

    def __repr__(self):
        return "<align={}, hdrsize={}, Image version={}, endian={}, type={}, \
                 format={}, payloadlen=0x{:x}>".format(
                    self.align,
                    self.hdrsize,
                    self.version,
                    self.endian,
                    self.type,
                    self.__class__.__name__,
                    len(self.payload))

    def get_tag(self):
        self.metacnt += 1
        value = self.metacnt & 0x7FFF
        value ^= value >> 8
        value ^= value >> 4
        value &= 0xf
        if ((0x6996 >> value) & 1) == 0:
            return self.metacnt | 0x8000

        return self.metacnt

    def check(self):
        """Perform some sanity checking of the image."""
        # Check that image starts with header of all 0x00.
        if any(v != 0x00 for v in self.payload[0:self.hdrsize]):
            raise Exception("Header size provided, but image does not \
            start with 0x00")

    def load(self, path):
        """Load an image from a given file"""
        ext = os.path.splitext(path)[1][1:].lower()
        if ext != INTEL_HEX_EXT:
            raise Exception("Only hex input file supported")

        ih = IntelHex(path)
        self.payload = ih.tobinarray()
        self.offset = ih.minaddr();

        # Padding the payload to aligned size
        padlen = self.align - len(self.payload) % self.align
        if (padlen != self.align):
            padding = get_random_bytes(padlen)
            self.payload = bytes(self.payload) + padding

        self.payload = bytearray(self.payload)
        self.check()

    def save(self, path):
        """Save an image from a given file"""
        ext = os.path.splitext(path)[1][1:].lower()

        if ext != INTEL_HEX_EXT:
            raise Exception("Only hex input file supported")

        h = IntelHex()
        h.frombytes(bytes=self.payload, offset = self.offset)
        h.tofile(path, 'hex')

    def add_auth(self):
        e = STRUCT_ENDIAN_DICT[self.endian]
        auth_fmt = (e +
            'HH' +  # rec_tag + rec_len
            '32s' +    # fsl_fhmac
            '32s' +    # ldr_shamc
            '32s'      # ldr_fhmac
        )

        auth = struct.pack(auth_fmt,
            SBK_IMAGE_AUTH_TAG, struct.calcsize(auth_fmt),
            self.fsl_fhmac,
            self.ldr_shmac,
            self.ldr_fhmac
        )

        self.payload[0:len(auth)] = auth
        return len(auth)

    def add_meta(self, offset):
        self.image_dep.append((
            self.offset + self.hdrsize,
            (versmod.decode_version("0"), self.version)
        ))

        image_dep_tag = []
        for entry in self.image_dep:
            image_dep_tag.append(self.get_tag())
        image_dep_tag.append(0)
        product_dep_tag = []
        for entry in self.product_dep:
            product_dep_tag.append(self.get_tag())
        product_dep_tag.append(0)

        e = STRUCT_ENDIAN_DICT[self.endian]
        meta_fmt = (e +
            'HH' +  # rec_tag + rec_len
            'BBH' + # Image version
            'I' +   # Image start address
            'I' +   # Image flags
            'I' +   # Image size
            'H' +   # Image offset
            'H' +   # Image dep tag
            'H' +   # Board dep tag
            'H' +   # Other tag
            '16s'  # salt
        )
        info = struct.pack(meta_fmt,
            SBK_IMAGE_META_TAG, struct.calcsize(meta_fmt),
            self.version.major or 0, self.version.minor or 0, self.version.revision or 0,
            self.offset + self.hdrsize,
            self.flags,
            len(self.payload) - self.hdrsize,
            self.hdrsize,
            image_dep_tag[0],
            product_dep_tag[0],
            0,
            self.salt,
        )

        image_dep_fmt = (e +
            'HH' +  # rec_tag + rec_len
            'BBH' + # minimum version
            'BBH' + # maximum version
            'I' +   # image start address
            'H' +   # next image dependency tag
            'H'     # pad16
        )

        n = 0
        for image_dep in self.image_dep:
            address = image_dep[0]
            vrange = image_dep[1]
            info += struct.pack(image_dep_fmt,
                image_dep_tag[n], struct.calcsize(image_dep_fmt),
                vrange[0].major, vrange[0].minor, vrange[0].revision,
                vrange[1].major, vrange[1].minor, vrange[1].revision,
                address,
                image_dep_tag[n + 1],
                0
            )
            n = n + 1

        product_dep_fmt = (e +
            'HH' +  # rec_tag + rec_len
            'BBH' + # minimum version
            'BBH' + # maximum version
            'I' +   # product hash (djb2)
            'H' +   # next product dependency tag
            'H'     # pad16
        )

        n = 0
        for product_dep in self.product_dep:
            product_hash = product_dep[0]
            vrange = product_dep[1]
            info += struct.pack(product_dep_fmt,
                product_dep_tag[n], struct.calcsize(product_dep_fmt),
                vrange[0].major, vrange[0].minor, vrange[0].revision,
                vrange[1].major, vrange[1].minor, vrange[1].revision,
                product_hash,
                product_dep_tag[n + 1],
                0
            )
            n = n + 1

        if len(info) > (self.hdrsize - offset):
            raise Exception("Header size to small to fit meta data")

        info = info + bytearray([0] * (self.hdrsize - offset - len(info)))
        self.payload[offset:self.hdrsize] = info
        return len(info)

    def show(self, data):
        print('\\x' + '\\x'.join(format(x, '02x') for x in data))

    def create(self, fslkey, updkey, confirm, downgrade, encrypt):

        if encrypt:
            self.flags |= SBK_IMAGE_FLAG_ENCRYPTED
        
        if confirm:
            self.flags |= SBK_IMAGE_FLAG_CONFIRMED

        if downgrade:
            self.flags |= SBK_IMAGE_FLAG_DOWNGRADE

        meta_offset = self.add_auth()
        self.add_meta(meta_offset)

        km = HKDF(fslkey.get_private_key_bytearray(), 44, self.salt, SHA256, 1, SBK_IMAGE_AUTH_CTX)
        h = HMAC.new(km, digestmod=SHA256)
        h.update(self.payload[meta_offset:])
        self.fsl_fhmac = h.digest()

        km = HKDF(updkey.get_private_key_bytearray(), 44, self.salt, SHA256, 1, SBK_IMAGE_AUTH_CTX)
        h = HMAC.new(km, digestmod=SHA256)
        h.update(self.payload[meta_offset:self.hdrsize])
        self.ldr_shmac = h.digest()

        if encrypt:
            ekm = HKDF(updkey.get_private_key_bytearray(), 44, self.salt, SHA256, 1, SBK_IMAGE_ENCR_CTX)
            cipher = ChaCha20.new(key=ekm[0:32], nonce=ekm[32:44])
            self.payload[self.hdrsize:]=cipher.encrypt(self.payload[self.hdrsize:])

        h = HMAC.new(km, digestmod=SHA256)
        h.update(self.payload[meta_offset:])
        self.ldr_fhmac = h.digest()

        self.add_auth()


