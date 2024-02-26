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
import sbktool.sbktcrypto as sbktcrypto

from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256, HMAC
from Crypto.Protocol.KDF import HKDF
from Crypto.Cipher import ChaCha20

SBK_IMAGE_INFO_TAG = 0x8000
SBK_IMAGE_TLVF_TAG = 0x80BF
SBK_IMAGE_SSLC_TAG0 = 0x80C0
SBK_IMAGE_SSLI_TAG0 = 0x80D0
SBK_IMAGE_FSLI_TAG0 = 0x80F0
SBK_IMAGE_FLAG_TEST = 0x00000001
SBK_IMAGE_FLAG_ENCRYPTED = 0x00000010
SBK_IMAGE_FLAG_ZLIB = 0x00000020
SBK_IMAGE_FLAG_VCDIFF = 0x00000040

SBK_IMAGE_SALT_SIZE = 16
SBK_IMAGE_HMAC_SIZE = 32
SBK_IMAGE_HMAC_CONTEXT = b"SBK HMAC"
SBK_IMAGE_CIPH_CONTEXT = b"SBK CIPH"

SBK_IMAGE_HASH_SIZE = 32
SBK_IMAGE_SIGNATURE_SIZE = 64

INTEL_HEX_EXT = "hex"
STRUCT_ENDIAN_DICT = {
        'little': '<',
        'big':    '>'
}

class Image():
    def __init__(self, align = 1, hdrsize = None, offset = None, version = 0,
                 image_dep = None, product_dep = None, endian = 'little',
                 type = 'image'):
        self.hdrsize = hdrsize
        self.offset = offset
        self.align = align
        self.version = version
        self.payload = []
        self.product_dep = product_dep
        self.image_dep = image_dep
        self.endian = endian
        self.metacnt = SBK_IMAGE_INFO_TAG
        self.salt = get_random_bytes(SBK_IMAGE_SALT_SIZE)
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
        self.image_address = ih.minaddr()

        # Padding the payload to aligned size
        padlen = self.align - len(self.payload) % self.align
        if (padlen != self.align):
            padding = get_random_bytes(padlen)
            self.payload = bytes(self.payload) + padding

        self.payload = bytearray(self.payload)
        sha256 = SHA256.new()
        sha256.update(self.payload[self.hdrsize:])
        self.hash = sha256.digest()
        self.chash = self.hash
        self.check()

    def save(self, path):
        """Save an image from a given file"""
        ext = os.path.splitext(path)[1][1:].lower()

        if ext != INTEL_HEX_EXT:
            raise Exception("Only hex input file supported")

        h = IntelHex()
        if self.offset is None:
            self.offset = self.image_address
        h.frombytes(bytes=self.payload, offset = self.offset)
        h.tofile(path, 'hex')

    def add_meta(self, signkey, privkey):
        
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
            'I' +   # sequence number
            'BBH' + # Image version
            'I' +   # Image flags
            'I' +   # Image size
            'I' +   # Image start address
            'H' +   # Image offset
            'H' +   # Image dep tag
            'H' +   # Board dep tag
            'H' +   # Other tag
            '32s'   # Image hash
        )

        #print(struct.calcsize(meta_fmt))
        info = struct.pack(meta_fmt,
            SBK_IMAGE_INFO_TAG, struct.calcsize(meta_fmt),
            0,
            self.version.major or 0, self.version.minor or 0, self.version.revision or 0,
            self.flags,
            len(self.payload) - self.hdrsize,
            self.image_address + self.hdrsize,
            self.hdrsize,
            image_dep_tag[0],
            product_dep_tag[0],
            0,
            self.hash,
        )

        #print(' '.join(format(x, '02x') for x in self.hash))

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
            '32s' + # product guid
            'H' +   # next product dependency tag
            'H'     # pad16
        )

        n = 0
        for product_dep in self.product_dep:
            guid = sbktcrypto.sha256(product_dep[0])
            vrange = product_dep[1]
            info += struct.pack(product_dep_fmt,
                product_dep_tag[n], struct.calcsize(product_dep_fmt),
                vrange[0].major, vrange[0].minor, vrange[0].revision,
                vrange[1].major, vrange[1].minor, vrange[1].revision,
                guid,
                product_dep_tag[n + 1],
                0
            )
            n = n + 1

        # sslc format
        e = STRUCT_ENDIAN_DICT[self.endian]
        sslc_meta_fmt = (e +
            'HH' +  # rec_tag + rec_len
            '16s'   # salt
        )

        # ssli format
        e = STRUCT_ENDIAN_DICT[self.endian]
        ssli_meta_fmt = (e +
            'HH' +  # rec_tag + rec_len
            '64s'   # signature
        )

        # fsli format
        e = STRUCT_ENDIAN_DICT[self.endian]
        fsli_meta_fmt = (e +
            'HH' +  # rec_tag + rec_len
            '32s'   # hash
        )

        filler_size = self.hdrsize
        filler_size -= len(info)
        if privkey is not None:
            filler_size -= struct.calcsize(sslc_meta_fmt)
        filler_size -= struct.calcsize(ssli_meta_fmt)
        filler_size -= struct.calcsize(fsli_meta_fmt)

        if (filler_size < 0):
            raise Exception("Header size to small to fit meta data")
        
        if (filler_size > 3):
            # insert filler
            e = STRUCT_ENDIAN_DICT[self.endian]
            filler_meta_fmt = (e +
                'HH' # rec_tag + rec_len
            )
            info += struct.pack(filler_meta_fmt,
                SBK_IMAGE_TLVF_TAG,
                filler_size,
            )
            info += bytearray([0x55] * (filler_size - struct.calcsize(filler_meta_fmt)))
      
        if privkey is not None:
            info += struct.pack(sslc_meta_fmt,
            SBK_IMAGE_SSLC_TAG0, struct.calcsize(sslc_meta_fmt),
            self.salt,
        )

        ssli_pubkey = signkey.p256_pubkey()
        ssli_sig = signkey.p256_sign(info)
        info += struct.pack(ssli_meta_fmt,
            SBK_IMAGE_SSLI_TAG0, struct.calcsize(ssli_meta_fmt),
            ssli_sig,
        )
     
        ssli_hash = sbktcrypto.sha256(info)
        info += struct.pack(fsli_meta_fmt,
            SBK_IMAGE_FSLI_TAG0, struct.calcsize(fsli_meta_fmt),
            ssli_hash,
        )
        self.payload[:self.hdrsize] = info
        return len(info)

    def show(self, data):
        print('\\x' + '\\x'.join(format(x, '02x') for x in data))

    def create(self, signkey, privkey, test):

        if privkey is not None:
            self.flags |= SBK_IMAGE_FLAG_ENCRYPTED

        if test:
            self.flags |= SBK_IMAGE_FLAG_TEST

        if privkey is not None:
            self.payload[self.hdrsize:]=privkey.rpk_encrypt(self.salt,
                SBK_IMAGE_CIPH_CONTEXT, self.payload[self.hdrsize:])
            self.chash = sbktcrypto.sha256(self.payload[self.hdrsize:])

        self.add_meta(signkey, privkey)
