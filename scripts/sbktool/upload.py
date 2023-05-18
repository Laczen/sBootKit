# Copyright 2023 LaczenJMS
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
Image upload utility.
"""

from intelhex import IntelHex
import binascii
import os.path
import serial
import time

INTEL_HEX_EXT = "hex"

def upload(device, baudrate, slot, file):
        """Load an image from a given file"""
        ext = os.path.splitext(file)[1][1:].lower()
        if ext != INTEL_HEX_EXT:
            raise Exception("Only hex input file supported")

        ih = IntelHex(file)
        payload = ih.tobinarray()
        print(len(payload))
        port = []
        try:
                s = serial.Serial(device, baudrate)
                s.close()
                port.append(device)
        except (OSError, serial.SerialException):
                pass
    
        if len(port) == 0:
                msg = device + " is not available"
                raise ValueError(msg)

        s = serial.Serial(port[0], baudrate)
        s.timeout = 2
        msg = "\n"
        s.write(msg.encode())
        a = s.read(32767)
        print(a)
        msg = "image upload " + str(slot) + " " + str(len(payload)) + "\n"
        print(msg)
        s.write(msg.encode())
        a = s.read_until(b'\r\n')
        #
        pos = 0
        length = len(payload)
        while length > 0:
                a = s.read_until(b'OK\r\n')
                print("resp: " + a.decode())
                wrlen = min(length, 256)
                data = payload[pos: pos + wrlen]
                b = s.write(data)
                length -= wrlen
                pos += wrlen

        a = s.read_until(b'\r\n')
        print(a.decode())
        s.close()