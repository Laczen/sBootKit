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
import serial.threaded
import sys
import time

INTEL_HEX_EXT = "hex"

def upload(device, baudrate, slot, file):
        """Load an image from a given file"""
        ext = os.path.splitext(file)[1][1:].lower()
        if ext != INTEL_HEX_EXT:
            raise Exception("Only hex input file supported")

        ih = IntelHex(file)
        payload = ih.tobinarray()
        port = []
        try:
                s = serial.Serial(device, baudrate, timeout = 0.5)
                s.close()
                port.append(device)
        except (OSError, serial.SerialException):
                pass
    
        if len(port) == 0:
                msg = device + " is not available"
                raise ValueError(msg)

        s.open()
        s.reset_input_buffer()
        s.reset_output_buffer()

        while True:
                s.write(b'\r\n')
                s.flush()
                msg = s.read_until("sbk_shell>")
                if msg is not None:
                        break

        msg = "upload " + str(slot) + " " + str(len(payload)) + "\r\n"
        s.write(msg.encode('utf8'))
        s.flush()
        allow_send = False
        while True:
                msg = s.readline()
                ok = msg.decode('utf8').find('OK')
                if (ok > 0):
                        allow_send = True
                        break
        
        pos = 0
        length = len(payload)
        print("uploading " + str(length) + "byte of " + file)
        while True:
                if allow_send:
                        wrlen = min(length - pos, 64)
                        data = payload[pos: pos + wrlen]
                        b = s.write(data)
                        s.flush()
                        pos += wrlen
                        if (pos % 512 == 0) or (pos == length):
                                allow_send = False
                else:
                        msg = s.readline()
                        ok = msg.decode('utf8').find('OK')
                        if (ok > 0):
                                print(f'\r {pos/length * 100:.2f} %', end = '')
                                if (pos < length):
                                        allow_send = True
                                else:
                                        print(" ", end = '')
                                        break
                        

        print("done")
        s.close()