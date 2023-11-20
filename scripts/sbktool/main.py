#! /usr/bin/env python3
#
# Copyright 2022 LaczenJMS
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

import click
import getpass
import sbktool.sbktcrypto as sbktcrypto
from sbktool import image
from sbktool import upload as upl
from sbktool.version import decode_version
import sys

sys.tracebacklimit = 0

def get_password():
    while True:
        passwd = getpass.getpass("Enter key passphrase: ")
        passwd2 = getpass.getpass("Reenter passphrase: ")
        if passwd == passwd2:
            break
        print("Passwords do not match, try again")

    # Password must be bytes, always use UTF-8 for consistent
    # encoding.
    return passwd.encode('utf-8')

@click.option('-p', '--password', is_flag=True,
              help='Prompt for password to protect key')
@click.option('-k', '--keyfile', metavar='filename', required=True)
@click.option('-t', '--type', type = click.Choice(['rpk', 'p256']),
              default = 'rpk', help = 'Select key type')
@click.command(help='Generate key file for use with sbktool')
def genkey(keyfile, password, type):
    password = get_password() if password else "sBootKit".encode('utf-8')
    if type == 'rpk':
        key = sbktcrypto.SBKTCrypto.generate('rpk')
    else:
        key = sbktcrypto.SBKTCrypto.generate('p256')
    key.export_private(path=keyfile, passwd=password)
    print("Done exporting {}-key".format(key.type))

def load_key(keyfile):
    # TODO: better handling of invalid pass-phrase
    passwd = "sBootKit".encode('utf-8')
    key = sbktcrypto.load(keyfile, passwd)
    if key is not None:
        return key
    passwd = getpass.getpass("Enter key passphrase: ").encode('utf-8')
    return sbktcrypto.load(keyfile, passwd)

@click.option('-k', '--key', metavar='filename', required=True)
@click.command(help='Generate key to include in sFSL (pub) or sLDR')
def geninclude(key):
    key = load_key(key)
    if key is not None:
        key.emit()

def validate_version(ctx, param, value):
    try:
        decode_version(value)
        return value
    except ValueError as e:
        raise click.BadParameter("{}".format(e))

def validate_version_range(value):
    rv = []
    range = value.split("-", 1)
    if not range[0]:
        range[0] = "0.0.0"
    if not range[1]:
        range[1] = "255.255.65535"
    for version in range:
        try:
            rv.append(decode_version(version))
        except ValueError as e:
            raise ValueError(e)
    return rv

def djb2_hash(s):
    hash = 5381
    for x in s:
        # ord(x) simply returns the unicode rep of the
        # character x
        hash = (( hash << 5) + hash) + ord(x)
        hash = hash & 0xFFFFFFFF
    return hash

def convert_product_dep(ctx, param, value):
    # a product is specified as: "product:min_ver-max_ver"
    rv = []
    for entry in value:
        [product, range] = entry.split(":", 1)
        product_hash = djb2_hash(product)
        try:
            range = validate_version_range(range)
        except ValueError as e:
            raise click.BadParameter("Bad range {}".format(e))

        rv.append((product_hash, range))

    return rv

def convert_image_dep(ctx, param, value):
    # a image is specified as: "address:min_ver-max_ver"
    rv = []
    for entry in value:
        [address, range] = entry.split(":", 1)
        try:
            if address[:2].lower() == '0x':
                address = int(address[2:], 16)
            elif address[:1] == '0':
                address = int(address, 8)
            address = int(address, 10)
        except ValueError:
            raise click.BadParameter("address is not a valid integer")

        try:
            range = validate_version_range(range)
        except ValueError as e:
            raise click.BadParameter("Bad range {}".format(e))

        rv.append((address, range))

    return rv
class BasedIntParamType(click.ParamType):
    name = 'integer'

    def convert(self, value, param, ctx):
        try:
            if value[:2].lower() == '0x':
                return int(value[2:], 16)
            elif value[:1] == '0':
                return int(value, 8)
            return int(value, 10)
        except ValueError:
            self.fail('%s is not a valid integer' % value, param, ctx)

@click.argument('outfile', required = False)
@click.argument('infile')
@click.option('-end', '--endian', type = click.Choice(['little', 'big']),
              default = 'little', help = 'Select little or big endian')
@click.option('-a', '--align', type = int, default = 32,
              help = 'Byte aligment - extends the image to alignment')
@click.option('-hs', '--hdrsize', required = True, type = BasedIntParamType(),
              help = 'Size of the header that was prepended during image \
                      generation')
@click.option('-v', '--version', callback = validate_version, type = str)
@click.option('-prd','--product', multiple=True, type = str,
              callback = convert_product_dep,
              help = 'Product dependency, productname:version range')
@click.option('-dep','--dependency', multiple=True, type = str,
              callback = convert_image_dep,
              help = 'Image dependency, image address:version range')
@click.option('-fk','--fslkey', metavar = 'filename', required = True,
              help = 'First stage loader authentication using the provided key')
@click.option('-uk','--updkey', metavar = 'filename', required = True,
              help = 'Updater authentication/encryption using the provided key')
@click.option('-c','--confirm', is_flag = True, help = 'create confirmed image')
@click.option('-d','--downgrade', is_flag = True,
              help = 'allow image downgrade (reverting image)')
@click.option('-e','--encrypt', is_flag = True, help = 'create encrypted image')
@click.option('-tst', '--test-image', is_flag = True,
              help = 'generate test image as c file')
@click.command(help='''Create a image for use with sBootKit\n
               INFILE and OUTFILE are of type hex''')
def create(align, hdrsize, version, product, dependency, fslkey, updkey,
           confirm, downgrade, encrypt, test_image, infile, outfile, endian):
    fslkey = load_key(fslkey)
    updkey = load_key(updkey)
    if (fslkey is not None) and (updkey is not None):
        img = image.Image(hdrsize = hdrsize, version = decode_version(version),
                          product_dep = product, image_dep = dependency,
                          endian = endian, align = align, type = type)
        img.load(infile)
        img.create(fslkey, updkey, confirm, downgrade, encrypt)
        if outfile is not None:
            img.save(outfile)

        if test_image:
            print("const unsigned char {}[{}] = {{".format("test_image", len(img.payload)), end = '')
            for count, b in enumerate(img.payload):
                if count % 8 == 0:
                    print("\n" + "\t", end='')
                else:
                    print(" ", end='')
                print("0x{:02x},".format(b), end='')
            print("\n};")
    else:
        print("Wrong bootkey or loadkey provided")

@click.argument('file')
@click.option('-d', '--device', type = str, default = None,
              help = 'Serial port device')
@click.option('-b', '--baudrate', type = int, default = 115200,
              help = 'Serial port baudrate')
@click.option('-s', '--slot', type = int, default = 0,
              help = 'Slot to upload to')
@click.command(help='''Send hex file to serial loader\n
               FILE should be of type hex''')
def upload(device, baudrate, slot, file):
    upl.upload(device, baudrate, slot, file)

class AliasesGroup(click.Group):

    _aliases = {
        "sign": "create",
    }

    def list_commands(self, ctx):
        cmds = [k for k in self.commands]
        aliases = [k for k in self._aliases]
        return sorted(cmds + aliases)

    def get_command(self, ctx, cmd_name):
        rv = click.Group.get_command(self, ctx, cmd_name)
        if rv is not None:
            return rv
        if cmd_name in self._aliases:
            return click.Group.get_command(self, ctx, self._aliases[cmd_name])
        return None


@click.command(cls=AliasesGroup,
               context_settings=dict(help_option_names=['-h', '--help']))
def sbktool():
    pass

sbktool.add_command(genkey)
sbktool.add_command(geninclude)
sbktool.add_command(create)
sbktool.add_command(upload)


if __name__ == '__main__':
    sbktool()
