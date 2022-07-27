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
import sbktool.keys as keys
from sbktool import image
from sbktool.version import decode_version
import sys

#sys.tracebacklimit = 0

def gen_ec_p256(keyfile, passwd):
    keys.EC256P1.generate().export_private(keyfile, passwd=passwd)

keygens = {
    'ec-p256': gen_ec_p256,
}

def load_key(keyfile):
    # TODO: better handling of invalid pass-phrase
    key = keys.load(keyfile)
    if key is not None:
        return key
    passwd = getpass.getpass("Enter key passphrase: ").encode('utf-8')
    return keys.load(keyfile, passwd)

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
@click.option('-t', '--type', metavar='type', required=True,
              type=click.Choice(keygens.keys()))
@click.option('-k', '--key', metavar='filename', required=True)
@click.command(help='Generate key file for use with zb8tool')
def genkey(type, key, password):
    password = get_password() if password else None
    print(type)
    keygens[type](key, password)

@click.option('-rpk', '--rootpubkey', metavar='filename', required=True)
@click.option('-bpk', '--bootprikey', metavar='filename', required=True)
@click.command(help='Generate bootloaders keys.inc file')
def geninclude(rootpubkey, bootprikey):
    bootkey = load_key(bootprikey)
    if bootkey is not None:
        label = bootkey.shortname()
        print("/* Autogenerated by sbktool.py, do not edit. */")
        print("const unsigned char {}_boot_pri_key[] = {{".format(label), end = '')
        bootkey.emit_private()
        print("\n};")
        print("const unsigned int {}_boot_pri_key_len = ".format(label), end = '')
        print(bootkey.get_private_key_size(), end = '')
        print(";\n")

        rootlist = [s.strip() for s in rootpubkey.split(',')]
        rootkeylen = 0
        print("const unsigned char {}_root_pub_key[] = {{".format(label), end = '')
        for i, value in enumerate(rootlist):
            rootkey = load_key(value)
            if rootkey is not None:
                rootkeylen = rootkeylen + rootkey.get_public_key_size()
                rootkey.emit_public()
        print("\n};")
        print("const unsigned int {}_root_pub_key_len = ".format(label), end = '')
        print(rootkeylen, end= '')
        print(";\n")

def validate_version(ctx, param, value):
    try:
        decode_version(value)
        return value
    except ValueError as e:
        raise click.BadParameter("{}".format(e))

def validate_dependency(ctx, param, value):
    try:
        decode_version(value[2])
        decode_version(value[3])
        return value
    except ValueError as e:
        raise click.BadParameter("{}".format(e))

def validate_hdrsize(ctx, param, value):
    if value == None:
        return None
    min_io = image.MIN_HDRSIZE
    if (value!= 0) and (value < min_io):
        raise click.BadParameter(
            "Minimum value for -h/--hdrsize is {} or 0".format(min_io))
    return value

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

@click.argument('outfile')
@click.argument('infile')
@click.option('-e', '--endian', type = click.Choice(['little', 'big']),
              default = 'little', help = 'Select little or big endian')
@click.option('-h', '--hdrsize', callback = validate_hdrsize,
              type = BasedIntParamType(),
              help = 'Size of the header that was prepended during image \
generation')
@click.option('-la','--load-address', type = BasedIntParamType(),
              help = 'Start address of the slot the image will be uploaded to')
@click.option('-da','--destination-address', type = BasedIntParamType(),
              help = 'Start address of the slot the image will be run from')
@click.option('-v', '--version', callback = validate_version,  required = True)
@click.option('-sk','--signkey', metavar = 'filename', required = True,
              help = 'Sign image using the provided sign key')
@click.option('-ek','--encrkey', metavar = 'filename',
              help = 'Encrypt image using the provided encrypt key')
@click.option('-c','--confirm', is_flag=True,
              help = 'Confirm the image (not a test image)')
@click.option('-dep','--dependency', type = (BasedIntParamType(), str, str),
              callback = validate_dependency,
              help = 'Image dependency, image at address in version range')
@click.option('-tst', '--test-image',
              help = 'generate test image as c file')
@click.command(help='''Create a image for use with sBootKit\n
               INFILE and OUTFILE are of type hex''')

def create(hdrsize, load_address, destination_address, version, dependency,
           endian, signkey, encrkey, confirm, test_image, infile, outfile):
    signkey = load_key(signkey)
    if signkey is not None:
        encrkey = load_key(encrkey) if encrkey else None
        img = image.Image(hdrsize = hdrsize, load_address = load_address,
                          dest_address = destination_address,
                          version = decode_version(version), 
                          dep_min_addr = dep_min[1],
                          dep_min_ver = decode_version(dep_min[2]),
                          dep_max_ver = decode_version(dep_min[3]),
                          endian = endian,
                          type = type, confirm = confirm)
        img.load(infile)
        img.create(signkey, encrkey)
        img.save(outfile)

        if test_image:
            print("const unsigned char {}[{}] = {{".format(test_image, len(img.payload)),end = '')
            for count, b in enumerate(img.payload):
                if count % 8 == 0:
                    print("\n" + "\t", end='')
                else:
                    print(" ", end='')
                print("0x{:02x},".format(b), end='')
            print("\n};")
    else:
        print("Wrong signkey provided")

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


if __name__ == '__main__':
    sbktool()
