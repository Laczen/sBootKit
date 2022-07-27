<!--
  Copyright (c) 2022 Laczen

  SPDX-License-Identifier: Apache-2.0
-->

# Image tool - sbktool.py

The Python program `scripts/sbktool.py` can be used to perform the operations
that are necessary to create keys, generate keys.c file for the bootloader, and
sign and encrypt images.

This program is written for Python3, and has several dependencies on Python
libraries. These can be installed using 'pip3':

    pip3 install --user -r scripts/requirements.txt

## Managing keys

This tool currently supports only ec-p256 keys. You can generate a keypair
(combination of private and public key) using the `genkey` command:

    ./scripts/sbktool.py genkey -k filename.pem -t ec-p256

This key file is what is used to sign or encrypt images, this file should be
protected, and not widely distributed.

You can add the `-p` argument to `genkey`, which will cause it to prompt for a
password.  You will need to enter this password every time you use the key.

In most case you will need to create two keypairs:
* A root key: this key is used to sign the images. Only images signed with a
known key will be accepted by sBootKit. In order to do this the public key needs
to be added to the bootloader (see below).
* A bootloader key: this key is used to communicate the encryption key to the
bootloader. For each image sbktool.py generates a new random key and this random
key can be derived by the bootloader. From this random key the encryption key
is generated using a key derivation algorithm (KDF), for sBootKit this key
derivation algorithm is KDF1. In order for the bootloader to derive the random
key and the encryption key the private key needs to be added to the bootloader
(see below).

## Incorporating the root public key and bootloader private key into the code

There are development keys distributed with sBootKit (root-ec256.pem and
boot-ec256.pem) that can be used for testing. Since these keys are widely
distributed, they should never be used for production. Once you have generated
your own production keys, as described above, you should replace the public root
key and the private boot key with the generated one.

The keys live in the file `keys.c`. A new keys.c file is
generated using:

    ./scripts/sbktool.py geninclude -rpk root-ec256.pem -bpk boot-ec256.pem \
    > os/zephyr/src/keys.c

will extract the public key from root-ec256.pem, the private key from
boot-ec256.pem file, and output them as a C data structure in
`os/zephyr/src/keys.c`.

In some cases you might wish to allow images from different sources, this can be
achieved by suplying multiple root key files:

    ./scripts/sbktool.py geninclude -rpk root1-ec256.pem,root2-ec256.pem \
    -bpk boot-ec256.pem > os/zephyr/src/keys.c

## Creating images for sBootKit

Creating images for sBootKit takes an image in binary or Intel Hex format
intended and adds a header that the bootloader is expecting:

    Usage: sbktool.py sign [OPTIONS] INFILE OUTFILE

      Create a image for use with sBootKit

    Options:
      -e, --endian [little|big]     Select little or big endian
      -io, --image-offset INTEGER   Offset used to generate space for the image
                                    header [required]
      -ss, --slot-size INTEGER      Size of the slot where the image will be
                                    written [required]
      -a, --align [1|2|4|8]         Flash write alignment in bytes [required]
      -sa, --slot_address INTEGER   Start address of the slot the image is run
                                    from [required for files of type bin]
      -v, --version TEXT            Version [required]
      -sk, --signkey FILENAME       Root key file used for signing
      -ek, --encrkey FILENAME       Bootloader key file used for encryption
      -h, --help                    Show this message and exit.

An example is:

    ./scripts/sbktool.py sign -io 0x200 -ss 0x40000 -a 4 -sa 0x11000 -v 0.0.1\
    -sk root-ec256.pem -ek boot-ec256.pem test.bin output.bin

This line will create output.bin from input.bin, set the slot address to
0x11000 (input.bin must be created taking this into account), version 0.0.1,
output.bin is encrypted using boot-ec256.pem and signed using root-ec256.pem.

The image output.bin should then be placed in the correct upgrade location. A
reboot will start the upgrade proces.