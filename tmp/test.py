from Crypto.Hash import SHA256

msg = bytearray(b'\x61\x62\x63')
hash = SHA256.new(msg)
print(hash.digest())
digest = b'\xba\x78\x16\xbf\x8f\x01\xcf\xea\x41\x41\x40\xde\x5d\xae\x22\x23\xb0\x03\x61\xa3\x96\x17\x7a\x9c\xb4\x10\xff\x61\xf2\x00\x15\xad'
print(digest)