
import sys, binascii, random

def fromhex(h):
    return binascii.unhexlify(str(h).encode("ascii"))

if sys.version_info[0] >= 3:
    def flip_bit_in_byte(byte, whichbit):
        return bytes([byte ^ (1 << whichbit)])
else:
    def flip_bit_in_byte(byte, whichbit):
        return chr(ord(byte) ^ (1 << whichbit))

def flip_bit(orig):
    offset = random.randrange(0, len(orig))
    whichbit = random.randrange(0, 8)
    corrupted = (orig[:offset]
                 + flip_bit_in_byte(orig[offset], whichbit)
                 + orig[offset+1:])
    return corrupted
