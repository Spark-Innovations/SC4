
import os
from . import _tweetnacl as _t

def randombytes(count):
    return os.urandom(count)

crypto_onetimeauth = _t.crypto_onetimeauth
crypto_onetimeauth_verify = _t.crypto_onetimeauth_verify
crypto_hash = _t.crypto_hash
crypto_verify_16 = _t.crypto_verify_16
crypto_verify_32 = _t.crypto_verify_32
crypto_scalarmult = _t.crypto_scalarmult
crypto_scalarmult_base = _t.crypto_scalarmult_base
crypto_stream = _t.crypto_stream
crypto_stream_xor = _t.crypto_stream_xor
crypto_sign = _t.crypto_sign
crypto_sign_open = _t.crypto_sign_open
crypto_sign_keypair = _t.crypto_sign_keypair
crypto_sign_keypair_from_seed = _t.crypto_sign_keypair_from_seed
crypto_secretbox = _t.crypto_secretbox
crypto_secretbox_open = _t.crypto_secretbox_open
crypto_box = _t.crypto_box
crypto_box_open = _t.crypto_box_open
crypto_box_keypair = _t.crypto_box_keypair
crypto_box_beforenm = _t.crypto_box_beforenm
crypto_box_afternm = _t.crypto_box_afternm
crypto_box_open_afternm = _t.crypto_box_open_afternm
spk2epk = _t.spk2epk

crypto_onetimeauth_PRIMITIVE = _t.crypto_onetimeauth_PRIMITIVE
crypto_onetimeauth_IMPLEMENTATION = _t.crypto_onetimeauth_IMPLEMENTATION
crypto_onetimeauth_VERSION = _t.crypto_onetimeauth_VERSION
crypto_onetimeauth_BYTES = _t.crypto_onetimeauth_BYTES
crypto_onetimeauth_KEYBYTES = _t.crypto_onetimeauth_KEYBYTES
crypto_hash_PRIMITIVE = _t.crypto_hash_PRIMITIVE
crypto_hash_IMPLEMENTATION = _t.crypto_hash_IMPLEMENTATION
crypto_hash_VERSION = _t.crypto_hash_VERSION
crypto_hash_BYTES = _t.crypto_hash_BYTES
crypto_verify_16_BYTES = _t.crypto_verify_16_BYTES
crypto_verify_16_IMPLEMENTATION = _t.crypto_verify_16_IMPLEMENTATION
crypto_verify_16_VERSION = _t.crypto_verify_16_VERSION
crypto_verify_32_BYTES = _t.crypto_verify_32_BYTES
crypto_verify_32_IMPLEMENTATION = _t.crypto_verify_32_IMPLEMENTATION
crypto_verify_32_VERSION = _t.crypto_verify_32_VERSION
crypto_scalarmult_PRIMITIVE = _t.crypto_scalarmult_PRIMITIVE
crypto_scalarmult_IMPLEMENTATION = _t.crypto_scalarmult_IMPLEMENTATION
crypto_scalarmult_VERSION = _t.crypto_scalarmult_VERSION
crypto_scalarmult_BYTES = _t.crypto_scalarmult_BYTES
crypto_scalarmult_SCALARBYTES = _t.crypto_scalarmult_SCALARBYTES
crypto_stream_PRIMITIVE = _t.crypto_stream_PRIMITIVE
crypto_stream_IMPLEMENTATION = _t.crypto_stream_IMPLEMENTATION
crypto_stream_VERSION = _t.crypto_stream_VERSION
crypto_stream_KEYBYTES = _t.crypto_stream_KEYBYTES
crypto_stream_NONCEBYTES = _t.crypto_stream_NONCEBYTES
crypto_sign_PRIMITIVE = _t.crypto_sign_PRIMITIVE
crypto_sign_IMPLEMENTATION = _t.crypto_sign_IMPLEMENTATION
crypto_sign_VERSION = _t.crypto_sign_VERSION
crypto_sign_BYTES = _t.crypto_sign_BYTES
crypto_sign_PUBLICKEYBYTES = _t.crypto_sign_PUBLICKEYBYTES
crypto_sign_SECRETKEYBYTES = _t.crypto_sign_SECRETKEYBYTES
crypto_secretbox_PRIMITIVE = _t.crypto_secretbox_PRIMITIVE
crypto_secretbox_IMPLEMENTATION = _t.crypto_secretbox_IMPLEMENTATION
crypto_secretbox_VERSION = _t.crypto_secretbox_VERSION
crypto_secretbox_KEYBYTES = _t.crypto_secretbox_KEYBYTES
crypto_secretbox_NONCEBYTES = _t.crypto_secretbox_NONCEBYTES
crypto_secretbox_ZEROBYTES = _t.crypto_secretbox_ZEROBYTES
crypto_secretbox_BOXZEROBYTES = _t.crypto_secretbox_BOXZEROBYTES
crypto_box_PRIMITIVE = _t.crypto_box_PRIMITIVE
crypto_box_IMPLEMENTATION = _t.crypto_box_IMPLEMENTATION
crypto_box_VERSION = _t.crypto_box_VERSION
crypto_box_PUBLICKEYBYTES = _t.crypto_box_PUBLICKEYBYTES
crypto_box_SECRETKEYBYTES = _t.crypto_box_SECRETKEYBYTES
crypto_box_BEFORENMBYTES = _t.crypto_box_BEFORENMBYTES
crypto_box_NONCEBYTES = _t.crypto_box_NONCEBYTES
crypto_box_ZEROBYTES = _t.crypto_box_ZEROBYTES
crypto_box_BOXZEROBYTES = _t.crypto_box_BOXZEROBYTES
