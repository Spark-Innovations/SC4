#!/bin/env python
# coding: utf-8

import sc4
from sc4 import *
from random import randint

def test_encrypt():
  rx_key = random_key()
  cleartext = random_bytes(randint(1,100000))
  ciphertext = encrypt(cleartext, rx_key)
  sc4.my_key = rx_key
  cleartext2 = decrypt(ciphertext)[0]
  return cleartext2 == cleartext

def test_encrypt_pt():
  rx_key = random_key()
  cleartext = random_bytes(randint(1,100000))
  ciphertext = encrypt_pt(cleartext, rx_key)
  sc4.my_key = rx_key
  cleartext2 = decrypt_pt(ciphertext)[0]
  return cleartext2 == cleartext

def test_sign():
  thing = random_bytes(randint(1,100000))
  sig = sc4.sign(thing)
  v1 = sc4.verify_signature(sig)
  idx = randint(44, len(sig)-1)
  sig = bytearray(sig)
  sig[idx] ^= (1<<(randint(0,7)))
  sig = bstr(sig)
  v2 = sc4.verify_signature(sig)
  return (len(v1)==2, v2==False)

def test_sign_pt():
  thing = random_bytes(randint(1,100000))
  sig = sc4.sign_pt(thing)
  v1 = sc4.verify_signature_pt(sig)
  return v1 and len(v1)==2

def test_encrypt_multi():
  rx_keys = []
  for i in range(randint(1,10)): rx_keys.append(random_key())
  cleartext = random_bytes(randint(1,100000))
  ciphertext = encrypt_multi(cleartext, rx_keys)
  for k in rx_keys:
    sc4.my_keys = k
    cleartext2 = decrypt_multi(ciphertext)[0]
    if cleartext != cleartext2: return False
    pass
  return True

def test_encrypt_multi_pt():
  rx_keys = []
  for i in range(randint(1,10)): rx_keys.append(random_key())
  cleartext = random_bytes(randint(1,100000))
  ciphertext = encrypt_multi_pt(cleartext, rx_keys)
  for k in rx_keys:
    sc4.my_keys = k
    cleartext2 = decrypt_multi_pt(ciphertext)[0]
    if cleartext != cleartext2: return False
    pass
  return True

tests = [test_encrypt, test_encrypt_pt, test_sign, test_sign_pt,
         test_encrypt_multi, test_encrypt_multi_pt]

def test():
  for test in tests: print(test.__name__, test())
  return

if __name__=='__main__': test()
