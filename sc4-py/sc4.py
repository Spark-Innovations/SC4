#!/usr/bin/env python
# coding: utf-8

#####################################################################
#
# sc4.py -- Secure Communications for Mere Mortals
#
# Copyright (c) 2015 by Spark Innovations, Inc.
#
# Released under the terms of a
# Creative Commons Attribution-NonCommercial-ShareAlike 4.0
# International License.
# See http://creativecommons.org/licenses/by-nc-sa/4.0/ for details
#
#####################################################################

import sys

try:
  import nacl.raw as nacl
except:
  print("Importing nacl failed.  Did you run 'make'?")
  sys.exit()
  pass

import itertools
import re
import base64
import datetime
import os
import subprocess
import getopt
import glob
from getpass import getpass

#############################################
#
# Bstr is a replacement for the Python3 bytes data type.  It's a string
# that returns individual elements as integers instead of characters.
#

if str is bytes:  # Python2
  class Bstr(str):
    def __getitem__(self, idx): return ord(str.__getitem__(self, idx))
    def __getslice__(self, s, e): return bstr(str.__getslice__(self, s, e))
    def __repr__(self): return 'b' + str.__repr__(self)
    def __add__(self, b): return bstr(str.__add__(self, b))
    pass
  def bstr(thing):
    if type(thing) is Bstr: return thing
    if type(thing) is unicode: return Bstr(thing.encode('utf-8'))
    if type(thing) is list: return Bstr(''.join([chr(i) for i in thing]))
    return Bstr(thing)
  def bytes2string(bytes):
    return unicode(bytes, 'utf-8')
  pass
else: # Python3
  class Bstr(bytes): pass
  def bstr(thing):
    if isinstance(thing, bytes): return thing
    if type(thing) in [list, bytearray]: return Bstr(thing)
    return Bstr(thing, 'utf-8')
  def bytes2string(bytes):
    return str(bytes, 'utf-8')
  pass

def to_bytes(thing): return bstr(thing)

def concat(bstrs): return bstr(b''.join(bstrs))

###########################################
#
# Interface to the tweetnacl library
#

def crypto_box(thing, nonce, rx_pk, tx_sk):
  return nacl.crypto_box(bstr(thing), bstr(nonce), bstr(rx_pk), bstr(tx_sk))

def crypto_box_open(bytes, nonce, tx_pk, rx_sk):
  return bstr(nacl.crypto_box_open(bstr(bytes), bstr(nonce),
                                   bstr(tx_pk), bstr(rx_sk)))

def crypto_sign(thing, sk):
  return nacl.crypto_sign(bstr(thing), bstr(sk))

def crypto_sign_open(sig, pk):
  return nacl.crypto_sign_open(bstr(sig), bstr(pk))

def crypto_secretbox(bytes, nonce, key):
  return nacl.crypto_secretbox(bstr(bytes), bstr(nonce), bstr(key))

def crypto_secretbox_open(bytes, nonce, key):
  return nacl.crypto_secretbox_open(bstr(bytes), bstr(nonce), bstr(key))

def hash(thing): return nacl.crypto_hash(bstr(thing))

def random_bytes(n): return bstr(nacl.randombytes(n))

#############################################
#
#  Data format conversion utilities
#

def b64(bytes): return bytes2string(base64.b64encode(bytes))

def unb64(s): return bstr(base64.b64decode(s))

def baseN_encode(thing, alphabet, base):
  v = to_bytes(thing)
  origlen = len(v)
  v = v.lstrip(b'\0')
  newlen = len(v)
  p, acc = 1, 0
  for c in bstr(v[::-1]):
    acc += p * c
    p = p << 8
    pass
  result = ''
  while acc > 0:
    acc, mod = divmod(acc, base)
    result += alphabet[mod]
    pass
  return (alphabet[0] * (origlen - newlen)) + result[::-1]

def baseN_decode(v, alphabet, base):
  if not isinstance(v, str): v = v.decode('ascii')
  origlen = len(v)
  v = v.lstrip(alphabet[0])
  newlen = len(v)
  p, acc = 1, 0
  for c in v[::-1]:
    acc += p * alphabet.index(c)
    p *= base
    pass
  result = []
  while acc > 0:
    acc, mod = divmod(acc, 256)
    result.append(mod)
    pass
  return bstr('\0' * (origlen - newlen)) + bstr(result[::-1])

b58alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def b58(v): return baseN_encode(v, b58alphabet, 58)

def unb58(s): return baseN_decode(s, b58alphabet, 58)

hex_alphabet = '0123456789ABCDEF'

def hex(v): return baseN_encode(v, hex_alphabet, 16)

def unhex(s): return baseN_decode(s, hex_alphabet, 16)

###############################################
#
# Misc. utilities
#

def now(): return datetime.datetime.utcnow()

js_utc_fmt = "%a, %d %b %Y %H:%M:%S GMT"

def now_string(): return now().strftime(js_utc_fmt)

def parse_datetime(s): return datetime.datetime.strptime(s, js_utc_fmt)

two_years = 2*365*24*60*60 # In seconds

def wordify(age):
  if age<-5: return 'in the future'
  if age<5: return 'just now'
  if age<120: return str(int(age)) + ' seconds ago'
  age = round(age/60)
  if age<120: return str(int(age)) + ' minutes ago'
  age = round(age/60)
  if age<48: return str(int(age)) + ' hours ago'
  age = round(age/24)
  if age<60: return str(int(age)) + ' days ago'
  age = round(age/30)
  return 'about ' + str(int(age)) + ' months ago'

def pbkdf(s):
  for i in xrange(0,10000): s = hash(s)
  return s[0:32]

############################################
#
#  Keys.
#  SSK = Signing Secret Key, SPK = Signing Public Key
#  ESK = Encryption Secret Key, EPK = Encryption Public Key
#

class PublicKey(object):

  def __init__(self, email, spk, epk):
    self.email = email
    self.spk = spk
    self.epk = epk
    self.id = "%s [%s]" % (self.email, b58(self.spk)[0:10])
    return
  
  def __repr__(self): return "<Public key %s>" % self.id

  def __eq__(self, k): return self.spk==k.spk and self.email==k.email

  def __ne__(self, k): return not self==k

  def serialize(self):
    return 'PK %s %s' % (b58(self.spk[0:32]), self.email)

  def checksig(self, sig):
    return crypto_sign_open(sig, self.spk)
  
  pass

class SecretKey(PublicKey):

  def __init__(self, email, ssk, spk, esk, epk):
    super(SecretKey, self).__init__(email, spk, epk)
    self.ssk = ssk
    self.esk = esk
    return
  
  def __repr__(self): return "<Secret key %s>" % self.id
  
  def serialize(self, pw):
    s = crypto_secretbox(self.ssk[0:32], zeroNonce, pbkdf(pw))
    return 'SK %s %s' % (b58(s), self.email)
  
  def encrypt(self, bytes, nonce, rx_epk):
    return crypto_box(bytes, nonce, rx_epk, self.esk)
  
  def decrypt(self, bytes, nonce, sender_epk):
    return crypto_box_open(bytes, nonce, sender_epk, self.esk)

  def sign(self, msg):
    return crypto_sign(msg, self.ssk)

  def export(self):
    s = 'X-sc4-content-type: public-key v0.2\nFrom: ' + self.email + \
        '\nTimestamp: ' + now_string() + '\n' + b58(self.spk) + '\n'
    sig = signature(hash(s))
    return s + split_into_lines(b58(sig), 44)
  
  pass

def spk2key(email, spk):
  epk = nacl.spk2epk(spk)
  return PublicKey(email, spk, epk)

def ssk2key(email, ssk):
  seed = ssk + bstr('\0'*32)
  [spk, _ssk] = nacl.crypto_sign_keypair_from_seed(seed)
  if _ssk[0:32] != ssk: raise Exception("Keygen sanity check failed")
  esk = hash(_ssk[0:32])[0:32]
  epk = nacl.spk2epk(spk)
  return SecretKey(email, _ssk, spk, esk, epk)

def key_from_seed(email, seed): return ssk2key(email, hash(seed)[0:32])

def random_key(email='test'): return key_from_seed(email, random_bytes(64))

def deserialize_public_key(s):
  type, ks_b58, email = s.split(' ', 2)
  ks = unb58(ks_b58)
  if type=='PK': return spk2key(email, ks)
  return None

def maybe_deserialize_secret_key(s, pw):
  type, ks_b58, email = s.split(' ', 2)
  ks = unb58(ks_b58)
  if type=='PK': return spk2key(email, ks)
  try: seed = crypto_secretbox_open(ks, zeroNonce, pbkdf(pw))
  except: return None
  return ssk2key(email, seed)

def get_passphrase_for_key(s):
  k = maybe_deserialize_secret_key(s, '')
  if k:
    printt("Warning: your secret key is not protected by a pass phrase.")
    return ''
  while 1:
    pw = getpass("Please enter your pass phrase: ")
    k = maybe_deserialize_secret_key(s, pw)
    if k: return pw
    print("Incorrect pass phrase")
    pass
  pass  

def deserialize_secret_keys(l):
  pw = get_passphrase_for_key(l[0])
  return [maybe_deserialize_secret_key(k, pw) for k in l]

def keyfiles(prefix='~/.sc4_'):
  prefix = os.path.expanduser(prefix)
  pkpath = prefix + 'pk'
  skpaths = glob.glob(prefix + 'sk_*')
  if len(skpaths)>1:
    raise Exception("Multiple secret key files found: " + str(skpaths))
  if len(skpaths)==1: return (pkpath, skpaths[0], True)
  return (pkpath, prefix + 'sk_' + b58(random_bytes(10)), False)

my_keys = []
rx_keys = []
my_key = None

def store_secret_keys(skfile):
  global my_keys
  with open(skfile, 'w') as f:
    os.chmod(skfile, 0600)
    pw = getpass("Please enter a pass phrase: ")
    for k in my_keys: f.write(k.serialize(pw) + '\n')
    pass
  return

def store_public_keys(pkfile):
  global rx_keys
  with open(pkfile,'w') as f:
    for k in rx_keys: f.write(k.serialize() + '\n')
    pass
  return
  
def string_prefix_equal(s1, s2):
  n = min(len(s1), len(s2))
  return s1[0:n]==s2[0:n]

def find_keys(s):
  result = []
  for k in itertools.chain(rx_keys, my_keys):
    if s==k.email or string_prefix_equal(s, b58(k.spk)): result.append(k)
    pass
  return result

def generate_key(skfile):
  global my_keys
  print("Provisioning a secret key")
  email = None
  while not email:
    email = raw_input("Please enter your email address: ")
    pass
  my_keys = [random_key(email)]
  store_secret_keys(skfile)
  return

def setup_keys():
  global my_keys, my_key, rx_keys
  pkfile, skfile, flag = keyfiles()
  if not flag: generate_key(skfile)
  with open(skfile) as f: s = f.read()
  l = s.strip().split('\n')
  my_keys = deserialize_secret_keys(l)
  my_key = my_keys[0]
  try:
    with open(pkfile) as f: s = f.read()
    rx_keys = map(deserialize_public_key, s.strip().split('\n'))
  except:
    store_public_keys(pkfile)
    pass
  pass

################################################################
#
# Core SC4
#
def int2bytes(n, n_bytes):
  result = [0]*n_bytes
  for i in range(n_bytes-1, -1, -1):
    result[i] = n&255
    n = n >> 8
    pass
  return bstr(result)

def bytes2int(bytes):
  n = 0
  for byte in bytes: n = (n<<8) + byte
  return n

def u8a_cmp(s1, s2):
  # NOTE! Not constant time!
  if len(s1)!=len(s2): raise Exception("This should never happen")
  if s1>s2: return 1
  if s1<s2: return -1
  return 0

encrypted_header = bstr([0x48, 0x2e, 0x1e, 0, 0, 0])
multi_enc_header = bstr([0x48, 0x2e, 0x26, 0, 0, 0])
signature_header = bstr([0x48, 0x2e, 0x2c, 0, 0, 0])
bundle_header =    bstr([0x48, 0x2e, 0x1b, 0, 0, 0])

def split_into_lines(s, length=72):
  l = []
  while len(s)>length:
    l.append(s[0:length])
    s = s[length:]
    pass
  l.append(s)
  l.append('')
  return '\n'.join(l)

def encrypt(bytes, rx_key):
  global my_key
  bytes = to_bytes(bytes)
  length = int2bytes(len(bytes), 6)
  my_sk = my_key.esk
  my_pk = my_key.epk
  rx_pk = rx_key.epk
  nonce = random_bytes(nacl.crypto_box_NONCEBYTES)
  # Encode the key order in the nonce
  nonce = bytearray(nonce)
  nonce[0] = (nonce[0] & 0xFC) | (u8a_cmp(my_pk, rx_pk) & 3)
  nonce = bstr(nonce)
#  bstr(bytes)
#  bstr(nonce)
#  bstr(rx_pk)
#  bstr(my_sk)
  cipherbytes = crypto_box(bytes, nonce, rx_pk, my_sk)
  return encrypted_header + length + nonce + my_pk + cipherbytes

def decrypt(bytes):
  global my_key
  bytes = to_bytes(bytes)
  length = bytes2int(bytes[6:12])
  if length + 84 != len(bytes): return None
  nonce = bytes[12:36]
  sender_key = bytes[36:68]
  cipherbytes = bytes[68:]
  if (nonce[0] & 3) != (u8a_cmp(sender_key, my_key.epk) & 3):
    print("Warning: key order check failed")
    pass
  content = crypto_box_open(cipherbytes, nonce, sender_key, my_key.esk)
  return [content, sender_key]

def encrypt_pt(bytes, rx_pk):
  bytes = to_bytes(bytes)
  return split_into_lines(b64(encrypt(bytes, rx_pk)))

def decrypt_pt(s):
  return decrypt(unb64(s))

def signature(bytes):
  global my_key
  return crypto_sign(bytes, my_key.ssk)[0:64]

def sign(bytes):
  global my_key
  bytes = to_bytes(bytes)
  length = int2bytes(len(bytes), 6)
  h = hash(bytes)
  sig = signature(h)
  return signature_header + length + my_key.spk + h + sig

def verify_detached_signature(sig, hash, pk):
  return crypto_sign_open(sig+hash, pk)

def verify_signature(binary_sig):
  s = to_bytes(binary_sig)
  length = bytes2int(s[6:12])
  pk = s[12:44]
  h = s[44:108]
  sig = s[108:172]
  try: verify_detached_signature(sig, h, pk)
  except: return False
  return [pk, h]

def sign_pt(bytes):
  global my_key
  bytes = to_bytes(bytes)
  h = hash(bytes)
  sig = crypto_sign(h, my_key.ssk)[0:64]
  segments = ['X-SC4-signed: v0.1 ', b58(my_key.spk), '\n']
  segments.append(split_into_lines(hex(h), 64))
  segments.append(split_into_lines(b58(sig), 44))
  return ''.join(segments)

zeroNonce = to_bytes('\0' * nacl.crypto_secretbox_NONCEBYTES)
zeroKey = to_bytes('\0' * nacl.crypto_secretbox_KEYBYTES)
secretbox_OVERHEADBYTES = 16 # len(crypto_secretbox('', zeroNonce, zeroKey))

def encrypt_multi(bytes, rx_keys):
  global my_key
  key = random_bytes(nacl.crypto_secretbox_KEYBYTES)
  length = int2bytes(len(bytes), 6)
  cipherbytes = crypto_secretbox(bytes, zeroNonce, key)
  segments = [multi_enc_header, length, my_key.epk, cipherbytes,
              crypto_box(key, zeroNonce, my_key.epk, my_key.esk)]
  for rx_key in rx_keys:
    segments.append(crypto_box(key, zeroNonce, rx_key.epk, my_key.esk))
    pass
  return concat(segments)

def decrypt_multi(bytes):
  global my_key
  bytes = to_bytes(bytes)
  length = bytes2int(bytes[6:12])
  if length+108 > len(bytes): return None
  sender_key = bytes[12:44]
  offset = 44 + length + secretbox_OVERHEADBYTES
  cipherbytes = bytes[44:offset]
  while(offset<len(bytes)):
    b = bytes[offset:offset+48]
    offset += 48
    if (len(b) != 48): return None
    try:
      key = crypto_box_open(b, zeroNonce, sender_key, my_key.esk)
      msg = crypto_secretbox_open(cipherbytes, zeroNonce, key)
      return [msg, sender_key]
    except:
      pass
    pass
  return None

def encrypt_multi_pt(bytes, rx_keys):
  return split_into_lines(b64(encrypt_multi(bytes, rx_keys)))

def decrypt_multi_pt(s): return decrypt_multi(unb64(s))

signature_regex = re.compile(
  '''X-SC4-signed: ([v.0-9]+) (.{32,52})
(.{64})
(.{1,64})
(.{44})
(.{20,44})\
''')

def verify_signature_pt(s):
  l = signature_regex.findall(s)
  if not l: return False
  l = l[0]
  pk = unb58(l[1])
  h = unhex(l[2] + l[3])
  sig = unb58(l[4] + l[5])
  try: crypto_sign_open(sig+h, pk)
  except: return False
  return [pk, h]

def combine4sig(filename, mimetype, content):
  h = hex(hash(content)).lower()
  return h + '  ' + filename + '\n' + mimetype + '\n'

def bundle(filename, mimetype, content, sigflag=False):
  if not filename: filename = ''
  if len(filename)>255: filename = filename[0:255]
  # This should never happen, but better safe than sorry
  if len(mimetype)>255: mimetype = mimetype[0:255]
  length = int2bytes(len(content), 6)
  sig = sign(combine4sig(filename, mimetype, content)) if sigflag else ''
  segments = [bundle_header, length, 
              chr(len(filename)), filename,
              chr(len(mimetype)), mimetype,
              chr(len(sig)) , sig,
              content]
  return concat(segments)

def unbundle(bytes):
  content_len = bytes2int(bytes[6:12])
  idx=12
  filename_len = bytes[idx]
  idx += 1
  filename = bytes2string(bytes[idx:idx + filename_len])
  idx += filename_len
  mimetype_len = bytes[idx]
  idx += 1
  mimetype = bytes2string(bytes[idx: idx + mimetype_len])
  idx += mimetype_len
  siglen = bytes[idx]
  idx += 1
  sig = verify_signature(bytes[idx:idx + siglen]) if siglen>0 else None
  idx += siglen
  content = bytes[idx:]
  if content_len != len(content): print("Content length mismatch")
  if mimetype[0:4]=='text': content = bytes2string(content)
  return [filename, mimetype, content, sig]

def bundle_pt(filename, mimetype, content, sigflag):
  is_string = (type(content) in [str, unicode])
  encoding = 'raw' if is_string else 'base64'
  sig = sign_pt(combine4sig(filename, mimetype, content)) if sigflag else ''
  if not is_string: content = split_into_lines(b64(content))
  segments = ['X-SC4-bundle: 0 ', str(len(content)), ' ', encoding,
                '\nX-SC4-filename: ', filename, '\nX-SC4-mimetype: ', mimetype,
                '\n', sig, '\n', content]
  return u''.join(segments)

def unbundle_multi(bytes):
  idx = 0
  result = []
  while idx<len(bytes):
    if bytes[idx:idx+6]!=bundle_header: return False
    idx += 6
    content_len = bytes2int(bytes[idx:idx+6])
    idx += 6
    filename_len = bytes[idx]
    idx += 1
    filename = bytes2string(bytes[idx:idx + filename_len])
    idx += filename_len
    mimetype_len = bytes[idx]
    idx += 1
    mimetype = bytes2string(bytes[idx: idx + mimetype_len])
    idx += mimetype_len
    siglen = bytes[idx]
    idx += 1
    sig = verify_signature(bytes[idx:idx + siglen]) if siglen>0 else None
    idx += siglen
    content = bytes[idx:idx + content_len]
    idx += content_len
    if mimetype[0:4]=='text': content = bytes2string(content)
    result.append([filename, mimetype, content, sig])
    pass
  return result

bundle_regex = re.compile(
'''X-SC4-bundle: ([0-9]+) ([0-9]+) (raw|base64)
X-SC4-filename: (.*?)
X-SC4-mimetype: (.*?)
(X-SC4-signed: (?:.*\\n){5})?
([\s\S]*)$''')

def unbundle_pt(s):
  l = bundle_regex.findall(s)[0]
  version = l[0]
  content_length = l[1]
  encoding = l[2]
  filename = l[3]
  mimetype = l[4]
  sig = verify_signature_pt(l[5]) if l[5] else None
  content = l[6]
  if (encoding == 'base64'): content = unb64(content)
  return [filename, mimetype, content, sig]

#################################################
#
# UI
#

key_regex = re.compile(
r'''(X-sc4-content-type: public-key (\S*)
From: (\S*)
Timestamp: (.*)
(\w{32,44})
(\w{32,44})
(\w{32,44}))
''')

def import_key(s):
  global rx_keys
  l = key_regex.findall(s)
  if not l: return False
  l = l[0]
  version = l[1]
  if version != 'v0.2': raise Exception('Incompatible version')
  email = l[2]
  timestamp = parse_datetime(l[3])
  age = (now() - timestamp).total_seconds()
  if age<0: raise Exception('Invalid key (timestamp is in the future)')
  if age>two_years: raise Exception('Invalid key (too old)')
  spk = unb58(l[4])
  sig = unb58(l[5]+l[6])
  s = '\n'.join(l[0].split('\n')[0:4]) + '\n'
  if not verify_detached_signature(sig, hash(s), spk):
    raise Exception('Invalid key (bad signature)')
  key = spk2key(email, spk)
  if key == my_key: raise Exception("This is your own key.")
  if key in rx_keys: raise Exception("This key is already installed.")
  print("This is a valid key from " + email + " signed " + wordify(age))
  s = raw_input("Do you want to install it in your recipients list? ")
  if (len(s)>0 and s[0].lower()=='y'):
    rx_keys.append(spk2key(email, spk))
    store_public_keys()
    pass
  return (spk, email, age)

preamble = 'This is a secure message produced by SC4.  ' + \
           'See https://sc4.us/ for more information.\n\n'
plen = len(preamble)

def sc4re(s): return re.compile(s, re.DOTALL)

enc_pt_regex = sc4re('^(' + preamble + ')?(\n){0,2}(SC4eAAAA.*)$')

enc_pt_multi_regex = sc4re('^(' + preamble + ')?(\n){0,2}(SC4mAAAA.*)$')

decrypt_op_table = {
  'encrypted' : decrypt, 'encrypted_pt' : decrypt_pt,
  'multi_enc': decrypt_multi, 'multi_enc_pt': decrypt_multi_pt }

unbundle_op_table = { 'bundle' : unbundle, 'bundle_pt' : unbundle_pt }

def sc4_typeof(thing):
  if type(thing) in [str, unicode]:
    if enc_pt_regex.match(thing): return 'encrypted_pt'
    if bundle_regex.match(thing): return 'bundle_pt'
    if signature_regex.match(thing): return 'signature_pt'
    if key_regex.match(thing): return "public_key"
    if enc_pt_multi_regex.match(thing): return "multi_enc_pt"
    return None
  elif type(thing) is Bstr:
    hdr = thing[0:6]
    if hdr == encrypted_header: return 'encrypted'
    if hdr == bundle_header: return 'bundle'
    if hdr == signature_header: return 'signature'
    if hdr == multi_enc_header: return 'multi_enc'
    pass
  return None

def sigcheck(content, sig):
  if not sig: return "No signature"
  [pk, h] = sig
  if not pk: return "Invalid signature"
  if h != hash(content): return "Hash mismatch"
  signer_key = find_keys(b58(pk))
  if not signer_key: signer= "an unkown signer [" + b58(pk) + ']'
  elif signer_key[0] in my_keys: signer = "Myself [" + b58(pk)[0:10] + "]"
  else: signer = signer_key[0].id
  return 'Valid signature from ' + signer

def process_sc4_data(content):
  sc4_type = sc4_typeof(content)
  if sc4_type == 'public_key':
    import_key(content)
    return True
  if len(content)>plen and content[0:plen] == preamble:
    content = content.slice(plen)
    pass
  decrypt_op = decrypt_op_table.get(sc4_type)
  if decrypt_op:
    l = decrypt_op(content)
    if not l: raise Exception("Decryption failed")
    [content, encrypter_pk] = l
    sc4_type = sc4_typeof(content)
    pass
  unbundle_op = unbundle_op_table.get(sc4_type)
  if unbundle_op:
    [filename, mimetype, content, sig] = unbundle_op(content)
    sigcontent = combine4sig(filename, mimetype, content)
    sigstatus = sigcheck(sigcontent, sig)
  else:
    raise Exception('Unknown file format')
  return [filename, mimetype, content, sigstatus]

def process_sc4_file(path):
  with open(path) as f: content = f.read()
  try:
    result = process_sc4_data(content)
    if result==True: return # Public key
    [filename, mimetype, content, sigstatus] = result
    print("File name: " + filename)
    print("Mime type: " + mimetype)
    print("Length: %d bytes" % len(content))
    print(sigstatus)
    s = raw_input("Save this file? ")
    if s and s[0]=='y':
      with open(filename, 'w') as f: f.write(content)
      pass
    pass
  except Exception as e:
    print("Failed: " + str(e))
    pass
  pass

def mimetype(path):
  s = subprocess.Popen(['file', path, '-Ib'],
                       stdout=subprocess.PIPE).stdout.read()
  return s.split(';')[0]

helpmsg = '''Usage summary:
To encrypt a file:  sc4.py -e [file] [recipient]
To sign a file:     sc4.py -s [file]
To sign and encrypt a file:  sc4.py -se [file] [recipient]
To decrypt a file, or install a public key:  sc4.py [file]
To export your public key:  sc4.py -x
'''

def main():
  global my_key
  try:
    [opts, args] = getopt.getopt(sys.argv[1:], 'esx')
    assert(opts or args)
    assert(len(args)<=2)
  except:
    print(helpmsg)
    return
  opts = [opt[0][1] for opt in opts]
  if len(opts)==0:
    for file in args: process_sc4_file(file)
    return
  if 'x' in opts:
    if len(opts)>1:
      print('The -x flag cannot be used with any other options.')
      return
    print(my_key.export())
    return
  if not 'e' in opts: # Sign only
    [filename] = args
    with open(filename) as f: content = f.read()
    bndl = bundle_pt(filename, mimetype(filename), content, True)
    outfile = filename + '.sc4'
    with open(outfile, 'w') as f: f.write(bndl)
    print("Signed content written to " + outfile)
    return
  if len(args)<2:
    print("To encrypt a file you must specify at least one recipient.")
    return
  filename, recipient = args
  keys = find_keys(recipient)
  if not keys: print("Unknown recipient: " + recipient) ; return
  if len(keys)>1:
    print("Recipient is ambiguous.  It could be any of the following:")
    for k in keys: print(k)
    print("Please use the key id to specify the recipient.")
    return
  with open(filename) as f: content = f.read()
  bndl = bundle(filename, mimetype(filename), content, 's' in opts)
  result = encrypt_pt(bndl, keys[0])
  outfile = filename + '.sc4'
  with open(outfile, 'w') as f: f.write(result)
  print("Encrypted content written to " + outfile)
  return

if __name__=='__main__':
  setup_keys()
  main()
  pass
