#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Build and install the TweetNaCl wrapper.
"""

from __future__ import print_function
import sys, os
from distutils.core import setup, Extension, Command
from distutils.util import get_platform

def setup_path():
    # copied from distutils/command/build.py
    plat_name = get_platform()
    plat_specifier = ".%s-%s" % (plat_name, sys.version[0:3])
    build_lib = os.path.join("build", "lib"+plat_specifier)
    sys.path.insert(0, build_lib)

nacl_module = Extension('nacl._tweetnacl',
                        ["tweetnaclmodule.c", "tweetnacl.c", "randombytes.c"],
                        extra_compile_args=["-O2",
                                            "-funroll-loops",
                                            "-fomit-frame-pointer"])

class Test(Command):
    description = "run tests"
    user_options = []
    def initialize_options(self):
        pass
    def finalize_options(self):
        pass

    def run(self):
        setup_path()
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "test"))
        import test_box; test_box.run()
        import test_hash; test_hash.run()
        import test_onetimeauth; test_onetimeauth.run()
        import test_scalarmult; test_scalarmult.run()
        import test_secretbox; test_secretbox.run()
        import test_sign; test_sign.run()
        import test_stream; test_stream.run()
        import test_verify_16; test_verify_16.run()
        import test_verify_32; test_verify_32.run()

class Speed(Test):
    description = "run benchmark suite"
    def run(self):
        setup_path()
        from timeit import Timer

        def do(setup_statements, statement):
            # extracted from timeit.py
            t = Timer(stmt=statement, setup="\n".join(setup_statements))
            # determine number so that 0.2 <= total time < 2.0
            for i in range(1, 10):
                number = 10**i
                x = t.timeit(number)
                if x >= 0.2:
                    break
            return x / number

        def abbrev(t):
            if t > 1.0:
                return "%.3fs" % t
            if t > 1e-3:
                return "%.1fms" % (t*1e3)
            return "%.1fus" % (t*1e6)


        IM = "from nacl import raw; msg='H'*1000"

        # Hash
        S1 = "raw.crypto_hash(msg)"
        print(" Hash:", abbrev(do([IM], S1)))

        # OneTimeAuth
        S1 = "k = 'k'*raw.crypto_onetimeauth_KEYBYTES"
        S2 = "auth = raw.crypto_onetimeauth(msg, k)"
        S3 = "raw.crypto_onetimeauth_verify(auth, msg, k)"
        print(" OneTimeAuth:", abbrev(do([IM, S1], S2)))
        print(" OneTimeAuth verify:", abbrev(do([IM, S1, S2], S3)))

        # SecretBox
        S1 = "k = 'k'*raw.crypto_secretbox_KEYBYTES"
        S2 = "nonce = raw.randombytes(raw.crypto_secretbox_NONCEBYTES)"
        S3 = "c = raw.crypto_secretbox(msg, nonce, k)"
        S4 = "raw.crypto_secretbox_open(c, nonce, k)"
        print(" Secretbox encryption:", abbrev(do([IM, S1, S2], S3)))
        print(" Secretbox decryption:", abbrev(do([IM, S1, S2, S3], S4)))

        # Curve25519
        S1 = "pk,sk = raw.crypto_box_keypair()"
        S2 = "nonce = raw.randombytes(raw.crypto_box_NONCEBYTES)"
        S3 = "ct = raw.crypto_box(msg, nonce, pk, sk)"
        S4 = "k = raw.crypto_box_beforenm(pk, sk)"
        S5 = "ct = raw.crypto_box_afternm(msg, nonce, k)"

        print(" Curve25519 keypair generation:", abbrev(do([IM], S1)))
        print(" Curve25519 encryption:", abbrev(do([IM, S1, S2, S3], S3)))
        print(" Curve25519 beforenm (setup):", abbrev(do([IM, S1, S2, S3], S4)))
        print(" Curve25519 afternm:", abbrev(do([IM, S1, S2, S3, S4], S5)))

        # Ed25519
        S1 = "vk,sk = raw.crypto_sign_keypair()"
        S2 = "sig = raw.crypto_sign(msg, sk)"
        S3 = "raw.crypto_sign_open(sig, vk)"

        print(" Ed25519 keypair generation:", abbrev(do([IM], S1)))
        print(" Ed25519 signing:", abbrev(do([IM, S1], S2)))
        print(" Ed25519 verifying:", abbrev(do([IM, S1, S2], S3)))


setup (name = 'tweetnacl',
       version = '0.1',
       author      = "Brian Warner, Jan Mojžíš",
       description = """Python wrapper for TweetNaCl""",
       ext_modules = [nacl_module],
       packages = ["nacl"],
       package_dir = {"nacl": "src"},
       cmdclass = { "test": Test,
                    "speed": Speed },
       )
