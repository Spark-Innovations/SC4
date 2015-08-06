# 20140106
# Jan Mojzis
# Public domain.

import sys, binascii
import nacl.raw as nacl
from util import fromhex, flip_bit


def exc():
        """
        """

        a, b, c = sys.exc_info()
        return b



def secretbox_bad_test():
        """
        """

        n = nacl.randombytes(nacl.crypto_secretbox_NONCEBYTES);
        k = nacl.randombytes(nacl.crypto_secretbox_KEYBYTES);
        m = nacl.randombytes(1);

        c = nacl.crypto_secretbox(m, n, k)


        #save exception string
        cx = flip_bit(c)
        exc_string = ""
        try:
                nacl.crypto_secretbox_open(cx, n, k)
        except:
                exc_string = exc()

        bad = []
        tmp = {"c":c, "m":m, "k":k, "n":n}
        tmp["n"] = nacl.randombytes(nacl.crypto_secretbox_NONCEBYTES + 1)
        bad.append(tmp)
        tmp = {"c":c, "m":m, "k":k, "n":n}
        tmp["n"] = nacl.randombytes(nacl.crypto_secretbox_NONCEBYTES - 1)
        bad.append(tmp)
        tmp = {"c":c, "m":m, "k":k, "n":n}
        tmp["n"] = 0
        bad.append(tmp)
        tmp = {"c":c, "m":m, "k":k, "n":n}
        tmp["k"] = nacl.randombytes(nacl.crypto_secretbox_KEYBYTES + 1)
        bad.append(tmp)
        tmp = {"c":c, "m":m, "k":k, "n":n}
        tmp["k"] = nacl.randombytes(nacl.crypto_secretbox_KEYBYTES - 1)
        bad.append(tmp)
        tmp = {"c":c, "m":m, "k":k, "n":n}
        tmp["k"] = 0;
        bad.append(tmp)
        tmp = {"c":c, "m":m, "k":k, "n":n}
        tmp["m"] = 0
        tmp["c"] = 0
        bad.append(tmp)

        for tmp in bad:

                try:
                        nacl.crypto_secretbox(tmp["m"], tmp["n"], tmp["k"])
                except:
                        pass
                else:
                        raise Exception("crypto_secretbox accepts incorrect input data")

                try:
                        nacl.crypto_secretbox_open(tmp["c"], tmp["n"], tmp["k"])
                except:
                        if exc_string == exc():
                                raise
                else:
                        raise Exception("crypto_secretbox accepts incorrect input data")

def secretbox_test():
        """
        """

        mlen = 0
        while 1:
                mlen = mlen + 1 + int(mlen / 16)

                if  mlen > 10000:
                        break

                n = nacl.randombytes(nacl.crypto_secretbox_NONCEBYTES);
                k = nacl.randombytes(nacl.crypto_secretbox_KEYBYTES);
                m = nacl.randombytes(mlen);
        
                c = nacl.crypto_secretbox(m, n, k)
                m1 = nacl.crypto_secretbox_open(c, n, k)

                if m != m1:
                        raise ValueError("bad decryption")

                n1 = flip_bit(n)
                try:
                        m1 = nacl.crypto_secretbox_open(c, n1, k)
                except:
                        pass
                else:
                        print(hexlify(n))
                        print(hexlify(n1))
                        raise ValueError("forgery")

                c1 = flip_bit(c)
                try:
                        m1 = nacl.crypto_secretbox_open(c1, n, k)
                except:
                        pass
                else:
                        raise ValueError("forgery")



def secretbox_constant_test():
        """
        """

        x = nacl.crypto_secretbox
        x = nacl.crypto_secretbox_BOXZEROBYTES
        x = nacl.crypto_secretbox_IMPLEMENTATION
        x = nacl.crypto_secretbox_KEYBYTES
        x = nacl.crypto_secretbox_NONCEBYTES
        x = nacl.crypto_secretbox_PRIMITIVE
        x = nacl.crypto_secretbox_VERSION
        x = nacl.crypto_secretbox_ZEROBYTES
        x = nacl.crypto_secretbox_open


def secretbox_xsalsa20poly1305_test():
        """
        """

        n =     "69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37"
        k =     "1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389"
        m =     "be075fc53c81f2d5cf141316ebeb0c7b5228c52a4c62cbd44b66849b64244ffc"
        m = m + "e5ecbaaf33bd751a1ac728d45e6c61296cdc3c01233561f41db66cce314adb31"
        m = m + "0e3be8250c46f06dceea3a7fa1348057e2f6556ad6b1318a024a838f21af1fde"
        m = m + "048977eb48f59ffd4924ca1c60902e52f0a089bc76897040e082f93776384864"
        m = m + "5e0705"
        r =     "f3ffc7703f9400e52a7dfb4b3d3305d98e993b9f48681273c29650ba32fc76ce"
        r = r + "48332ea7164d96a4476fb8c531a1186ac0dfc17c98dce87b4da7f011ec48c972"
        r = r + "71d2c20f9b928fe2270d6fb863d51738b48eeee314a7cc8ab932164548e526ae"
        r = r + "90224368517acfeabd6bb3732bc0e9da99832b61ca01b6de56244a9e88d5f9b3"
        r = r + "7973f622a43d14a6599b1f654cb45a74e355a5"

        c = nacl.crypto_secretbox(fromhex(m), fromhex(n), fromhex(k))
        if c != fromhex(r):
                raise ValueError("invalid secretbox")


def secretbox_xsalsa20poly1305_test2():
        """
        """

        n =     "69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37"
        k =     "1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389"
        m =     "be075fc53c81f2d5cf141316ebeb0c7b5228c52a4c62cbd44b66849b64244ffc"
        m = m + "e5ecbaaf33bd751a1ac728d45e6c61296cdc3c01233561f41db66cce314adb31"
        m = m + "0e3be8250c46f06dceea3a7fa1348057e2f6556ad6b1318a024a838f21af1fde"
        m = m + "048977eb48f59ffd4924ca1c60902e52f0a089bc76897040e082f93776384864"
        m = m + "5e0705"
        c =     "f3ffc7703f9400e52a7dfb4b3d3305d98e993b9f48681273c29650ba32fc76ce"
        c = c + "48332ea7164d96a4476fb8c531a1186ac0dfc17c98dce87b4da7f011ec48c972"
        c = c + "71d2c20f9b928fe2270d6fb863d51738b48eeee314a7cc8ab932164548e526ae"
        c = c + "90224368517acfeabd6bb3732bc0e9da99832b61ca01b6de56244a9e88d5f9b3"
        c = c + "7973f622a43d14a6599b1f654cb45a74e355a5"

        m1 = nacl.crypto_secretbox_open(fromhex(c), fromhex(n), fromhex(k))
        if m1 != fromhex(m):
                raise ValueError("invalid secretbox")


def secretbox_xsalsa20poly1305_constant_test():
        """
        """

        if nacl.crypto_secretbox_KEYBYTES != 32:
                raise ValueError("invalid crypto_secretbox_KEYBYTES")
        if nacl.crypto_secretbox_NONCEBYTES != 24:
                raise ValueError("invalid crypto_secretbox_NONCEBYTES")
        if nacl.crypto_secretbox_ZEROBYTES != 32:
                raise ValueError("invalid crypto_secretbox_ZEROBYTES")
        if nacl.crypto_secretbox_BOXZEROBYTES != 16:
                raise ValueError("invalid crypto_secretbox_BOXZEROBYTES")

        x = nacl.crypto_secretbox
        x = nacl.crypto_secretbox_IMPLEMENTATION
        x = nacl.crypto_secretbox_VERSION
        x = nacl.crypto_secretbox_open

def run():
        """
        """

        #main
        secretbox_bad_test()
        secretbox_test()
        secretbox_constant_test();

        secretbox_xsalsa20poly1305_test()
        secretbox_xsalsa20poly1305_test2()
        secretbox_xsalsa20poly1305_constant_test();


if __name__ == '__main__':
        run()
