# 20140105
# Jan Mojzis
# Public domain.

import sys
import nacl.raw as nacl
from util import fromhex, flip_bit


def exc():
        """
        """

        a, b, c = sys.exc_info()
        return b


def onetimeauth_bad_test():
        """
        """

        k = nacl.randombytes(nacl.crypto_onetimeauth_KEYBYTES)
        m = nacl.randombytes(1)
        a = nacl.crypto_onetimeauth(m, k)

        #save exception string
        exc_string = ""
        ax = flip_bit(a)
        try:
                a = nacl.crypto_onetimeauth(ax, k)
        except:
                exc_string = exc()

        bad = []
        tmp = {"k":k, "m":m, "a":a}
        tmp["k"] = nacl.randombytes(nacl.crypto_onetimeauth_KEYBYTES + 1)
        bad.append(tmp)
        tmp = {"k":k, "m":m, "a":a}
        tmp["k"] = nacl.randombytes(nacl.crypto_onetimeauth_KEYBYTES - 1)
        bad.append(tmp)
        tmp = {"k":k, "m":m, "a":a}
        tmp["k"] = 0
        bad.append(tmp)
        tmp = {"k":k, "m":m, "a":a}
        tmp["m"] = 0
        tmp["a"] = 0
        bad.append(tmp)

        for tmp in bad:

                try:
                        nacl.crypto_onetimeauth(tmp["m"], tmp["k"])
                except:
                        pass
                else:
                        raise Exception("crypto_onetimeauth accepts incorrect input data")
                try:
                        nacl.crypto_onetimeauth_open(tmp["a"], tmp["k"])
                except:
                        if exc_string == exc():
                                raise
                else:
                        raise Exception("crypto_onetimeauth_open accepts incorrect input data")


def onetimeauth_test():
        """
        """

        return


        mlen = 0
        while 1:
                mlen = mlen + 1 + int(mlen / 16)

                if  mlen > 10000:
                        break

                k = nacl.randombytes(nacl.crypto_onetimeauth_KEYBYTES)
                m = nacl.randombytes(mlen)
                a = nacl.crypto_onetimeauth(m, k)
                nacl.crypto_onetimeauth_verify(a, m, k)

                if mlen < 1:
                        continue

                a1 = flip_bit(a)
                try:
                        nacl.crypto_onetimeauth_verify(a1, m, k)
                except:
                        pass
                else:
                        raise ValueError("forgery")



def onetimeauth_constant_test():
        """
        """

        x = nacl.crypto_onetimeauth
        x = nacl.crypto_onetimeauth_verify
        x = nacl.crypto_onetimeauth_BYTES
        x = nacl.crypto_onetimeauth_IMPLEMENTATION
        x = nacl.crypto_onetimeauth_KEYBYTES
        x = nacl.crypto_onetimeauth_PRIMITIVE
        x = nacl.crypto_onetimeauth_VERSION

def onetimeauth_poly1305_test():
        """
        """

        k =     "eea6a7251c1e72916d11c2cb214d3c252539121d8e234e652d651fa4c8cff880"
        m =     "8e993b9f48681273c29650ba32fc76ce48332ea7164d96a4476fb8c531a1186a"
        m = m + "c0dfc17c98dce87b4da7f011ec48c97271d2c20f9b928fe2270d6fb863d51738"
        m = m + "b48eeee314a7cc8ab932164548e526ae90224368517acfeabd6bb3732bc0e9da"
        m = m + "99832b61ca01b6de56244a9e88d5f9b37973f622a43d14a6599b1f654cb45a74"
        m = m + "e355a5"
        r =     "f3ffc7703f9400e52a7dfb4b3d3305d9"

        a = nacl.crypto_onetimeauth(fromhex(m), fromhex(k))
        if a != fromhex(r):
                raise ValueError("invalid authenticator")

def onetimeauth_poly1305_test2():
        """
        """

        k =     "eea6a7251c1e72916d11c2cb214d3c252539121d8e234e652d651fa4c8cff880"
        m =     "8e993b9f48681273c29650ba32fc76ce48332ea7164d96a4476fb8c531a1186a"
        m = m + "c0dfc17c98dce87b4da7f011ec48c97271d2c20f9b928fe2270d6fb863d51738"
        m = m + "b48eeee314a7cc8ab932164548e526ae90224368517acfeabd6bb3732bc0e9da"
        m = m + "99832b61ca01b6de56244a9e88d5f9b37973f622a43d14a6599b1f654cb45a74"
        m = m + "e355a5"
        a =     "f3ffc7703f9400e52a7dfb4b3d3305d9"

        nacl.crypto_onetimeauth_verify(fromhex(a), fromhex(m), fromhex(k))

def onetimeauth_poly1305_constant_test():
        """
        """

        if nacl.crypto_onetimeauth_BYTES != 16:
                raise ValueError("invalid crypto_onetimeauth_BYTES")
        if nacl.crypto_onetimeauth_KEYBYTES != 32:
                raise ValueError("invalid crypto_onetimeauth_KEYBYTES")
        x = nacl.crypto_onetimeauth
        x = nacl.crypto_onetimeauth_IMPLEMENTATION
        x = nacl.crypto_onetimeauth_VERSION
        x = nacl.crypto_onetimeauth_verify



def run():
        """
        """

        onetimeauth_test()
        onetimeauth_bad_test()
        onetimeauth_constant_test()
        onetimeauth_poly1305_test()
        onetimeauth_poly1305_test2()
        onetimeauth_poly1305_constant_test()


if __name__ == '__main__':
        run()

