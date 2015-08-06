# 20140105
# Jan Mojzis
# Public domain.

import nacl.raw as nacl
from util import fromhex, flip_bit


def scalarmult_bad_test():
        """
        """

        sk = nacl.randombytes(nacl.crypto_scalarmult_SCALARBYTES)
        pk = nacl.crypto_scalarmult_base(sk);
        if len(pk) != nacl.crypto_scalarmult_BYTES:
                raise ValueError("invalid crypto_scalarmult_base output length")

        k = nacl.crypto_scalarmult(sk, pk)
        if len(k) != nacl.crypto_scalarmult_BYTES:
                raise ValueError("invalid crypto_scalarmult output length")

        ss = (
                nacl.randombytes(nacl.crypto_scalarmult_SCALARBYTES + 1),
                nacl.randombytes(nacl.crypto_scalarmult_SCALARBYTES - 1),
                0
        )
        pp = (
                nacl.randombytes(nacl.crypto_scalarmult_BYTES + 1),
                nacl.randombytes(nacl.crypto_scalarmult_BYTES - 1),
                0
        )
        for s in ss:
                try:
                        pk = nacl.crypto_scalarmult_base(s);
                except:
                        pass
                else:
                        raise Exception("crypto_scalarmult_base accepts incorrect input data")
                try:
                        k = nacl.crypto_scalarmult(s, pk);
                except:
                        pass
                else:
                        raise Exception("crypto_scalarmult accepts incorrect input data")
        for p in pp:
                try:
                        k = nacl.crypto_scalarmult(sk, p);
                except:
                        pass
                else:
                        raise Exception("crypto_scalarmult accepts incorrect input data")


def scalarmult_test():
        """
        """

        for i in range(0, 10):

                alicesk = nacl.randombytes(nacl.crypto_scalarmult_SCALARBYTES)
                alicepk = nacl.crypto_scalarmult_base(alicesk);

                bobsk = nacl.randombytes(nacl.crypto_scalarmult_SCALARBYTES)
                bobpk = nacl.crypto_scalarmult_base(bobsk);

                alicek = nacl.crypto_scalarmult(alicesk, bobpk)
                bobk   = nacl.crypto_scalarmult(bobsk, alicepk)

                if nacl.crypto_scalarmult(alicesk, bobpk) != nacl.crypto_scalarmult(bobsk, alicepk):
                        raise ValueError("crypto_scalarmult problem")


def scalarmult_constant_test():
        """
        """

        x = nacl.crypto_scalarmult
        x = nacl.crypto_scalarmult_base
        x = nacl.crypto_scalarmult_BYTES
        x = nacl.crypto_scalarmult_IMPLEMENTATION
        x = nacl.crypto_scalarmult_PRIMITIVE
        x = nacl.crypto_scalarmult_SCALARBYTES
        x = nacl.crypto_scalarmult_VERSION


def scalarmult_curve25519_test1():
        """
        """

        sk = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
        r  = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
        pk = nacl.crypto_scalarmult_base(fromhex(sk))
        if pk != fromhex(r):
                raise ValueError("invalid crypto_scalarmult_base result")


def scalarmult_curve25519_test2():
        """
        """

        sk = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
        r  = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
        pk = nacl.crypto_scalarmult_base(fromhex(sk))
        if pk != fromhex(r):
                raise ValueError("invalid crypto_scalarmult_base result")


def scalarmult_curve25519_test3():
        """
        """

        alicesk = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
        bobpk   = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
        r       = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
        x = nacl.crypto_scalarmult(fromhex(alicesk), fromhex(bobpk))
        if x != fromhex(r):
                raise ValueError("invalid crypto_scalarmult result")


def scalarmult_curve25519_constant_test():
        """
        """

        if nacl.crypto_scalarmult_BYTES != 32:
                raise ValueError("invalid crypto_scalarmult_BYTES")
        if nacl.crypto_scalarmult_SCALARBYTES != 32:
                raise ValueError("invalid crypto_scalarmult_SCALARBYTES")
        x = nacl.crypto_scalarmult
        x = nacl.crypto_scalarmult_base
        x = nacl.crypto_scalarmult_IMPLEMENTATION
        x = nacl.crypto_scalarmult_VERSION

def run():
        "'"
        "'"

        scalarmult_bad_test()
        scalarmult_test()
        scalarmult_constant_test()

        scalarmult_curve25519_test1()
        scalarmult_curve25519_test2()
        scalarmult_curve25519_test3()
        scalarmult_curve25519_constant_test()


if __name__ == '__main__':
        run()

