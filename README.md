### SC4 - Secure Communications for Mere Mortals

SC4 is a web application that provides secure encrypted communications and
secure digital signatures.  It is intended to be a replacement for PGP/GPG.
The main advantages that SC4 claims over PGP are:

1.  Less code.  The cryptographic core of SC4 is only 33 kilobytes of
minimized Javascript.  Compare that to 247kB for OpenPGP-JS.  A smaller
code base means easier auditability and fewer places that vulnerabilities
can hide.

2.  Smaller keys and signatures.  SC4 uses elliptic curves (specifically
Curve25519 and Ed25519).  The keys for these algorithms are only 128
bits long, compared to 2048 bits (at least) for RSA keys with equivalent
security.

3.  Easier-to-generate keys.  RSA keys require the generation of large
prime numbers, which means you need both a trustworthy source of entropy
and a trustworthy code base to convert that entropy into random primes.
Elliptic curve keys do not require prime numbers.  They can use essentially
any random number as a key, so all that is required to generate a key is a
trustworthy source of entropy.  This elimintes an entire attack surface.

*** IMPORTANT NOTE ***

This is a BETA release of SC4.  We are in the process of going through an
independent security audit, but this has not yet been completed.  Until it
has, SC4 should not be used for mission-critical applications.

### LICENSE

The cryptographic core of SC4 is [TweetNaCl-js](https://github.com/dchest/tweetnacl-js), a Javascript port of [TweetNaCl](http://tweetnacl.cr.yp.to),
which is in the public domain.  SC4 also uses [JQuery](http://jquery.com),
which is (published under the terms of the MIT license)
[https://jquery.org/license/].  The remainder of the code
(sc4.html, sc4.js, and sc4.css) is copyright (c) 2015 by Spark Innovations
Inc., all rights reserved, and is released here under the terms of a
<a rel="license" href="http://creativecommons.org/licenses/by-nc-sa/4.0/">
Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International
License</a>.

### Quickstart

Download the code and open sc4.html in your favorite browser.  The code has
been tested on Firefox, Chrome and Safari, but *not* Internet Explorer.  The
code will run standalone.  You don't need to be connected to the internet.

The first time you run SC4 it will ask for your email address.  Note that
this is only used as an identifier for your key.  It is not shared with
anyone until you share your public key.  Once you have entered your email
address, SC4 will automatically provision you with a set of random keys.

The first thing you need to do to use SC4 is to share public keys.  To share
your key, click on the "Connect with a new user" button.  SC4 will
automatically compose an email containining your public key.  Send this
to the person you want to communicate with, and ask them to do the same.

To install a public key, simply copy-and-paste the key (the text between
the lines --- START KEY --- and --- END KEY ---) into the text box in the
SC4 application.

SC4 performs four basic functions: encryption, decryption, signing, and
signature verification.  In general, to perform any of these functions you
just enter or copy-and-paste text into the text box, or drag-and-drop a file
into the browser window.  SC4 should figure out what kind of file you have
given it and automatically do the Right Thing.

By default, SC4 will encrypt but not sign the data that you give it.
Encryption is targeted so that only the person for whom a file is encrypted
is able to decypt it.  This is the reason you need to install the public keys
of the person you want to communicate with before you can encrypt a file for
them.

### Contact info

Please send feedback, including bug reports, to sc4@sc4.us.

My public key is:

    ---START KEY---
    X-sc4-content-type: public-key
    From: sc4@sc4.us
    Timestamp: Tue, 17 Mar 2015 22:12:24 GMT
    AocfySUwQXhMGFezXFEJKPL77AoMLupwREpCeOZgRB4=
    RBDrBehSHbm1x/o+yPFrpdD6kWwSV3QQI8S/y8MdeEg=
    CNDBlfC7J78l2q14tUPyhEdnWHkXJEbLUeCev9HLUGvK
    ED1XUmAByEwfTNCaSdx8AP1HASmB+OHbUVzK/JBRDA==
    ---END KEY---
