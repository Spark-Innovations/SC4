# NEWS

### August 2015

SC4 now has a command-line version written in Python.  If crypto in
the browser make you queasy, this is for you.  A PGP replacement in
700 LOC (plus TweetNaCl).

### June 2015

SC4 has completed an [independent security audit](audit-report.pdf)
conducted by [Cure53](https://cure53.de).  The money quote:

"Our verdict is that SC4 has developed from a proof-of-concept to an
edgy and unconventional yet reliable crypto tool. If certain
limitations and constraints are respected by its users, SC4 indeed
fills a formerly unpopulated gap in the world of browser crypto."

# SC4 - Secure Communications for Mere Mortals

SC4 is a web application that provides secure encrypted communications
and secure digital signatures.  It is intended to eventually be a
replacement for PGP/GPG.  The main advantages that SC4 claims over PGP
are:

1.  Less code.  The cryptographic core of SC4 is only 33 kilobytes of
minimized Javascript.  Compare that to 247kB for OpenPGP-JS.  A smaller
code base means easier auditability and fewer places that vulnerabilities
can hide.

2.  Smaller keys and signatures.  SC4 uses elliptic curves (specifically
Curve25519 and Ed25519).  The keys for these algorithms are only 256
bits long, compared to 2048 bits (at least) for RSA keys with equivalent
security.

3.  Easier-to-generate keys.  RSA keys require the generation of large
prime numbers, which means you need both a trustworthy source of entropy
and a trustworthy code base to convert that entropy into random primes.
Elliptic curve keys do not require prime numbers.  They can use essentially
any random number as a key, so all that is required to generate a key is a
trustworthy source of entropy.  This elimintes an entire attack surface.

### LICENSE

The cryptographic core of SC4 is [TweetNaCl-js](https://github.com/dchest/tweetnacl-js), a Javascript port of [TweetNaCl](http://tweetnacl.cr.yp.to),
which is in the public domain.  SC4 also uses [JQuery](http://jquery.com),
which is (published under the terms of the MIT license)
[https://jquery.org/license/].  The remainder of the code
(sc4.html, sc4.js, and sc4.css) is copyright (c) 2015 by Spark Innovations
Inc., and is released here under the terms of a
<a rel="license" href="http://creativecommons.org/licenses/by-nc-sa/4.0/">
Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International
License</a>;  All other rights reserved.

### Quickstart

Because SC4 is a security application, there are some subtle issues
that you need to be aware of before trying to run it yourself.  If you
don't want to be bothered, there is a live demo version of SC4 running
at [https://sc4.us/sc4](https://sc4.us/sc4).  If you don't
want to trust this server you can, of course, run SC4 yourself.
See the following section for details on how to do this.

The first time you run SC4 it will ask for your email address.  Note that
this is only used as an identifier for your key.  It is not shared with
anyone until you share your public key.  Once you have entered your email
address, SC4 will automatically provision you with a set of random keys.

To encrypt or sign a file, simply drag-and-drop it into the
application window, or you can type text content directly into the
text area in the application window.  Whether the content is encrypted
or signed or both is controlled by the check boxes at the bottom of
the window.  The encrypted/signed content can be delivered either as a
download file or directly to your native mail client.

To decrypt a file or verify a signature, simply paste the encrypted or
signed content into the text area.  SC4 will automatically regognize
encrypted and signed content and do the Right Thing with it.

To share your public key, click on the "Connect with a new user"
button.  SC4 will automatically compose an email containing your public
key to send to the person you want to share encrypted data with.

To install a public key that you receive from someone else, simply
copy-and-paste the key (the text between the lines --- START KEY ---
and --- END KEY ---) into the text box in the SC4 application.

SC4 has been tested in Safari, Firefox and Chrome, but *not* IE.

### Running SC4 yourself

There are two ways to run SC4, either from an HTTP server, or directly
from a local file.  The latter is, of course, more convenient, but making
this secure is tricky.  This is because SC4 normally stores your keys in
your browser's localStorage, and most browsers do not correctly implement
same-origin policies for FILE: URLs.  The upshot is that it is trivial to
craft malicious Javascript that can steal your SC4 keys if you run it from
a FILE: URL.

The solution to this problem is to generate a local copy of SC4 that has
your keys embedded directly inside it.  Doing this involves two steps:

1.  Run 'make' to generate a self-contained copy of SC4 that includes all
of the Javascript and CSS in a single file called sc4z.html.

2.  Open this file (sc4z.html) in your browser.  SC4 will
automatically figure out that it is being run from a FILE: URL and
will generate a copy of itself with embedded keys.  The generated file
will have a randomized file name as an extra measure of protection
(because it turns out to be easy to steal files from your computer if
the attacker knows the file name).

This is a bit cumbersome, but you only have to do it once.  Needless to
say, you should not share your copy of SC4 with anyone.  (You can, however,
safely share sc4z.html.)

If you want to run SC4 from a server, simply copy the contents of the
git repository to the server.  SC4 runs entirely in the browser.  The
only reason to have a server in the loop is to provide an origin so
that keys can safely be stored in localStorage.  Of course, this means
that you MUST serve SC4 from an HTTPS URL, not an HTTP URL.  But if
you didn't already know that then you should probably just use the
live demo and not try to run SC4 yourself.

### Contact info

Please send feedback, including bug reports, to sc4@sc4.us.

My public key is:

	---START KEY---
	X-sc4-content-type: public-key v0.2
	From: ron@spark-innovations.com
	Timestamp: Wed, 22 Jul 2015 19:55:37 GMT
	C74bKoKVF7fU9YPg3T93KjayDgw1xBg4hiX8fgyKEyrP
	2GzixEkG2rqAVeJiTQSbgPA7LiBPH2UcnruhGFBPMkK6
	BpPtsVynbe7Ko2DicHPMNgPgSRkSPmh1qaCiUbZNepdk
	---END KEY---
