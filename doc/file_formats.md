# File formats for SC4

### Version 0.2, April 2015

SC4 uses tweetnacl-js as its crypto core.  These file formats are
simply wrappers around the nacl output.  They are designed to be
easily identifiable so that any of them can be provided as input and
SC4 can identify them and do the "right thing" with them.

There are four main file formats:

* Single-recipient encrypted files
* Multi-recipient encrypted files
* Signed files
* Bundle files (a collection of data and associated meta-data)

Each of these formats comes in binary and plain-text (a.k.a. what in the PGP world is called ascii armor) variants.  The plain-text variants of encrypted files are simply the base-64 encoding of the binary data.  But binary bundles and plain-text bundles are different.  The payload of encrypted files are binary bundles, while unencrypted signed data is packaged as plain-text bundles.  The rationale for this design is that SC4 is designed to be as transparent as possible for non-technical users, and so signed but unencrypted plain-text data should be (more or less) human-readable without any decoding

In addition, SC4 defines a standard format for sharing keys, which is a minor variant on the signed file format, but optimized for key data.

SC4's file formats are designed for aesthetics as well as functionality.
Towards this end, SC4 uses three different encodings for binary data:
base64, base58 and base32.  This seems at first to be at odds with the
desire to keep things simple, but it's not as bad as it looks.  Base64
conversion is built in to all browsers, and arbitrary base-N conversion
is not difficult to implement.  Base32 and Base58 are only used for small
data items (keys and signatures) so this code doesn't have to be efficient.

The detailed file formats are:

## Single-recipient encrypted data

The binary format for SC4 encrypted files is:

Byte number	Description

	0-2		Magic number, always 0x482E1E.  (This is "SC4e" in base64.)
	3-5		Version number (currently 0)
	6-11	Content length (excludes header, 6 bytes, big-endian)
	12-35	Nonce (24 bytes)
	36-67	Sender public key (32 bytes)
	68-N	Encrypted data, i.e. the output of nacl.box

The plain-text format for encrypted files is the binary file converted
to base64 with line breaks inserted every 72 characters (though code
should rely on this number being exact).  Thus, a plain-text SC4
encrypted file is always 7-bit clean ascii, and can be identified by
the prefix "SC4e".

The encrypted payload can in principle be anything, but SC4 always
produces files whose payload is a binary bundle.

NOTE:  SC4 encodes the key order in the low bits of the first byte of the nonce as a protection measure against a key swap attack.  See the security audit for more details.

## Multi-recipient encrypted data

Files are encrypted for multiple recipients by encrypting the data with a symmetric key, and then encrypting that key asymmetrically for each recipient.  The binary format is:

	0-2		Magic number, always 0x482E26.  (This is "SC4m" in base64.)
	3-5		Version number (currently 0)
	6-11	Content length (excludes header, 6 bytes, big-endian)
	12-44	Sender public key
	44-N	Encrypted data i.e. the output of nacl.secret_box
	N-EOF Recipient keys (see below)

Each recpient key is the 48-byte output of nacl.box that results from encrypting the symmetric key used to encrypt the data.  These are simply appended after the sender public key.  SC4 will always include a recipient key for the message sender.

Note that multi-recipient encrypted data files are not protected against key swap attacks.  This is a deliberate design decision.  Key-swap attacks present a very minor threat to begin with, and the complexity of dealing with them in multi-recipient scenarios is not worth the effort.  If it is desired the authenticate the content of a multi-recipient encrypted file, the content should be signed.

## Bundle files

A bundle file is a collection of data bundled with associated
metadata, specifically the data's MIME-type, length, file name
(which may be empty if the data did not originate from a file)
and an optional signature.

There are two separate formats for bundle files, one binary, one plain text.

### Binary bundles

The binary format for bundle files is:

	0-2		Magic number, always 0x482E1B.  (This is "SC4b" in base64.)
	3-5		Version number (currently all 0)
	6-11	Content length (excludes header, 6 bytes, big-endian
	12		File-name length (1 byte)
	13-N	File name
	N+1		MIME-type length (1 byte)
	N+2-M	MIME type
	1		Signature flag (0=not signed, 172=signed)
	172		Signature (only if signature flag is not zero, see below)
	M+1-P	Content

NOTE:  SC4 bundle files cannot represent file names (or mime types)
longer than 255 characters.

### Plain text bundles

The plain text format for bundle files is:

	X-SC4-bundle: [version] [content-length] [encoding]
	X-SC4-filename: [file-name]
	X-SC4-mimetype: [mime-type]
	[optional signature]
	
	[content]

where

	[version] is the version number in decimal (currently 0)
	[content-length] is the content length in decimal
	[encoding] is the content-transfer encoding, either 'raw' or 'base64'
	[file-name] is the file name (can be blank)
	[mime-type] is the mime type
	[optional signature] is described below

Example:

	X-SC4-bundle: 0 12 raw
	X-SC4-filename: hello.txt
	X-SC4-mimetype: text/plain
	
	Hello world


### NOTES:

1.  Only UTF-8 text files may be transferred using 'raw' encoding.
Any other data MUST be encoded using base64.

2.  If a binary bundle contains an optional signature, the content that is
signed is NOT the raw data.  Instead, the signature applies to the
following:

	[sha512sum-hex]  [file-name]
	[mime-type]

Where:

	[sha512sum-hex] is the sha512 sum of the actual content being signed,
	represented as a hexadecimal string using lower-case letters

	[file-name] and [mime-type] are the obvious things.

Note that the [sha512sum-hex] is separated from [file-name] by two
spaces, and [file-name] is separated from [mime-type] by a newline.  The
rationale for this somewhat eccentric design is to allow the hash of the
signed content to be independently computed using the following simple
bash script:

	{ shasum -a 512 [file-name]; echo [mime-type]; } | shasum -a 512

Separating the hash from the file type using two spaces reflects the
output format of the shasum program.


## SIGNATURES

SC4 signatures are NACL detached signatures.  As such, they are
self-contained entities that are potentially useful separate from
their associated signed content.  SC4 does not currently use detached
signatures, but they have their own headers to allow for future
expansion.

As with bundle files, signatures have a separate binary and plain-text
format.  Binary signatures look like this:

Byte number	Description

	0-2		Magic number, always 0x482E2C.  (This is "SC4s" in base64.)
	3-5		Version number (currently all 0)
	6-11		Content length (excludes header, 6 bytes, big-endian)
	12-43		Signer public key (32 bytes)
	44-107		SHA512 hash of signed content (64 bytes)
	107-171		Ed25519 signature (64 bytes)

Binary signatures are always 172 bytes long, which is the reason that
the signature flag value in a signed binary bundle that indicates the
presence of a signature is 172.

The plain-text format for a signature is:

	X-SC4-signed: [version] [signer-pubkey-b58]
	[hash1-b32]
	[hash2-b32]
	[sig1-b32]
	[sig2-b32]

Where:

	[version] is the version in decimal (currently 0)
	[signer-pubkey-b58] is the signer's public key encoded in base58
	[hash1-b32] is the first 32 bytes of the SHA512 hash of the signed content
	[hash2-b32] is the second 32 bytes of the SHA512 hash of the signed content
	[sig1-b32] is the first 32 bytes of the Ed25519 signature
	[sig2-b32] is the second 32 bytes of the Ed25519 signature
	[content] is the signed content (see below)

All of the '-b32' values are encoded in base32.  The reason for using base32
here is purely aesthetic.  The signature lines are approximately the same
length as the header line when encoded in base32, which makes the whole
block look more even.

Note that the plain-text signed format does not include the content
length.  This is because plain-text signatures are visible to the
end-user, and signatures are always embedded inside bundle files,
which contain the content length, so including the content length in
the signature is redundant.  The reason the content length IS included
in binary signatures is that this redundancy is not visible to the
end-user.  It also allows binary signatures to be more useful if they
are ever used in a detached format in the futre.


## KEY FILES:

There is one additional special file format in SC4 for sharing public
keys.  Key files are always plain-text.  There is no binary format for
a key file.  The format is:

	X-sc4-content-type: public-key [version]
	From: [user identifier]
	Timestamp: [timestamp]
	[base58 public key]
	[base58 signature]

where

	[user identifier] is free text, but will usually be the users name and/or email address
	
	[timestamp] is the time the key file was created in RFC1124 UTC format (i.e. what is produced by new Date().toUTCString().
	
	[public key] is the user's public signing key (from which the encryption
key can be derived) encoded in base58.
	
	[signature] is the Ed25519 signature of the entire preceding content, base58-encoded, and split into two lines.
