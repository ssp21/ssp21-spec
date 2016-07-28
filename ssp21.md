---
title:      'SSP21'
author:     'Adam Crain (jadamcrain@automatak.com)'
revision:   'pre-release'
date:       'n/a'
---

# Introduction

Secure SCADA Protocol (SSP) is cryptographic wrapper designed to secure point-to-multipoint serial protocols, or to act 
as a security layer for new SCADA applications. It is intended to fill a gap where existing technologies like TLS are 
not applicable, or require too much processing power or bandwidth. It can be used as a protocol agnostic bump in the 
wire (BitW) at outstation endpoints or as a bump in the stack (BitS) on the master or the outstation. No provision is 
made for retrofitting masters with a BitW as we assume that masters can be much more easily upgraded than outstations.

# Requirements

The following requirements guided the design of the specification and the selection of appropriate companion standards.

## Basis of trust - "Utility PKI"

All trust in the system are based on a Public Key Infrastructure (PKI) wholly controlled by the asset owner. A more 
efficient certificate format than [x509](https://tools.ietf.org/html/rfc5280) will be utilized to reduce bandwidth 
consumption for low bit rate serial networks. Asymmetric key algorithms for key derivation and/or signing will use 
primitives substantially more efficient than RSA encryption.

## Asymmetric Certificate Revocation

Master certificates (certificates that identify masters to outstations), will support a fast expiration scheme in
addition to  explicit revocation. This works well in an operational environment where the utility has a reliable and 
isolated IP network between an online authority and multiple master stations. An intermediate authority private key can
be used to periodically renew master certificates. Using CRLs with outstations may be undesirable as outstations 
may not be able to reach them on a serial channel, and masters would have to push revocation notifications down to each
endpoint and ensure that they arrive. Outstations would then have to persist these CRLs in non-volatile memory.

This scheme requires that outstations have access to an out-of-band time synchronization mechanism such as GPS, local 
NTP via GPS in a substation, or WWVB. Alternatively, over TCP networks, outstations could check an online CRL.

Outstation certificates (certificates that identify outstations to masters) will be longer lived, and will be revoked 
using an online CRL accessible to the masters in the system over a traditional TCP network.

## Simplicity of implementation

The encodings, state machines, and other technical details of the protocol shall, above all else but without 
sacrificing security, endeavor to be as simple to implement as possible. Complexity, bells and whistles, and unneeded 
features inevitably lead to bugs both in specification and implementation.

A reference implementation shall be developed to inform the evolving design, and shall not be an afterthought. Too 
often standardization efforts spend too much time on paper, only to lead to designs that are difficult to implement 
correctly.

## Use only strong vetted cryptography

SSP21 shall only use algorithms that have received prolonged and intense scrutiny from the crypto community. This does 
not mean that all algorithms need to be NIST approved. Algorithms that are simpler to implement and/or have variations 
with provably constant-time implementations should be preferred.

## Extensible only to the extent necessary

* Endpoints shall be able to identify the protocols version to each other during key exchange.
* Must be secure against protocol downgrade attacks via a mechanism that fully authenticates the handshake.
* The protocol shall use security-suite specifications to allow new algorithms to be used in future versions, or to 
provide more than one option for when algorithms, inevitably, are compromised.
* The number of initial security suites will be limited to one or two, and will only support authentication.

## Authentication

All messages shall be authenticated. Each endpoint in the session shall be able to unambiguously determine that a 
session message comes from the other endpoint. The authentication mechanism shall automatically provide message 
integrity and protection from spoofing and MitM attacks.

This authentication will ensure that a particular SCADA master is talking to a particular outstation. In other words, 
it shall only secure the communication link and will not authenticate individual users or operators of the system. Role 
Based Access Control (RBAC) and auditing of users is best done at the platform level, and is outside the scope of 
SSP21. Individual SCADA vendors are free to use different technologies (such as Active Directory, RSA, LDAP, Kerberos, 
etc.) to manage users at the platform level.

Particular BitS implementations could potentially use some metadata in certificates to limit or constrain what is 
allowed during a particular communication session. How this metadata is used or configured to limit permissions for a 
particular protocol is outside the scope of SSP21<!-- RLC: This implies that the "lite" certificate format allows for 
extensions -->.

## Protection from replay

Both endpoints of the session shall be able to detect replayed session messages. Although the protocol needs to be 
secure from replay, it does not necessarily need to ensure that all messages are delivered in order, as SCADA protocols
like DNP3 automatically handle retries at a higher level. The protocol will support two modes: one that strictly
enforces packet order over (TCP) and a more tolerant mode that allows any new (non-replayed) packet to pass over serial
or UDP. 

## Session message “time of validity”

Since SSP21 is designed to protect control protocols with particular timing constraints, undesirable behavior could 
occur if an attacker held back a series of authenticated control messages and then replayed them in rapid succession. 
To eliminate this mode of attack, both parties record their own relative time-base in milliseconds during session 
establishment. Session messages shall include a timestamp in milliseconds since this common time point that indicates
the last possible moment when the packet should be accepted.

Implementations will have to make these timing parameters configurable so that they can be tuned for the latency and 
bandwidth of any particular network. As relative clock drift can occur, sessions may need to renegotiated more 
frequently or the configurable validity window of session messages made larger[^ieee1711].

[^ieee1711:] This mode of operation is similar to IEEE 1711-2010, but without the complexity of having multiple units 
of time. DNP3 (IEEE 1815-2012) Secure Authentication is an example of a protocol with a one pass authentication 
(aggressive mode) that lacks this protection. Attackers can hold back multiple messages and then replay them in rapid 
succession within a single session.

## Optional encryption

The secure operation of SCADA system does not require confidentiality of session traffic under all, or even most, 
circumstances. Reasons to prefer unencrypted sessions include the ability to inspect traffic with IDS/IPS and denying a 
potentially opaque tunnel usable by an attacker.

Certain systems may exchange sensitive information and require session confidentiality. SSP21 shall use a security 
suite specification and encodings that allow for encrypted sessions in the future. The session key exchange mechanism 
shall support forward secrecy.

## Support bump in the wire retrofits

The outstation implementations of the protocol shall be capable of being deployed as a bump in the wire (BitW) or 
integrated into endpoints as a bump in the stack (BitS).  BitS integration is preferred, but it is understood that BitW 
implementations are necessary to retrofit legacy components during transitions.

Requiring a BitW implementation only for outstations and not masters simplifies requirements as the BitW needn’t be 
protocol-aware. It can be configured with the static addresses of the outstation and master, and ignore protocol 
messages addressed for other nodes. In BitW and BitS implementations, all cryptographic operations including key 
negotiation and authentication will occur at the bump.

## Support serial and IP

Supporting multi-drop serial means that frames must be addressed in some manner. SSP21 will use 16-bit addressing as 
this accommodates the addressing scheme used for common existing SCADA protocols. SSP21 will have its own delimiters or 
length fields, and will use some type of non-cryptographic error detection so that environmental noise is 
probabilistically filtered out at a level below cryptographic checks for deliberate tampering.

For some protocols, this new secure serial layer could act as a replacement for redundant functionality in existing 
protocols. For example, the DNP3 link-layer and transport function could be completely removed in BitS implementations 
and replaced with the SSP21 crypto and framing layers. SSP21 could also fully wrap the existing protocols, but removing 
redundancy in certain implementations could provide significant bandwidth savings.

<!--- RLC: While true, I think this may hinder adoption in that market, as it would mean that an SSP21-enhanced protocol 
is no longer interoperable with the  original protocol, but devices will still need to implement the original protocol. 
That means more code (two link layers for the same protocol), more testing, more complex procurement, more complex 
deployment, ...At least in the beginning, I think we should not expect anything other than BitW on the outstation 
end... -->

Out-of-band messages like session key establishment, heartbeats, etc. can only be initiated from the SCADA master side 
when it attempts to send a normal protocol message. This is because in half-duplex communications the wrapper cannot 
squelch a reply from a remote by inappropriately using the channel.

## Low overhead

Security is not a zero-cost protocol feature. Inevitably adding a security sub-layer will require more bandwidth, 
increase latency, and put a computational burden on endpoints. SSP21 will endeavor to minimize these overheads.

* **reduced latency** – BitS implementations have a significant advantage in this regard over BitW. HMAC hold back 
can double latencies in BitW integrations as the entire packet must be received and verified before the first payload 
byte can be emitted. Some tricks could be played with asymmetric baud rates to minimize this effect. MAC algorithms 
should be used for which hardware acceleration exists.

* **reduced bandwidth** – It is not uncommon for serial SCADA systems to operate at rates as low as 1200 BPS. 
Cryptographic encodings need to be sensitive to tight polling margins. HMACs can be truncated (per [NIST 
guidelines](http://csrc.nist.gov/publications/nistpubs/800-107-rev1/sp800-107-rev1.pdf)) to reduce overhead. BitS
integration may be able to remove redundant layers provided by both the SSP21 and the wrapped protocol. An efficient\
certificate format that utilizes Elliptic Curve Cryptography (ECC) public keys will be used to reduce certificate sizes.

# Utility PKI

While the primary aim of this specification is describe the protocol in sufficient detail that it can be faithfully 
implemented, it is important to describe the broader system in which the protocol is designed to operate.

![Components of the system relevant to SSP21](svg/network_architecture.png){#fig:networkarchitecture}

SSP21 is designed to secure the communication link between one or more SCADA masters and some number of field sites as 
shown in figure @fig:networkarchitecture. It accomplishes this using a PKI wholly owned and controlled by the utility. 
Ideally, SCADA masters and field assets (RTUs, gateways, IEDs, etc.) generate a public / private key pair locally, 
never share the private key with another entity (human or machine), and can freely disseminate the public key for the 
purposes of certificate generation. The primary role of any PKI is to reduce the complexity of key management by 
requiring parties to only place their trust in a central signing authority. The identity of all other parties is then 
established via certification from this authority. To understand the attractiveness of such an architecture, it useful 
to compare it is to a few alternatives.

## Alternative: Symmetric keys only

In this architecture, each communication link has a unique symmetric key that both parties possess prior to any 
communication occurring. Security is achieved in knowing that only the other end of the channel possesses the same key. 
In a typical SCADA point-to-multipoint scenario, best practice dictates that there be a unique symmetric key for each 
outstation (N), and the master would possess a copy of all N keys for the outstations with which it communicates. The 
primary advantage of such a system is conceptual simplicity, but the system is difficult to use at scale for several of 
reasons:

* If multiple masters are needed for redundancy purposes, the keys must be shared with the master increasing the attack 
surface and the risk of compromise, or the number of keys in the system must be doubled from N to 2N.

* This type of an architecture does a poor job of limiting access to sensitive key data. To commission a new field 
asset, the key must be entrusted to field personnel, possibly contractors.

* Compromise of a field asset always requires that the channel be rekeyed. Compromise of the master requires that the 
entire system be rekeyed.

## Alternative: Asymmetric keys without an authority

In this architecture, each communication node has an asymmetric public / private key pair. It is free to disseminate 
the public key, and each node must possess the public key for every other node with which it communicates. This 
architecture better addresses some of the concerns presented with the symmetric key only architecture, namely:

* Multiple masters can be commissioned without doubling the number of keys in the system, however, each outstation must 
possess the public key of each master with which it must communicate.

* Only the master's public key(s) need to be shared with commissioning personnel. Each outstation can also secure its 
private key, and only share the public key. This makes tampering from insiders slightly more difficult than in the 
symmetric only scheme.

A number of potential problems still remain:

* Compromise of a master still results in having to update the master's public key on each outstation.

* Installing or authorizing additional masters requires either sharing the master private key with the backup master, 
or installing an additional master public key on all outstations.

## Small vs big systems

Small systems with a limited number of outstations may function perfectly well with either the symmetric or asymmetric 
key scenarios described above.

While SSP21 does not support symmetric pre-shared keys, it can operate in an authority-less mode by using what is 
commonly referred to as "self-signed certificates". This mode is no different than the asymmetric case described above, 
and requires each party have the public key of party with which it communicates. Larger systems can benefit from a full 
PKI where the downsides above can be truly problematic.

## The role of the authority

The authority in the system possesses a private asymmetric key that it uses to sign certificates.  Certificates consist 
of the following elements:

* A public asymmetric key
* Metadata associated with the public key (e.g. id, validity windows, serial numbers, etc)
* A digital signature over all other data calculated using the authority private key.

Creating and signing certificates is one of the primary roles of the authority.  In its simplest form, this might 
consist of some cryptographic command line tools on a properly isolated server with a private key and a set of humans 
with access to this server.  Such a basic system might work for small systems.

### Issuing outstation certificates

There are far more outstations in any given SCADA system than the number of masters. Such a statement might seem 
trivial, however, it is an important insight into how the process of enrollment needs to be streamlined for large 
systems. In such systems, the authority is envisioned to have a hardened web portal accessible from the corporate LAN. 
This level of access allows authorized personnel to reach the portal using cellular IP technologies and a VPN.

The web portal would likely be secured using a commodity TLS certificate and the users authenticated using strong 
passwords and a second factor like a security token. The authority itself would likely reside in the DMZ, thus proper 
procedures will need to be followed to provide this access. Prior to commissioning a new field asset, a privileged user 
would grant the user commissioning the field asset the permission to generate a certificate for the asset. Thus the 
authority would maintain a database of a few items:

* An editable set of field assets that will require enrollment.
* A set of users
* A set of permissions for the users (user editing, key generation by asset, etc).
* Properly hashed/salted passwords for the set of users that follow a strong password policy 
<!--- rlc: I don't see why 
the authority database would have a password for the user: I would expect the user to be authenticated through an LDAP 
or similar mechanism and have the appropriate access to the database, which would only need to contain information 
necessary to audit enrollment and the data for the device. -->.
* A system for 2-factor authentication of the users like a key token.

The database will already be configured by the system administrator with all of the authorized metadata for each 
certificate in question. The only piece of information the person generating the outstation certificate needs to 
provide once properly logged in is the outstation public key. Outstation certificates will be very long lived, likely 
for the lifetime of the equipment. A cryptographic break in the algorithm underlying the certificate signature will 
require that a new certificate be installed, so this algorithm should be chosen prudently.

It's important to note that while the authority could be a standalone application with its own complete database of 
outstations, masters, and users, it might also leverage data available in other systems. For instance, an LDAP server 
or other enterprise identity system could be used to establish the identity and permissions of users <!--- rlc: This 
should be the default way of doing things. The alternative above could be proposed as an alternative (i.e. invert 
places with here) but the default suggestion should be for the authority to only manage devices. -->. The authority 
might also be capable of keeping its database of outstations in the system synchronized with a utility EMS.

Allowing system administrators to pre-configure which users can generate certificates for which outstations and 
providing access to this part of the authority through proper safeguards will substantially streamline the process of 
enrollment and reduce the extent to which adding security impacts operations. The portal approach also limits direct 
access to signing keys and provides a central point for creating an audit trail regarding certificate generation.

### Revoking outstation certificates

The master(s) will be capable of reaching a CRL on the authority and will be responsible for checking it at a 
reasonable interval. The compromise of a single outstation private key is small breach compared to other attack 
scenarios. Nevertheless, a mechanism must be in place to allow for revocation.

### Issuing master certificates

The recommended way to issue master certificates is machine-to-machine (M2M) communication directly from the master to 
the authority. The reason for this asymmetry is that on a serial network, there is no path for an outstation to reach a 
certificate revocation list (CRL), and thus a fast expiration scheme allows master certificates to be "revoked" by 
virtue of the fact that the authority can refuse to renew them. This expiration should happen on the timescale of hours 
and not days.

The compromise of a master private key is a significant security event, since that master may be authorized to control 
a significant amount of field equipment. There is no fast mechanism for informing outstations on a serial network that 
a master has been compromised, thus some other mitigation will be needed until the affected certificate expires 
naturally.

The communication link between the authority and the masters can be secured using a separate, more-traditional PKI. 
Since the number of masters in the system is low, it could even use pairs of self-signed certificates where the 
authority has the public key of every master it needs to authorize. This public key would be used to authenticate the 
certificate sign request for the certificate to be used to authenticate the master to the outstation.

Unlike the web portal link to the authority, this M2M link need only be authenticated since no user credentials or 
critical information will flow over it. TLS with NULL encryption and a strong authentication mechanism would be 
sufficient and would allow NSM tools to continuously inspect and monitor this traffic. <!--- rlc: While this is true, I 
see no reason to mention it if we assume the master has a fast internet connection and sufficient processing power to 
do the necessary encryption (which should normally be the case). -->

# The Link Layer

SSP21 specifies a two layer architecture for delivering secure data to the user layer.

![SSP21 stack - The link and crypto layers are defined in this specification](svg/stack.png){#fig:stack}

The link layer provides three features: 

* **Framing** - A procedure is defined to identify a frame from a stream of bytes.
* **Addressing** - The frame contains source and destination addresses for the transmitter and receiver.
* **Error detection** - All of the header fields and payload are covered by a cyclic redundancy check (CRC). 

Since this functionality does not  have any cryptographic protections, it is designed with simplicity in mind and is
completely stateless.  The non-cryptographic hash function (like a CRC) is important at this layer to detect data
corruption from random sources (EMF, cosmic rays, etc).  This check is intended to prevent randomly corrupted payloads 
from  reaching the cryptographic layer. This prevents "tampering" false positives from occurring at the cryptographic 
layer which would require a completely different organizational response than from a sudden increase line noise.

**Note: We are currently consulting with an expert on error detection algorithms and CRCs. A recommendation for the
 frame format and CRC algorithm will come from this engagement.**

<!--
```
[ start ][ destination ][ source ][ length ][ payload ... ][ CRC ]
```
-->

The frames consist of the following fields. All multi-byte integer fields are encoded in big endian for consistency 
with the Noise specification and the cryptographic layer. 

**destination** (2-bytes) - The destination field encodes the address of the intended recipient of the frame. Devices 
shall always set this field to the address of the intended recipient when transmitting. When receiving a frame, devices 
shall not do any further processing of frames with an unknown destination address.

**source** (2-bytes) - The source field encodes the address of the transmitting party. The usage of this field may 
depend on the application layer of wrapped protocol.

**length** (2-bytes) - Length of the message, including the header and CRC, in bytes.

# Cryptographic Layer

The cryptographic layer is inspired by the [Noise](http://noiseprotocol.org), a self-described framework for building 
cryptographic protocols. This specification picks from all the available options and modes within Noise to create a 
subset appropriate for wrapping ICS serial protocols. This specification is self-contained: reading the Noise 
specification is not required to understand or implement SSP21.

Modifications to Noise include:

* A single handshake pattern is used, therefore the concept of handshake patterns have been removed entirely.
* Modifying Noise to support authentication only (handshake and session)
* Message identifiers to make session renegotiation possible on serial networks
* Initiator-specified cipher suites to allow masters to specify sets of cryptographic algorithms
* Selecting a specific handshake mode that will be used in all applications
* Definitions for handshake payload data including relative time bases and certificate formats
* Static public keys are always transmitted as part of a certificate

## Algorithms

SSP21 uses a number of cryptographic algorithms. They are described here within the context of the functionality they 
provide. SSP21 initially specifies a smaller subset of algorithms available in Noise.

The following notation will be used in algorithm pseudo-code:

* The **||** operator denotes the concatenation of two byte sequences.
* The **[b1, b2, .. bn]** syntax denotes a, possibly empty, byte sequence.
* The **len()** function returns the length of a byte sequence as a 2-byte unsigned big endian byte sequence.
* The **++** operator applied after an integer variable implements post-increment, namely it returns the current value 
and then increments it by 1.


### Diffie Hellman (DH) functions

SSP21 currently only supports Curve25519 for session key agreement. It is described in detail in [RFC 
7748](https://www.ietf.org/rfc/rfc7748.txt). Curve448 will likely be supported in the future.

| DH Curve       | length (*DHLEN*)       |
| ---------------|------------------------|
| Curve22519     | 32                     |

All DH curves will support the following two algorithms with the key lengths specified above.

* GeneratePublicKey(key_pair) - Given a key pair, generate a random private key and calculate the corresponding public 
key. 

<!--- RLC: Why ``given a key pair''? Noise defines GenerateKeyPair() that doesn't take any parameters and generates a 
key pair. I don't see anything that generates a new key pair from an existing one..? (Don't see it in the RFC either) 
-->

<!-- JAC: This is because the in Noise's definition the of the function, the key pair argument is mutable. I'm not 
particularly fond of all the definitions in Noise, and we can change them --> 

* DH(key_pair, public_key) - Given a local key pair and remotely supplied public key, calculate a sequence of bytes of 
length _DHLEN_.

<!--- RLC: Should perhaps mention, as in the RFC, to check for all zeroes. -->
<!--- JAC: Yes, definitely. Keeping these comments here as a reminder. -->

### Hash Functions

SSP21 currently only supports SHA256 described in 
[FIPS 190-4](http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf). SHA512 and/or hash function from the
BLAKE family will likely be supported in the future. The hash function serves two roles:

* Maintain a hash of all data sent and received during the key negotiation sequence. This running hash is then 
incorporated into the authentication signatures and makes any tampering of handshake data detectable.

* Used as a sub-function of HMAC to produce authentication tags and derive session keys.

| Hash Function       | Hash Length (*HASHLEN*) |
| --------------------|-------------------------|
| SHA256              |  32                     |

### Hashed Message Authentication Code (HMAC)

HMAC provides produces an authentication tag given a shared symmetric key and an input message. It is described in [RFC 
2104](https://www.ietf.org/rfc/rfc2104.txt). Any hash algorithm described above can be used in conjunction with this 
construct, and the corresponding HMAC function will produce a tag with the same length as the underlying hash function.

HMAC(key, message) - Calculate an authentication tag from an arbitrary length symmetric key and message bytes.

### HKDF

SSP21 uses the same key derivation function defined in Noise, however, it is invoked with slightly different
parameters as described in the [section][Key Negotiation Handshake] on key negotiation.

* *HKDF(handshake_hash, input_key_material)*: Calculates a pair of session keys based on input key material. 
    * Sets *temp_key* = *HMAC(handshake_hash, input_key_material)*.
    * Sets *key1* = *HMAC(temp_key, [0x01])*.
    * Sets *key2* = *HMAC(temp_key, key1 || [0x02])*.
    * Returns the pair of keys *(key1, key2)*.
  
### Digital Signature Algorithms (DSA)
  
While SSP21 does not use any DSA in the core key negotiation or session, implementations will need to support some set
of DSAs to verify certificates. SSP21 will initially support only usage of the Machine-to-Machine certificate format
defined in an  [RFC draft](https://tools.ietf.org/html/draft-ford-m2mcertificate-00).
     
**TODO: research all the DSAs used in M2M**

<!--
### Cipher Functions

SSP21 allows for the future use of AEAD cipher modes to encrypt session traffic and the key negotiation data as 
supported by Noise. The initial version of the specification, however, shall only support HMAC based authentication. 
Throughout the rest of the document it is assumed that the functions *Encrypt* and *Decrypt* are synonymous with *Sign* 
or *Verify* respectively when an authentication-only cipher mode is specified. Noise defines the following abstract 
AEAD Cipher functions.

* **ENCRYPT(k, n, ad, plaintext)**: Encrypts *plaintext* using the 32-byte key (*k*) and an unsigned 8-byte nonce (*n*) 
which must be unique for the key (*k*). Returns the ciphertext.  Encryption is performed using an AEAD encryption mode 
with the associated data (*ad*). The returned ciphertext is the same size as the plaintext plus 16 bytes for an 
authentication tag.

* **DECRYPT(k, n, ad, ciphertext)**: Decrypts *ciphertext* using 32-byte key (*k*), and 8-byte nonce (*n*), and 
associated data (*ad*). Returns the plaintext if authentications succeeds, otherwise it signals an error in the event 
of authentication failure.

To support authentication-only modes, SSP21 redefines *Encrypt* and *Decrypt* as *Sign* and *Verify* in terms of HMAC 
over the same set of fields. The *message* input to the HMAC calculation is defined as a concatenation of the 8-byte 
nonce (*n*), the 1-byte length of the associated data (*len(ad)*) for domain separation, the associated data (*ad*), 
and the plaintext:

*message* = *n* || *len(ad)* || *ad* || *plaintext*

* **SIGN(k, n, ad, plaintext)**:  Calculates the HMAC tag based on the message definition above and appends it to the 
plaintext.

* **VERIFY(k, n, ad, ciphertext)**: Interprets the ciphertext argument as a concatenation of the plaintext and the HMAC 
tag. Calculates the correct HMAC tag according to the message definition above. Uses a constant-time comparison 
algorithm to
check the input and calculated tag values for equality. Returns the plaintext if authentication succeeds, otherwise 
signals an error in the event of authentication failure.
-->


### CSPRNG

A cryptographically secure pseudorandom number generator (CSPRNG) is required for the selection of static and ephemeral 
private keys. Any secure RNG will do, put implementers should err on the side of caution and prefer one from a proven 
library.

## Messages

Every message at the cryptographic layer begins with a one octet message type identifier. The remaining octets are 
interpreted according the defined structure of that type.

### Syntax

SSP21 uses a lightweight structural syntax to define the contents of messages
and to specify how the message shall be serialized. These definitions
are meant to precisely define the contents of a message, however, they are not
meant to be used by a compiler to automatically generate source code.

Messages consist of the following structure:

```
message <message-name> {
  <field1-name> : <field1-type>
  <field2-name> : <field2-type>
  ...
  <field3-name> : <field3-type>
}
```

The following basic types are defined. All multi-byte integers are serialized in big-endian format.

* **U8** - 8-bit (1-byte) unsigned integer.
* **U16** - 16-bit (2 byte) unsigned integer.
* **U32** - 32-bit (4 byte) unsigned integer.

The following example defines a message that provides counts of various types of flowers:

```
message FLOWERS {
  num_roses : U8
  num_violets : U16
  num_petunias : U32
}
```

The serialized size of a *flowers* message would always be 7 bytes 
(sizeof(U8) + sizeof(U16) + sizeof(U32)).

#### Enumerations

Single byte enumerations are defined with the following syntax:

```
enum <enum-name> {
  <name1> : <value1>
  <name2> : <value2>
  ...
  <nameN> : <valueN>
}
```

The following example defines an enumeration of 3 possible color values:

```
enum COLOR {
  RED : 0
  GREEN : 1
  BLUE : 2
}
```

Enumeration types can be referenced from within a message definition using the following notation:

```
message <message-name> {
  <enum-field-name> : enum::<enum-name>
}
```

Using the COLOR example above we could define a message that represents the intensity of a single color:

```
message INTENSITY {
  color : enum::COLOR
  value : U8
}
```

Message definitions can reference a constant enumeration value by specifying a specific value after the type:

```
message RED_INTENSITY {
  color : enum::COLOR::RED
  value : U8
}
```

In practice, this only occurs for the *FUNCTION* enumeration.

#### Sequences

*Sequences* are variable length lists of particular type that, when serialized, are prefixed  with a *U8* or *U16* 
count of elements denoted with the notation **Seq8[x]** or **Seq16[x]** respectively where *x* is some type id. 

When sequences are typed on primitive values, the length of the sequence in bytes is calculated as the count of elements
multiplied by the size of primitive plus the size of the count prefix field.

```
message ByteSequence {
  value : Seq16[U8]
}
```

Given the message definition above, the ByteSequence with value equal to {0xCA, 0xFE} would be encoded as:

```
[0x00, 0x02, 0xCA, 0xFE]
```

Sequences of sequences are also allowed, but only to this maximum depth of 2. For instance, we could define
a message containing a sequence of byte sequences as follows:

```
message ByteSequences {
  values : Seq8[Seq16[U8]]
}
```

Suppose that we wish to encode the following sequence of byte sequences in the values field above:

```
{ {0x07}, {0x08, 0x09}, {0x0A, 0x0B, 0x0C} }
```

The serialized ByteSequences message would be encoded as:

```
[**0x03**, **0x00, 0x01**, 0x07, **0x00, 0x02**, 0x08, 0x09, **0x00, 0x03**, 0x0A, 0x0B, 0x0C]
```

The first highlighted value of `0x03` refers to the fact that there are 3 byte sequences in the outer
sequence. The subsequent highlighted values (`[0x00, 0x01], [0x00, 0x02], [0x00, 0x01]`) refer to the number of bytes 
that follow in each sub-sequence.

Despite the generality of the sequence definition over any type, in practice it is only used to define **Seq*N*[U8]** 
and **Seq*N*[Seq*N*[U8]]**.


### Definitions

#### Enumerations

Common enumeration types that are used in one or more messages are defined here.

##### FUNCTION 

SSP21 message definitions always begin with a fixed value of the *FUNCTION* enumeration. This fixed value allows a 
parser to determine the type of the message by inspecting the first byte of an opaque message delivered by the link 
layer. The correct message-specific parser can then be invoked.
      
```
enum FUNCTION {
    REQUEST_HANDSHAKE_BEGIN  : 0
    REPLY_HANDSHAKE_BEGIN    : 1
    REQUEST_HANDSHAKE_AUTH   : 2
    REPLY_HANDSHAKE_AUTH     : 3
    REPLY_HANDSHAKE_ERROR    : 4
    UNCONFIRMED_SESSION_DATA : 5
}
```

##### NONCE_VERIFICATION_MODE

The *NONCE_VERIFICATION_MODE* enumeration specifies how the incrementing nonce (message counter) is verified to protect
packets from replay.

```
enum NONCE_VERIFICATION_MODE {
    INCREMENT_LAST_RX : 0
    GREATER_THAN_LAST_RX : 1
}
```

* **INCREMENT_LAST_RX** - If this mode is specified, the receiver of a session message will require that the
received nonce strictly equally the last nonce plus one. This mode is intended to be used in session oriented 
environments like TCP that provide ordered stream reassembly and **should always be used in such environments** as it
provides the strongest guarantees.

* **GREATER_THAN_LAST_RX** - If this mode is specified, the receiver of a session message will only require that the
received nonce be greater the last nonce. This mode is intended to be used in session-less environments like serial or 
UDP.

##### DH_MODE

The *DH_MODE* enumeration specifies which Diffie Hellman function will be used during the handshake to derive key
material.

```
enum DH_MODE {
    X25519 : 0
}
```

##### HASH_MODE

The *HASH_MODE* enumeration specifies which hash algorithm will be used during the handshake process to prevent
tampering.

```
enum HASH_MODE {
    SHA256 : 0
}
```

##### SESSION_SECURITY_MODE

The *SESSION_SECURITY_MODE* enumeration specifies the complete set of algorithms that determine the security properties 
of
the session. 

```
enum SESSION_SECURITY_MODE {
    HMAC-SHA256-16 : 0
}
```

**Authentication-only session modes**

* **HMAC-SHA256-16** - Plaintext is authenticated with HMAC-SHA256 truncated to the leftmost 16 bytes.
 
**Encrypted and authenticated session modes** 
 
SSP21 does not currently support encrypted sessions. Future versions of the protocol may support AEAD cipher
modes like AES-GCM.

##### CERTIFICATE_MODE

The *CERTIFICATE_MODE* enumeration specifies what type of certificate will be exchanged by both parties to authenticate
each other.

```
enum CERTIFICATE_MODE {
    PRESHARED_KEYS : 0
    M2M : 1
}
```

* **NONE_PRESHARED_KEYS** - No certificates are exchanged. Parties have preshared public static DH keys. 

* **M2M** - Machine-to-machine certificate format

##### HANDSHAKE_ERROR

The *HANDSHAKE_ERROR* enumeration denotes an error condition that occurred during the handshake process.

```
enum HANDSHAKE_ERROR {
    BAD_MESSAGE_FORMAT                : 0
    UNSUPPORTED_DH_MODE               : 1
    UNSUPPORTED_HASH_MODE             : 2
    UNSUPPORTED_SESSION_SECURITY_MODE : 3
    UNSUPPORTED_CERTIFICATE_MODE      : 4
    BAD_CERTIFICATE_FORMAT            : 5
    UNSUPPORTED_CERTIFICATE_ALGORITHM : 6
    AUTHENTICATION_ERROR              : 7
    INTERNAL                          : 255
}
```

**Note: Implementations shall NEVER define custom error codes as this can allow implementation fingerprinting**

* **BAD_MESSAGE_FORMAT** - A received handshake message was malformed in some manner, e.g. it was improperly encoded,
had missing bytes, or fields with the incorrect lengths.

* **UNSUPPORTED_DH_MODE** - The requested Diffie Hellman mode is not supported.
 
* **UNSUPPORTED_HASH_MODE** - The requested hash algorithm is not supported.
 
* **UNSUPPORTED_SESSION_SECURITY_MODE** - The requested session security mode is not supported.
 
* **UNSUPPORTED_CERTIFICATE_MODE** - The requested certificate mode is not supported.
 
* **BAD_CERTIFICATE_FORMAT** - One of the received certificates was improperly encoded.
 
* **UNSUPPORTED_CERTIFICATE_ALGORITHM** - The specified algorithm in one of the certificates is not supported.

* **AUTHENTICATION_ERROR** - The outstation was unable to authenticate the master.
 
* **INTERNAL** - A error code for any unforeseen condition or implementation specific error. 

#### Handshake Messages

##### REQUEST_HANDSHAKE_BEGIN

The master initiates the process of establishing a new session by sending the *REQUEST_HANDSHAKE_BEGIN* message.

```
message REQUEST_HANDSHAKE_BEGIN {
   function                 : enum::FUNCTION::REQUEST_HANDSHAKE_BEGIN
   version                  : U16
   nonce_verification_mode  : enum::NONCE_VERIFICATION_MODE
   handshake_dh_mode        : enum::DH_MODE
   handshake_hash_mode      : enum::HASH_MODE
   session_security_mode    : enum::SESSION_SECURITY_MODE
   certificate_mode         : enum::CERTIFICATE_MODE
   ephemeral_public_key     : Seq8[U8]      
   certificates             : Seq8[Seq16[U8]]
}
```

* **version** - Identifies the version of SSP21 in use. Only new versions that introduce non-backward compatible 
changes to the specification which cannot be mitigated via configuration will increment this number. 

<!--- RLC: Consider using a scheme that would allow new features to be added without losing backward compatibility, and 
indicating it - e.g. a libtool-like versioning scheme -->

<!--- JAC: Yes, definitely. Will look into this. Will also make it explicit that adding new cipher suite modes won't
impact the version field ---->

* **nonce_verification_mode** - Identifies one of two modes for verifying messages against replay with differing
 security properties.
 
* **handshake_dh_mode** - Specifies what DH algorithm to be used , and implicitly determines the expected length of 
*ephemeral_public_key* and the type/length of the public key used lowest certificate in any chain.

* **handshake_hash_mode** - Specifies what hash algorithm is used to prevent tampering of handshake data.
  
* **session_security_mode** - Specifies the full set of algorithms used to secure the session.
   
* **certificate_mode** - Specifies what type of certificates are being exchanged. If certificate_mode is equal to 
*PRESHARED_KEYS*, the *certificates* field shall contain not contain any certificates.

* **ephemeral_public_key** - An ephemeral public DH key with length corresponding to the associated length defined by
*handshake_dh_mode*.

* **certificates** - A possibly empty certificate chain that is interpreted according to the *certificate_mode* field. 
Chains are placed in the sequence from the root level of the chain down to the endpoint certificate.

##### REPLY_HANDSHAKE_BEGIN

The outstation replies to *REQUEST_HANDSHAKE_BEGIN* by sending *REPLY_HANDSHAKE_BEGIN*, unless an error occurs in which 
case it responds with *REPLY_HANDSHAKE_ERROR*.

```
message REPLY_HANDSHAKE_BEGIN {
   function : enum::FUNCTION::REPLY_HANDSHAKE_BEGIN
   ephemeral_public_key: Seq8[U8]
   certificates: Seq8[Seq16[U8]]
}
```

* **empheral_public_key** - An ephemeral public DH key corresponding to the key type requested by the master.

* **certificates** - A possibly empty certificate chain that is interpreted according to the *certificate_mode* field
 transmitted by the master.


##### REQUEST_HANDSHAKE_AUTH

After receiving a valid *REPLY_HANDSHAKE_BEGIN*, the master transmits a *REQUEST_HANDSHAKE_AUTH*.

```
message REQUEST_HANDSHAKE_AUTH {
   function : enum::FUNCTION::REQUEST_HANDSHAKE_AUTH   
   hmac: Seq8[U8]
}
```

* **hmac** - An untruncated HMAC authentication tag calculated using the handshake hash function.

##### REPLY_HANDSHAKE_AUTH

After receiving a valid and authenticated *REQUEST_HANDSHAKE_AUTH*, the outstation transmits a *REPLY_HANDSHAKE_AUTH*.

```
message REPLY_HANDSHAKE_AUTH {
   function : enum::FUNCTION::REPLY_HANDSHAKE_AUTH   
   hmac: Seq8[U8]
}
```

* **hmac** - An untruncated HMAC authentication tag calculated using the handshake hash function.

##### REPLY_HANDSHAKE_ERROR

The outstation can reply to a *REQUEST_HANDSHAKE_BEGIN* or a *REQUEST_HANDSHAKE_AUTH* message with a 
*REPLY_HANDSHAKE_ERROR* message. This message is for debugging purposes only during commissioning and cannot be
authenticated.

```
message REPLY_HANDSHAKE_ERROR {
   function : enum::FUNCTION::REPLY_HANDSHAKE_ERROR
   error_code : enum::HANDSHAKE_ERROR
}
```

* **error_code** - An error code that enumerates possible error conditions that can occur during the handshake.

##### UNCONFIRMED_SESSION_DATA

After the successful completion of a key negotiation handshake, either party may transmit *UNCONFIRMED_SESSION_DATA*
to the other.

```
message UNCONFIRMED_SESSION_DATA {
   function : enum::FUNCTION::UNCONFIRMED_SESSION_DATA
   nonce : U16
   valid_until_ms : U32   
   payload_and_auth_tag : SEQ16[U8]
}
```

* **nonce** - An incrementing nonce that ensures every session message for a given key is unique.
* **valid_until_ms** - A millisecond time-bound on the validity of the message since session establishment 

<!--- RLC: Should 
be clearer as to when that is: I think it would be better to include an arbitrary ms counter in the first two messages 
to establish a time base (i.e. have the master send a number indicating its time, and the outstation a number 
indicating its time -->.

<!--- JAC: Yes, definitely, this is undefined ATM, but I am going to try and define this without exchanging time bases
 -->

* **payload_and_auth_tag** - Either a concatenation of the plaintext payload and a truncated HMAC or the output of an
AEAD mode of encryption. How this field is interpreted depends on the previously agreed upon *session_security_mode*.

When *session_security_mode* is a truncated HMAC mode, *payload_and_auth* is defined as follows:
 
*payload_and_auth* := plaintext_payload | HMAC(key, entire_message_except_for_hmac)

## Key Negotiation Handshake

Key negotiation in SSP21 derives a common pair of symmetric keys that can be used to secure a session and authenticates
the handshake and both parities. The SSP21 handshake most closely resembles the following message pattern from Noise:

```
-> e, s
<- e, s, dhee, dhes, dhse
```

It's not important to understand the specifics of Noise's notation. The important point here is that SSP21 uses a
handshake pattern where all Diffie Hellman operations are deferred until after first two messages are exchanged.
 
### Procedure 

The following steps are performed during a successful handshake. The various errors that can occur and early handshake
terminations are described in the [state transition diagrams](State Transition Diagrams).

DH keys in this section use the following abbrevations:

* OEVK - Outstation ephemeral private key
* OEPK - Outstation ephemeral public key
* OSVK - Outstation static private key
* OSPK - Outstation static public key
* MEVK - Master ephemeral private key
* MEPK - Master ephemeral public key
* MSVK - Master static private key
* MSPK - Master static public key

Symmetric session keys in this this section use the following abbrevations:

* CK - a *chaining key* used as an intermediate key and later stretched into two session keys
* AK - an *authentication key* used to authenticate both parties prior to final session key derivation
* MOSK - Master to outstation session key 
* OMSK - Outstation to master session key

Note: The HASH() and HMAC() functions below always refer to the hash function specified by the master in the initial 
*REQUEST_HANDSHAKE_BEGIN* message.  

1. The master sends the *REQUEST_HANDSHAKE_BEGIN* message to the outstation containing an ephemeral public key, some
additional metadata, and a certificate chain.

    * The master initializes the *handshake_hash* value to the hash of the entire transmitted message:
        *set handshake_hash = HASH(message)*

2. The outstation receives the *REQUEST_HANDSHAKE_BEGIN* message, and then validates that it trusts the public key via 
the certificate chain.

    * The outstations initializes the *handshake_hash* value equal to the hash of the entire received message:
        *set handshake_hash = HASH(message)*

3. The outstation sends the *REPLY_HANDSHAKE_BEGIN* message containing its own ephemeral public DH key and
certificate chain.
 
    * The outstation mixes the entire transmitted message into the *handshake hash*.
        * set handshake_hash = HASH(handshake_hash || message)
 
    * The outstation then derives the *chaining key* and the *authentication key*:
        * *set dh1* = *DH(OEVK, MEPK)*
        * *set dh2* = *DH(OEVK, MSPK)*
        * *set dh3* = *DH(OSVK, MEPK)*
        * *set (CK, AK) = HKDF(handshake_hash, dh1 || dh2 || dh3)* 
 
4. The master receives the *REPLY_HANDSHAKE_BEGIN* message and validates that it trusts the public key via the 
certificate chain.

    * The master mixes the entire received message into the *handshake hash*.
            * set handshake_hash = HASH(handshake_hash || message)
    
    * The master then derives the *chaining key* and the *authentication key*:
        * *set dh1* = *DH(MEVK, OEPK)*
        * *set dh2* = *DH(MEVK, OSPK)*
        * *set dh3* = *DH(MSVK, OEPK)*
        * *set (CK, AK) = HKDF(handshake_hash, dh1 || dh2 || dh3)*
        
5. The master transmits a *REQUEST_HANDSHAKE_AUTH* message setting *hmac = HMAC(AK, [0x01])*.
    
6. The outstation receives the *REQUEST_HANDSHAKE_AUTH* message, verifies the HMAC, and then transmits a 
*REPLY_HANDSHAKE_AUTH* message setting *hmac = HMAC(AK, [0x02])*.
    
    * The outstation performs the final session key derivation by splitting the chaining key:
        * set (MOSK, OMSK) = HKDF(CK, [])
        
    * The outstation initializes a new session with (MOSK, OMSK, nonce = 0)         
    
7.  The master receives the *REPLY_HANDSHAKE_AUTH*, verifies the HMAC, and performs the same key derivation
and session initialization as the outstation.
        
### Security Properties

If any of the following properties do not hold, then master and outstation will not agree on the same *chaining_key* and
*authentication_key*.

* If a MitM tampers with the contents of either the *REQUEST_HANDSHAKE_BEGIN* message or the *REPLY_HANDSHAKE_BEGIN*, 
the two parties will have differing handshake hashes which will produce different keys when feed into the key derivation
function.

* If either party does not possess the private DH keys corresponding to the ephemeral or static public keys 
transmitted, they will be unable to perform the correct DH calculations and will not be able to calculate the same keys 
in the KDF.
 
### Message Exchanges

A success handshake involves the exchange of the following four messages:

![Successful handshake](msc/handshake_success.png){#fig:handshake_success}

The outstation may signal an error after REQUEST_HANDSHAKE_BEGIN:

![Error in REQUEST_HANDSHAKE_BEGIN](msc/handshake_error1.png){#fig:handshake_error1}

The outstation could also indicate an error in REQUEST_HANDSHAKE_AUTH:

![Error in  REQUEST_HANDSHAKE_AUTH](msc/handshake_error2.png){#fig:handshake_error2}

### State Transition Diagrams

The master implements the following state transition diagram for the key negotiation handshake.


**Note: This diagram is notional while we explore the full capabilities of graph generation**

![Master handshake states](dot/master_handshake_states.png){#fig:master_handshake_states}


<!--
### Security Variables

A number of security variables are maintained during the key negotiation handshake and during active sessions.
These variables and the routines that operate on them are slightly modified from their definitions in Noise. The
high-level objected-oriented definitions in Noise are reused here as they provide useful clues to
implementers for organizing data structures and functions the operate on them.

#### CipherState ####

A *CipherState* can sign/verify or encrypt/decrypt a message based on the following variables:

* **k**: A symmetric key of 32 bytes (which may be empty as indicated by a flag or state variable). This key
is used in HMAC calculations.

* **n**: A 4-byte (32-bit) unsigned integer nonce.

The following methods will be associated with *CipherState*.  The maximum value of nonce (*n*) of 2^64 - 1 is reserved 
for future use and shall not be used. If incrementing *n* results in the maximum value, any further *EncryptWithAd()* 
or  *DecryptWithAd()* calls will signal an error.

* **InitializeKey(key)**: Sets *k* = key, and sets *n* = 0.

* **HasKey()**: Returns true if *k* is non-empty, false otherwise.

* **EncryptWithAd(ad, plaintext)**: If *k* is non-empty returns *ENCRYPT(k, n++, ad, plaintext)*, otherwise signals an 
error to the caller.

* **DecryptWithAd(ad, ciphertext)**: If *k* is empty, signals an error to the caller. Otherwise it attempts decryption 
by calling *DECRYPT(k, n++, ad, plaintext)*. If an authentication error occurs, it is signaled to the caller, otherwise
it returns the plaintext.

#### Symmetric State

A *SymmetricState* object contains a *CipherState* plus the following variables:

* **ck**: A chaining key of *HASHLEN* bytes.

* **h**: A hash output of *HASHLEN* bytes.

The following methods will be associated with *SymmetricState*:

* **Initialize()**:
    * Sets h equal to all zeros. 
 
**TODO: research consequences of setting h to a fixed value. Shouldn't matter since 
all the fixed Noise patterns would produce a deterministic hash value anyway**
    * Sets *ck* = *h*.
    * Calls *InitializeKey(empty)*.

* **MixKey(input_key_material)**:
    * Sets *ck*, *temp_k* = *HKDF(ck, input_key_material)*.
    * If *HASHLEN* is 64, then truncates *temp_k* to 32 bytes.
    * Calls *InitializeKey(temp_k)*.

* **MixHash(data)**:
    * Sets *h* = *HASH(h* || *data)*

* **EncryptAndHash(plaintext)**:
   * Sets *ciphertext = EncryptWithAd(h, plaintext)*.
   * Calls *MixHash(ciphertext).
   * returns *ciphertext*.
   * Note: if *k* is *empty*, the *EncryptWithAd()* call will set *ciphertext* equal to  *plaintext*.

* **DecryptAndHash(ciphertext)**:
    * Sets *plaintext = DecryptWithAd(h, ciphertext)*
    * calls *MixHash(ciphertext)*
    * returns *plaintext*.
    * Note that if *k* is *empty*, the *DecryptWithAd()* call will set *plaintext* equal to *ciphertext*.

* **Split()**: Returns a pair of *CipherState* objects for encrypting transport messages.
    * Sets *temp_k1, temp_k2* = *HKDF(ck, [])*.
    * If *HASHLEN* is 64, then truncates *temp_k1* and *temp_k2* to 32 bytes.
    * Creates two new *CipherState* objects *cs1* and *cs2*.
    * Calls *cs1.InitializeKey(temp_k1)* and *cs2.InitializeKey(temp_k2)*.
    * Returns the pair *(cs1, cs2)*.
-->
