---
title:      'SSP21'
author:     'Adam Crain (jadamcrain@automatak.com)'
date:       'pre-release'
---

# Introduction

Secure SCADA Protocol (SSP) is cryptographic wrapper designed to secure point-to-multipoint serial protocols, or to act 
as a security layer for new SCADA applications. It is intended to fill a gap where existing technologies like TLS are 
not applicable, or require too much processing power or bandwidth. It can be used as a protocol agnostic bump in the 
wire (BitW) at initiator endpoints or as a bump in the stack (BitS) on the master or the outstation. No provision is 
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

<!--- RLC: While true, I think this may hinder adoption in that market, as it would mean that an SSP21-enhanced
protocol is no longer interoperable with the  original protocol, but devices will still need to implement the
original protocol. That means more code (two link layers for the same protocol), more testing, more complex
procurement, more complex deployment, ...At least in the beginning, I think we should not expect anything other
than BitW on the outstation end... -->

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
* A means of authenticating users and roles/permissions. This information is likely to come from an external identity
management systeem.

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
completely stateless.  The CRC is important at this layer to detect data corruption from random sources 
(EMF, cosmic rays, etc).  This check is intended to prevent randomly corrupted payloads from  reaching the cryptographic
layer. This prevents "tampering" false positives from occurring at the cryptographic layer which would require a 
completely different organizational response than occasional randomly corrupted frames.

```

[ start ][ destination ][ source ][ length ][ crc-h ][ payload ][ crc-p ]

```

The frames consist of the following fields. All multi-byte integer fields (including the CRCs) are encoded in little 
endian format.

**destination** (2-bytes) - The destination field encodes the address of the intended recipient of the frame. Devices 
shall always set this field to the address of the intended recipient when transmitting. When receiving a frame, devices 
shall not do any further processing of frames with an unknown destination address.

**source** (2-bytes) - The source field encodes the address of the transmitting party. The usage of this field may 
depend on the application layer of wrapped protocol.

**length** (2-bytes) - Length of the message, including the header and CRC, in bytes.

**crc-h** (4-bytes) - A 32-bit CRC value calculated over the header (start, destination, source, and length fields). 
The CRC polynomial is described in detail in the next section.

**payload** (0 to 4092 bytes) - An opaque payload that is passed to the cryptographic layer. The length is determined by
the *length* field in the header. This length shall never exceed 4092 bytes.

**crc-p** (4-bytes) - A 32-bit CRC value calculated over the payload bytes.
 
## CRC Polynomial

The CRC polynomial for the SSP21 link frame was selected based on the Hamming distance (HD) offered by several
candidate polynomials at different payload lengths. Our candidates included the following polynomials:
  
| notation  | DNP3     | IEEE 802.3 | **Castagnoli** |  Koopman   |
|-----------|----------|------------|----------------|------------|
| msb first | 0x3d65   | 0x04c11db7 | 0xf4acfb13     | 0x32583499 |
| Koopman   | 0x9eb2   | 0x82608edb | 0xfa567d89     | 0x992c1a4c |

The polynomials provide the following maximum payload lengths (in bytes) at various Hamming distances:

| HD   |  DNP3   | IEEE 802.3 | Castagnoli |  Koopman  |
|------|---------|------------|------------|-----------|
| 8    |    0    |    11      |     34     |     16    |
| 7    |    0    |    21      |     34     |     16    |
| 6    |    16   |    33      |     4092   |     4092  |
| 5    |    16   |    371     |     4092   |     4902  |
| 4    |    16   |    11450   |     8187   |     8188  |

Four byte polynomials can provide significantly better error detection across longer payload lengths. The Koopman
and Castagnoli polynomials were discovered using exhaustive search techniques and have significantly longer
runs of HD = 6 protection than IEEE 802.3. We selected the Castagnoli polynomial because of slightly better HD=8 
coverage for very short frames. The error detection properties of this polynomial have also been independently verified
by at least two researchers.

The maximum HD=6 payload length of 4092 determines the bound for the maximum link layer frame size allowed by the 
standard.

# Cryptographic Layer

The cryptographic layer is inspired by the [Noise](http://noiseprotocol.org), a self-described framework for building 
cryptographic protocols. This specification picks from all the available options and modes within Noise to create a 
subset appropriate for wrapping ICS serial protocols. This specification is self-contained. Reading the Noise 
specification is not required to understand or implement SSP21.

Modifications to Noise include:

* A single handshake pattern is used, therefore the concept of handshake patterns have been removed entirely.
* Modifying Noise to support authentication only (handshake and session)
* Message identifiers to make session renegotiation possible on serial networks
* Masters can specify sets of cryptographic algorithms
* Selecting a specific handshake mode that will be used in all applications
* Definitions for handshake payload data including relative time bases and certificate formats
* Static public keys are always transmitted as part of a certificate

## Terminology

The key agreement handshake in SSP21 is a request-reply protocol, thus are two parties: an *initiator* and a 
*responder*. Normally, the initiator is expected to be the SCADA master, and the responder is expected to be an
outstation. It's perfectly possible, however, to flip this relationship in certain circumstances, and have the 
outstation initiate the key agreement. To preserve the generality of the specification the terms initiator and responder
are used in place of master and outstation.

## Algorithms

SSP21 uses a number of cryptographic algorithms. They are described here within the context of the functionality they 
provide. The initial SSP21 specification contains a minimal subset of algorithms, but the protocol is capable of 
extension.

The following notation will be used in algorithm pseudo-code:

* The **||** operator denotes the concatenation of two byte sequences.
* The **[b1, b2, .. bn]** syntax denotes a, possibly empty, byte sequence.

### Diffie-Hellman (DH) functions

SSP21 currently only supports Curve25519 for session key agreement. It is described in detail in [RFC 
7748](https://www.ietf.org/rfc/rfc7748.txt).

| DH Curve       | length (*DHLEN*)       |
| ---------------|------------------------|
| Curve22519     | 32                     |

All DH curves will support the following two algorithms with the key lengths specified above.

* GenerateKeyPair() - Generate a random public/private key pair.

* DH(private_key, public_key) - Given a local private key and remotely supplied public key, calculate bytes of 
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

HMAC provides produces an authentication tag given a shared key and an input message. It is described in [RFC 
2104](https://www.ietf.org/rfc/rfc2104.txt). Any hash algorithm described above can be used in conjunction with this 
construct, and the corresponding HMAC function will produce a tag with the same length as the underlying hash function.

HMAC(key, message) - Calculate an authentication tag from an arbitrary length symmetric key and message bytes.

### HKDF

SSP21 uses the same key derivation function defined in Noise, however, it is invoked with slightly different
parameters as described in the [section][Key Negotiation Handshake] on key negotiation. 

* *HKDF(salt, input_key_material)*: Calculates a pair of session keys based on input key material. 
    * Sets *temp_key* = *HMAC(salt, input_key_material)*.
    * Sets *key1* = *HMAC(temp_key, [0x01])*.
    * Sets *key2* = *HMAC(temp_key, key1 || [0x02])*.
    * Returns the pair of keys *(key1, key2)*.
    
Note: This function is the same function as defined in [RFC 5869](https://www.ietf.org/rfc/rfc5869.txt), but with the
following simplifications:
 
* Specialized to only two output keys
* The optional info parameter is a zero byte sequence
* Extract and expand steps are collapsed into a single function
  
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
are meant to precisely define the contents of a message, and allow implementations
to use code generation.

Groupings of fields are called Structs. Structs use the following syntax:

```
struct <struct-name> {
  <field1-name> : <field1-type>
  <field2-name> : <field2-type>
  ...
  <field3-name> : <field3-type>
}
```

*Messages* are special *Structs* whose first field is always a constant value of the *Function* enumeration.

```
message <message-name> {
  function : enum::Function::<function-name>
  <field1-name> : <field1-type>
  <field2-name> : <field2-type>
  ...
  <field3-name> : <field3-type>
}
```

The following primitive types are defined. All multi-byte integers are serialized in network byte order.

* **U8** - 8-bit (1-byte) unsigned integer.
* **U16** - 16-bit (2 byte) unsigned integer.
* **U32** - 32-bit (4 byte) unsigned integer.

The following example defines a struct that provides counts of various types of flowers:

```
struct Flowers {
  num_roses : U8
  num_violets : U16
  num_petunias : U32
}
```

The serialized size of a *Flowers* struct would always be 7 bytes 
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

Enumeration types can be referenced from within a *Struct* or *Message* definition using the following notation:

```
struct <struct-name> {
  <enum-field-name> : enum::<enum-name>
}
```

Using the COLOR example above we could define a *Struct* that represents the intensity of a single color:

```
struct Intensity {
  color : enum::COLOR
  value : U8
}
```

#### Bitfields

Bitfields are single-byte members of *Structs* or *Messages* that encode up to eight boolean values, one value for each
bit using the following syntax:

```
bitfield <bitfield-name> { "name top bit", "name top bit - 1",  ... "name bottom bit" }
```

Bitfields can have zero to eight member bits. The top bit (0x80) is always implicitly defined first in the list of bit
names. Unspecified bits shall always be encoded as zero.  Parsers shall fail parsing if any unspecified bit is set in
the input.

```
bitfield Flags { "flag1", "flag2", "flag3" }
```

The bitfield above with flag1 = true, flag2 = false, and flag3 = true would have a serialized representation of
0b10100000 (0xA0). An example of input that would fail a parsing for this bitfield is 0b10100010 (0XA2).


#### Sequences

*Sequences* are variable length lists of particular type that, when serialized, are prefixed  with a *U8* or *U16* 
count of elements denoted with the notation **Seq8[x]** or **Seq16[x]** respectively where *x* is some type id. 

When sequences are typed on primitive values, the length of the sequence in bytes is calculated as the count of elements
multiplied by the size of primitive plus the size of the count prefix field.

```
struct ByteSequence {
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
struct ByteSequences {
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

##### Function

SSP21 message definitions always begin with a fixed value of the *Function* enumeration. This fixed value allows a 
parser to determine the type of the message by inspecting the first byte of an opaque message delivered by the link 
layer. The correct message-specific parser can then be invoked.
      
```
enum Function {
    REQUEST_HANDSHAKE_BEGIN  : 0
    REPLY_HANDSHAKE_BEGIN    : 1
    REQUEST_HANDSHAKE_AUTH   : 2
    REPLY_HANDSHAKE_AUTH     : 3
    REPLY_HANDSHAKE_ERROR    : 4
    UNCONFIRMED_SESSION_DATA : 5
}
```

##### Nonce Mode

The *Nonce Mode* enumeration specifies how the nonce (message counter) is verified to protect
packets from replay.

```
enum NonceMode {
    INCREMENT_LAST_RX : 0
    GREATER_THAN_LAST_RX : 1
}
```

* **INCREMENT_LAST_RX** - The receiver of a session message will verify that the each received nonce is strictly 
equal to the last valid nonce plus one. This is the default mode and should always be used in session oriented 
environments like TCP that provide stream integrity and ordering guarantees.

* **GREATER_THAN_LAST_RX** - The receiver of a session message will verify that each received is greater the last 
valid nonce. This mode is intended to be used in session-less environments like serial or UDP and allows for loss 
of authenticated packets, but also relaxes security allowing a MitM to selectively drop messages from a session.

##### DH Mode

The *DH Mode* enumeration specifies which Diffie-Hellman function will be used during the handshake to derive key
material.

```
enum DHMode {
    X25519 : 0
}
```

##### Hash Mode

The *Hash Mode* enumeration specifies which hash algorithm will be used during the handshake process to prevent
tampering.

```
enum HashMode {
    SHA256 : 0
}
```

##### Session Mode

The *Session Mode* enumeration specifies the complete set of algorithms used to secure the session. 

```
enum SessionMode {
    HMAC-SHA256-16 : 0
}
```

* **HMAC-SHA256-16** - A MAC session mode using HMAC-SHA256 truncated to the leftmost 16 bytes.
 
##### Certificate Mode

The *Certificate Mode* enumeration specifies what type of certificate will be exchanged by both parties to authenticate
each other during the handshake.

```
enum CertificateMode {
    PRESHARED_KEYS : 0
}
```

* **PRESHARED_KEYS** - No certificates are exchanged. Parties use eachothers preshared public static DH keys to
authenticate. The *certificates* field in handshake messages will be left empty.

##### Handshake Error

The *Handshake Error* enumeration denotes an error condition that occurred during the handshake process.

```
enum HandshakeError {
    BAD_MESSAGE_FORMAT                : 0
    UNSUPPORTED_VERSION               : 1
    UNSUPPORTED_DH_MODE               : 2
    UNSUPPORTED_HASH_MODE             : 3
    UNSUPPORTED_SESSION_MODE          : 4
    UNSUPPORTED_CERTIFICATE_MODE      : 6
    BAD_CERTIFICATE_FORMAT            : 7
    UNSUPPORTED_CERTIFICATE_FEATURE   : 8
    AUTHENTICATION_ERROR              : 9
    NO_PRIOR_HANDSHAKE_BEGIN          : 10
    INTERNAL                          : 255
}
```

**Note: Implementations shall NEVER define custom error codes as this can allow implementation fingerprinting**

* **BAD_MESSAGE_FORMAT** - A received handshake message was malformed in some manner, i.e. it was improperly encoded.

* **UNSUPPORTED_VERSION** - The specified protocol version is not supported.

* **UNSUPPORTED_DH_MODE** - The requested Diffie-Hellman mode is not supported.
 
* **UNSUPPORTED_HASH_MODE** - The requested hash algorithm is not supported.
 
* **UNSUPPORTED_SESSION_MODE** - The requested session security mode is not supported.
 
* **UNSUPPORTED_CERTIFICATE_MODE** - The requested certificate mode is not supported.
 
* **BAD_CERTIFICATE_FORMAT** - One of the received certificates was improperly encoded.
 
* **UNSUPPORTED_CERTIFICATE_FEATURE** - The feature or specified algorithm in one of the certificates is not supported.

* **AUTHENTICATION_ERROR** - The responder was unable to authenticate the initiator.
 
* **INTERNAL** - A error code for any unforeseen condition or implementation specific error. 

#### Handshake Messages

##### Request Handshake Begin

The master initiates the process of establishing a new session by sending the *Request Handshake Begin* message.

```
message RequestHandshakeBegin {
   function                 : enum::Function::REQUEST_HANDSHAKE_BEGIN
   version                  : U16
   nonce_mode               : enum::NonceMode
   handshake_dh_mode        : enum::DHMode
   handshake_hash_mode      : enum::HashMode
   session_mode             : enum::SessionMode
   certificate_mode         : enum::CertificateMode
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

* **nonce_mode** - Identifies one of two modes for verifying messages against replay with differing
 security properties.
 
* **handshake_dh_mode** - Specifies the DH algorithm to be used during the handshake, and implicitly determines 
the expected length of *ephemeral_public_key*.

* **handshake_hash_mode** - Specifies what hash algorithm is used to prevent tampering of handshake data.
  
* **session_mode** - Specifies the full set of algorithms used to secure the session.
   
* **certificate_mode** - Specifies what type of certificates are being exchanged. If certificate_mode is equal to 
*PRESHARED_KEYS*, the *certificates* field shall be empty.

* **ephemeral_public_key** - An ephemeral public DH key with length corresponding to the associated length defined by
*handshake_dh_mode*.

* **certificates** - A possibly empty certificate chain that is interpreted according to the *certificate_mode* field.

##### Reply Handshake Begin

The outstation replies to *Request Handshake Begin* by sending *Reply Handshake Begin*, unless an error occurs in which 
case it responds with *Reply Handshake Error*.

```
message ReplyHandshakeBegin {
   function : enum::Function::REPLY_HANDSHAKE_BEGIN
   ephemeral_public_key: Seq8[U8]
   certificates: Seq8[Seq16[U8]]
}
```

* **empheral_public_key** - An ephemeral public DH key corresponding to the key type requested by the master.

* **certificates** - A possibly empty certificate chain that is interpreted according to the *certificate_mode* field
 transmitted by the master.


##### Request Handshake Auth

After receiving a valid *Reply Handshake Begin*, the master transmits a *Request Handshake Auth*.

```
message RequestHandshakeAuth {
   function : enum::Function::REQUEST_HANDSHAKE_AUTH
   mac: Seq8[U8]
}
```

* **mac** - An untruncated HMAC tag calculated using the handshake hash function.

##### Reply Handshake Auth

After receiving a valid and authenticated *Request Handshake Auth*, the outstation transmits a *Reply Handshake Auth*.

```
message ReplyHandshakeAuth {
   function : enum::function::REPLY_HANDSHAKE_AUTH
   mac: Seq8[U8]
}
```

* **mac** - An untruncated HMAC tag calculated using the handshake hash function.

##### Reply Handshake Error

The outstation can reply to a *Request Handshake Begin* or a *RequestHandshakeAuth* message with a 
*Reply Handshake Error* message. This message is for debugging purposes only during commissioning and cannot be
authenticated.

```
message ReplyHandshakeError {
   function : enum::Function::REPLY_HANDSHAKE_ERROR
   error : enum::HandshakeError
}
```

* **error** - An error code that enumerates possible error conditions that can occur during the handshake.

##### Unconfirmed Session Data

After the successful completion of a key negotiation handshake, either party may transmit *Unconfirmed Session Data*
to the other.

The message uses the following sub-fields:

```

bitfield SessionFlags { "fir", "fin" }

struct AuthMetadata {
    nonce : U16
    valid_until_ms : U32
    flags : bitfield::SessionFlags
}
```

* **nonce** - An incrementing nonce that provides protection from replay of session messages.

* **valid_until_ms** - A relative millisecond timestamp since session initialization as defined in the section on key
negotiation.
 
* **flags** - First and final bits used for message reassembly.

```
message UnconfirmedSessionData {
   function : enum::Function::UNCONFIRMED_SESSION_DATA
   metadata : struct::AuthMetadata
   payload : SEQ16[U8]
}
```

* **metadata** - Metadata sub-struct covered by the authentication mechanism of the negotiated *Session Mode*. 

* **payload** - Opaque payload field is interpreted according the negotiated *Session Mode*. Contains user data and an 
authentication tag.

## Key Agreement Handshake

Key agreement in SSP21 derives a common pair of symmetric keys that can be used to secure a session and authenticates
the handshake and both parities. The SSP21 handshake most closely resembles the following message pattern from Noise:

```
-> e, s
<- e, s, dhee, dhes, dhse
```

It's not important to understand the specifics of Noise's notation. The important point here is that SSP21 uses a
handshake pattern where all DH operations are deferred until after first two messages are exchanged. This 
pattern of performing three DH operations combined with a KDF is sometimes referred to as TripleDH key agreement in the 
cryptographic community.
 
### Procedure 

The following steps are performed during a successful handshake. The various errors that can occur and early handshake
terminations are described in the state transition diagrams.

Notation:

* Both parties maintain a *chaining key* denoted by the variable *ck* which is HASH_LEN in length.
* The HASH() and HMAC() functions always refer to the hash function requested by the master.
* NOW() returns the current value of a relative monotonic clock as a 64-bit unsigned count of milliseconds. 

DH keys in this section use the following abbreviations:

* re_vk - responder ephemeral private key
* re_pk - responder ephemeral public key
* rs_vk - responder static private key
* rs_pk - responder static public key
* ie_vk - initiator ephemeral private key
* ie_pv - initiator ephemeral public key
* is_vk - initiator static private key
* is_pk - initiator static public key

Symmetric keys in this this section use the following abbreviations:

* ak - an *authentication key* used to authenticate both parties prior to final session key derivation
* tx_sk - transmit session key
* rx_sk - receive session key

1. The initiator sends the *Request Handshake Begin* message to the responder containing an ephemeral public key, some
additional metadata, and optional certificate data.

    * The initiator sets the *chaining key* value to the hash of the entire transmitted message:
        * *set ck = HASH(message)*

2. The responder receives the *Request Handshake Begin* message.

    * If using certificates, the responder validates that it trusts the public key via the certificate data.

    * The responder sets the *chaining key* value equal to the hash of the entire received message:
        * *set ck = HASH(message)*

    * The responder transmits a *Reply Handshake Begin* message containing its own ephemeral public DH key and    
certificate data as requested by the initiators's requested certificate mode.
 
    * The responder mixes the entire transmitted message into the *chaining key*.
        * *set ck = HASH(ck || message)*
 
    * The responder then derives a new *chaining key* and the *authentication key*:
        * *set dh1* = *DH(re_vk, ie_pk)*
        * *set dh2* = *DH(re_vk, is_pk)*
        * *set dh3* = *DH(rs_vk, ie_pk)*
        * *set (ck, ak) = HKDF(ck, dh1 || dh2 || dh3)* 
 
3. The initiator receives the *Reply Handshake Begin* message.

    * If using certificates, the initiator validates that it trusts the public key via the certificate data.

    * The initiator mixes the entire received message into the *chaining key*.
        * set ck = HASH(ck || message)
    
    * The initiator then derives a new *chaining key* and the *authentication key*:
        * *set dh1* = *DH(ie_vk, re_pk)*
        * *set dh2* = *DH(ie_vk, rs_pk)*
        * *set dh3* = *DH(is_vk, re_pk)*
        * *set (ck, ak) = HKDF(ck, dh1 || dh2 || dh3)*
        
    * The initiator transmits a *Request Handshake Auth* message setting *hmac = HMAC(ak, [0x01])*.

    * The initiator mixes the entire transmitted message into the chaining key.
        * set ck = HASH(ck || message)
    
    * The initiator records the time this request was transmitted for future use.
        
        * set *time_tx = NOW()* 
    
4. The responder receives the *Request Handshake Auth* message, and verifies the HMAC.
    
    * The responder mixes the entire received message into the chaining key.
        * set ck = HASH(ck || message)

    * The responder records the session initialization time:
        * *time_session_init = NOW()*               
    
    * The responder transmits a *Reply Handshake Auth* message setting *hmac = HMAC(AK, [0x02])*.
    
    * The responder mixes the entire transmitted message into the chaining key.
        * set ck = HASH(ck || message)
        
    * The responder performs the final session key derivation by expanding the chaining key:
        * set (rx_sk, tx_sk) = HKDF(ck, [])
        
    * The responder initializes the session with (rx_sk, tx_sk, time_session_init, read, write, verify_nonce).        
    
5.  The initiator receives the *Reply Handshake Auth*, and verifies the HMAC.
    
    * The initiator mixes the entire received message into the chaining key.
        * set ck = HASH(ck || message)
 
    * The initiator estimates the session initialization time: 
        * set *time_session_init = time_tx + (NOW() - time_tx)/2*
    
    * The initiator performs the final session key derivation by expanding the chaining key:
        * set *(tx_sk, rx_sk) = HKDF(ck, [])*
    
    * The initiator initializes the session with (rx_sk, tx_sk, time_session_init, read, write, verify_nonce). 
    
**Note:** See the section on session initialization for definitions of read, write, and verify_nonce functions.     
        
### Security Properties

If any of the following properties do not hold, then initiator and responder will not agree on the same *chaining_key* and
*authentication_key*.

* If a MitM tampers with the contents of either the *Request Handshake Begin* message or the *Reply Handshake Begin*, 
the two parties will have differing handshake hashes which will produce different keys when feed into the KDF.

* If either party does not possess the private DH keys corresponding to the ephemeral or static public keys 
transmitted, they will be unable to perform the correct DH calculations and will not be able to calculate the same keys 
in the KDF.

* A MitM cannot tamper with the common *time_session_init* by delaying messages by more than whatever timeout setting
 the initiator uses while waiting for replies from the responder. This ensures that the common time-point, in two separate
 relative time bases, is at least accurate to within this margin when the session is first initialized.
 
### Message Exchanges

A success handshake involves the exchange of the following four messages:

![Successful handshake](msc/handshake_success.png){#fig:handshake_success}

The responder may signal an error after receiving a *Request Hanshake Begin*:

![Error in Request Handshake Begin](msc/handshake_error1.png){#fig:handshake_error1}

The responder could also indicate an error in *Request Hanshake Auth*:

![Error in Request Handshake Auth](msc/handshake_error2.png){#fig:handshake_error2}

## Sessions

### Initialization

Upon complete of a successfully authenticated handshake, the communication session is initialized 
(or possibly reinitialized) with the following arguments:

* **rx_sk** - A session key used to authenticate decrypt received messages.
     
* **tx_sk** - A session key used to sign/encrypt transmitted messages.

* **time_session_init**  - The time the session was considered initialized in the local relative time base.

* **read** - A function corresponding to the specified *session_mode* used to process a received 
message's payload.
    * returns: 
        * Cleartext payload, or [] if an error occurs.
    * errors:
        * Signals an error if the message does not authenticate and/or decrypt properly.
        * Signals an error if input or output buffers do not meet required sizes.
    * arguments:
        * **key** - The session key used to perform the cryptographic operations.
        * **ad** - Additional data to be covered by the payload's authentication tag.  
        * **payload** - Payload bytes from the received message.

* **write** - A function corresponding to the specified *session_mode* used to prepare a transmitted 
message's payload.
    * returns:
        * The payload to be transmitted with the outgoing message.
    * errors:
        * Signals an error if input or output buffers do not meet required sizes.
    * arguments:
        * **key** - The session key used to perform the cryptographic operations.
        * **ad** - Additional data to be covered by the payload's authentication tag.
        * **cleartext** - Cleartext bytes to be placed into the payload.
  
* **verify_nonce** - A function used to verify the message nonce.
    * returns: 
        * A boolean value that is true if the new nonce is valid, and false otherwise.
    * arguments:
        * **last_nonce** - the last valid nonce, or zero for a newly initialized session.
        * **new_nonce** - the nonce from the current message.
  
The session shall also always maintain a few additional variables initialized internally:
    
* A 2-byte incrementing nonce (*n*) always initialized to zero, one for each session key.

* A configurable session termination timeout after which the session will no longer be considered valid. 
    
### Invalidation

Sessions will only become invalidated after one of the following conditions occurs:

* The transmit or receive nonce reaches the maximum value of 2^16 - 1.

* A configurable amount of time elapses. This session timeout shall default to 1 day and shall not be configurable
 to be greater than 30 days (the maximum session TTL of a message since initialization is ~49.7 days).
 
* A complete, authenticated handshake occurs reinitializing any prior existing session.

* In session oriented environments such as TCP, closing the underlying communication session will invalidate the SSP21
 cryptographic session.

Under no condition will malformed packets, unexpected messages, authentication failures, partial handshakes, or any 
other condition other than the ones listed above invalidate an existing session.

### Sending *Unconfirmed Session Data*

The following procedure is followed to transmit an *Unconfirmed Session Data* message:
  
* Ensure that the transmit nonce is not equal to the maximum value.
  
* Increment the transmit nonce by 1 and set this new value on the message.

* Set *valid_until_ms = NOW() + TTL*. 
 
* Set the message payload using the *write* function with which the session was initialized.

**Note:** The first transmitted session message from each party always has *n* = 1.

**Note:** See the TTL session for advice on how to set appropriate TTLs.

  
### Validating *Unconfirmed Session Data*

The following procedure is followed to validate a received *Unconfirmed Session Data* message:

* Verify the authenticity of the message using the *read* function with which the session was initialized. Upon
successfully authentication, the cleartext payload is returned.

* Check that *valid_until_ms <= NOW()*.

* Check the nonce using the *verify_nonce* function with which the session was initialized.

* Set the current nonce equal to the value of the received nonce.

### Session Modes

The *session_mode* specified by the initiator determines the concrete *read* and *write* functions with which the 
session is initialized. In general, these functions fall into two general classes: truncated MAC based functions that
only provide authentication, and Authenticated Encryption with Associated Data (AEAD) algorithms that encrypt the 
payload and additionally authenticate both the payload and associated data in the message.

#### MAC Modes

MAC session modes are based on some kind of MAC function, like a truncated HMAC. The write function of these modes can
be specified generically in terms of the MAC function.
   
```
write (key, ad, cleartext) -> payload {
  return cleartext | mac(key, len(ad) || ad || cleartext)
}
```

**Note:** len(ad) denotes the single byte length of the additional data, which cannot exceed 255.

The MAC is calculated over the concatenation of a single byte unsigned length of the additional data, the additional data 
itself, and the cleartext message.  Appending the length of additional data provides domain separation between the 
additional data and the payload. Although the additional data in SSP21 is of a fixed length currently, this future
proofs the protocol in the event that *ad* becomes a variable-length parameter in the future.

The corresponding *read* function splits the payload into cleartext and MAC, and then calculates the expected 
value of the MAC using the same arguments as the *write* function. It then uses a constant-time comparison to 
authenticate the MAC before returning the cleartext.

<!--
### State Transition Diagrams

#### Master

The master implements the following state machine to change the session keys.

![Master handshake states](dot/master_handshake_states.png){#fig:master_handshake_states}

States:

* **IDLE** - The master is not currently performing the key change and is idle.

* **WAIT_BEGIN** - The master has transmitted *REQUEST_HANDSHAKE_BEGIN* and is waiting to receive
*REPLY_HANDSHAKE_BEGIN*.

* **WAIT_AUTH** - The master has transmitted *REQUEST_HANDSHAKE_AUTH* and is waiting to receive *REPLY_HANDSHAKE_AUTH*.

Events:

* **begin** - The master begins the process of initializing session.
* **rx_ok_1** - The master receives a properly formatted *REPLY_HANDSHAKE_BEGIN*.
* **rx_err_1** - The master receives an improperly formatted *REPLY_HANDSHAKE_BEGIN* message.
* **rx_err_2** - The master receives an improperly formatted *REPLY_HANDSHAKE_AUTH* or fails to authenticate it.

Actions:

* **a1** - The master transmits a *REQUEST_HANDSHAKE_BEGIN* message, and starts the response timer.
* **a2** - The master transmits a *REQUEST_HANDSHAKE_AUTH* message, and starts the response timer.
-->


