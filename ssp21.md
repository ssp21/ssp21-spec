---
title:      'SSP21'
author:     'Adam Crain (jadamcrain@automatak.com)'
revision:   '1'
date:       '2016-05-16'
---

1. Introduction
================

Secure Systems Protocol (SSP) is cryptographic wrapper designed to secure point-to-multipoint serial protocols. It can be used as a protocol agnostic bump in the wire (BitW) at remote endpoints or as a bump in the stack (BitS). The cryptographic layer is based on the [Noise Protocol](noiseprotocol.org/) with modifications to make encryption optional.

2. The Link Layer
=================

SSP21's link layer provides three features: framing, addressing, and error-detection. The frame consists of the following fields. All multi-byte integer fields are encoded in little endian.

[ start 0x07BB ][ length ][destination ][ source ][ ... payload bytes ... ][ CRC (4-bytes)]

The minimum size of a link layer frame is 12 bytes, consisting of the start, length, destination, source, no payload bytes, and the CRC.

**start** (2-bytes) - The start bytes provide a delimiter for the beginning of the frame and shall always begin with the two bytes sequence 0x07BB.

**length** (2-bytes) - This field encodes the length in bytes of the payload data. A frame containing no payload will have this field set to zero. An upper maximum size (less than 65535) should be configurable to allow implementations to use less memory when receiving a full frame.

**destination** (2-bytes) - This field encodes the destination address for frame. Devices shall always set this field to the address of the intended recipient before transmitting. When receiving a frame, devices shall not do any further processing of frames with an unknown destination address.

**source** (2-bytes) - This field encodes the source address for frame. Devices shall always set this field to their local address before transmitting. The usage of this field depends on the application layer of
wrapped protocol.
