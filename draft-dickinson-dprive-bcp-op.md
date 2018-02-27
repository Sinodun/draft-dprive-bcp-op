%%%
    Title = "Best Current Practices for DNS Privacy Service Operators"
    abbrev = "BCP for DNS Privacy Service Operators"
    category = "std"
    docName= "draft-dickinson-bcp-op-00"
    ipr = "trust200902"
    area = "Internet"
    workgroup = "dprive"
    keyword = ["DNS"]
    date = 2018-02-27T00:00:00Z
    [pi]
    toc = "yes"
    compact = "yes"
    symrefs = "yes"
    sortrefs = "yes"
    subcompact = "no"
    [[author]]
    initials="S."
    surname="Dickinson"
    fullname="Sara Dickinson"
    organization = "Sinodun IT"
      [author.address]
      email = "sara@sinodun.com"
      [author.address.postal]
      streets = ["Magdalen Centre", "Oxford Science Park"]
      city = "Oxford"
      code = "OX4 4GA"
      country = 'United Kingdom'
    [[author]]
    initials="J."
    surname="Dickinson"
    fullname="John Dickinson"
    organization = "Sinodun IT"
      [author.address]
      email = "jad@sinodun.com"
      [author.address.postal]
      streets = ["Magdalen Centre", "Oxford Science Park"]
      city = "Oxford"
      country = 'United Kingdom'
      code = "OX4 4GA"
%%%

.# Abstract
This document presents operational and security considerations for DNS
operators who choose to offer DNS Privacy services, including but not limited to
DNS-over-TLS [@!RFC7858].

It is also intended to allow operators to develop DNS Privacy Policy Statements
analogous to DNSSEC Practice Statements described in [@RFC6841].

{mainmatter}

# Introduction

The Domain Name System (DNS) was not originally designed with strong security or
privacy mechanisms. [@!RFC7626] describes the privacy issues associated with the
use of the DNS by Internet users including those related to un-encrypted DNS
messages on the wire and DNS 'query log' data maintained on DNS servers.

Two documents that provide ways to increase DNS privacy between DNS clients and
DNS servers are:

* Specification for DNS over Transport Layer Security (TLS) [@!RFC7858], referred
to here as simply 'DNS-over-TLS'
* DNS over Datagram Transport Layer Security
(DTLS) [@!RFC8094], referred to here simply as 'DNS-over-DTLS'. Note that this
document has the Category of Experimental.

Both documents are limited in scope to communications between stub clients and
recursive resolvers and the same scope is applied to this document.
[@?I-D.ietf-dprive-dtls-and-tls-profiles], [@!RFC7830] and
[@?I-D.ietf-dprive-padding-policy] provide further specifications related to DNS
Privacy

Note that [@?I-D.ietf-dnsop-dns-tcp-requirements] discusses Operational
Requirements for DNS-over-TCP but does not provide specific guidance on DNS
Privacy protocols.

This document includes operational guidance related to the specifications listed above.

TODO: Discuss alternative (non-standard) schemes not covered by this
document e.g. DNSCrypt, IPsec, VPNs.

In recent years there has been an increase in the availability of "open"
resolvers. Operators of open resolvers that choose to enable transports which
encrypt DNS on the wire generally do so to cater to users who are privacy
conscious. Their ability to provide clear, well documented, and secure privacy
service is very important and will likely serve as a major differentiating
factor for privacy conscious users.

TODO: Discuss trust models

More recently the global legislative landscape with regard to personal data
collection, retention, and psuedo-anonymisation has seen significant activity
with differing requirements active in different juristrictions. The impact of
these changes on data pertaining to the users of Internet Service Providers and
specifically DNS open resolvers is not fully understood at the time of writing.
It may be in certain cases that these requirement may well conflict with the
IETF's end-2-end principles.

This document also attempts to outline recommendations for data handling for
operators of DNS Privacy services.

In addition, to provide a means for clients to evaluate the privacy properties
of DNS Privacy services this document lays out how entities may publish a DNS
Privacy Practice Statement (DPPS) document.


# Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in [@!RFC8174].

From [@?I-D.ietf-dprive-dtls-and-tls-profiles]:

* Privacy-enabling DNS server: A DNS server that implements DNS-
over-TLS [RFC7858] and may optionally implement DNS-over-DTLS [RFC8094].
The server should also offer at least one of the credentials described in
Section 8 and implement the (D)TLS profile described in Section 9.

* DNS Privacy Service: TODO

# Server capabilities to maximise DNS privacy

In addition to Section 9 of [@?I-D.ietf-dprive-dtls-and-tls-profiles] privacy-enabling DNS servers SHOULD offer the following capabilities

* QNAME minimisation [RFC7816]
* EDNS padding as per [@!RFC7830] and [@?I-D.ietf-dprive-padding-policy]
* A port selection of both 853 and 443 (to aid with blocking of port 853?) 
* EDNS Keepalive/DSO to manage TCP/TLS connections
* As a minimum honour EDNS Client Subnet requests with a SOURCE PREFIX-LENGTH value of 0 (possibly never send this)
* Do not require TLS session re-use (or EDNS0 cookies)

DNSSEC validation?

Offer a .onion service endpoint?

## Availability - denial of service to users

## Authentication of DNS privacy services

Commit to a public identity

### Generation, maintenance and publication of certificates

### Management of SPKI pins

### TLSA records

# Configuration management

## Limitations of using a pure (DNS ignorant) TLS proxy

## Anycast deployments


# Server data handling

## Logging and monitoring

## Data retention 

## User tracking

## Providing data to third-parties

## Psuedo-anonymisation and de-identification methods


# DNS privacy policy statement

## Current privacy statements

TODO: Compare main elements of Google vs Quad9 vs OpenDNS

## Recommended contents of a DPPS

## Enforcement/accountability

Transparency reports

Independent monitoring where possible

* ECS, etc.
* Filtering
* Uptime

# IANA considerations

None

# Security considerations

TODO: e.g. new issues for DoS defence, server admin policies

# Acknowledgements



# Changelog


draft-dickinson-dprive-bcp-op-00

* Initial commit


{backmatter}



