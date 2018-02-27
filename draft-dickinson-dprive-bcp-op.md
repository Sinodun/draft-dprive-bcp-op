%%%
    Title = "Recommendations for DNS Privacy Service Operators"
    abbrev = "DNS Privacy Service Recommendations"
    category = "bcp"
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
%%%

.# Abstract
This document presents operational, policy and security considerations for DNS
operators who choose to offer DNS Privacy services including, but not limited
to, DNS-over-TLS [@!RFC7858].

This document also presents a framework to assist writers of DNS Privacy Policy
and Practices Statements (analogous to DNS Security Extensions (DNSSEC) Policies
and DNSSEC Practice Statements described in [@RFC6841]).

{mainmatter}

# Introduction

[NOTE: This document is submitted to the IETF for initial review and for
feedback on the best forum for future versions of this document.]

The Domain Name System (DNS) was not originally designed with strong security or
privacy mechanisms. [@!RFC7626] describes the privacy issues associated with the
use of the DNS by Internet users including those related to un-encrypted DNS
messages on the wire and DNS 'query log' data maintained on DNS servers.

Two documents that provide ways to increase DNS privacy between DNS clients and
DNS servers are:

* Specification for DNS over Transport Layer Security (TLS) [@!RFC7858],
  referred to here as simply 'DNS-over-TLS'
* DNS over Datagram Transport Layer Security (DTLS) [@!RFC8094], referred to
  here simply as 'DNS-over-DTLS'. Note that this document has the Category of
  Experimental.

Both documents are limited in scope to communications between stub clients and
recursive resolvers and the same scope is applied to this document.
Other documents that provide further specifications related to DNS
privacy include  [@?I-D.ietf-dprive-dtls-and-tls-profiles], [@!RFC7830] and
[@!I-D.ietf-dprive-padding-policy].

Note that [@?I-D.ietf-dnsop-dns-tcp-requirements] discusses operational
requirements for DNS-over-TCP but does not provide specific guidance on DNS
privacy protocols.

This document includes operational guidance related to [@!RFC7858] and
[@!RFC8094].

In recent years there has been an increase in the availability of "open"
resolvers. Operators of some open resolvers choose to enable protocols which
encrypt DNS on the wire to cater for users who are privacy conscious. Whilst
protocols that encrypt DNS messages on the wire provide protection against
certain attacks, the resolver operator still has (in principle) full visibility
of the query data for each user and therefore a trust relationship exists. The
ability of the operator to provide a transparent, well documented, and secure
privacy service will likely serve as a major differentiating factor for privacy
conscious users.

More recently the global legislative landscape with regard to personal data
collection, retention, and psuedo-anonymisation has seen significant activity
with differing requirements active in different jurisdictions. The impact of
these changes on data pertaining to the users of Internet Service Providers and
specifically DNS open resolvers is not fully understood at the time of writing.
It may be in certain cases that these requirement may well conflict with the
IETF's end-to-end encryption principles.

This document also attempts to outline options for data handling for
operators of DNS privacy services.

TODO/QUESTION: Discuss alternative (non-standard) schemes not covered by this
document e.g. DNSCrypt, IPsec, VPNs. For example, should the data handling
practices be recommended for any service that encrypts DNS/makes claims about
DNS data privacy or is that outside the scope of this document?

This document also presents a framework to assist writers of DNS Privacy Policy
and Practice Statements (DPPPS). These are documents an operator can publish
outlining their operational practices and commitments with regard to privacy
providing a means for clients to evaluate the privacy properties of DNS a given
privacy services. In particular, the framework identifies the elements that
should be considered in formulating a DPPPS. It does not, however, define a
particular Policy or Practice Statement, nor does it seek to provide legal
advice or recommendations as to the contents.

Community knowledge about operational practices can change quickly, and
experience shows that a Best Current Practice (BCP) document about privacy and
security is a point-in-time statement. Readers are advised to seek out any
errata or updates that apply to this document.


# Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in [@!RFC8174].


* Privacy-enabling DNS server: A DNS server that implements DNS- over-TLS
  [RFC7858] and may optionally implement DNS-over-DTLS [RFC8094]. The server
  should also offer at least one of the credentials described in Section 8 and
  implement the (D)TLS profile described in Section 9 of
  [@?I-D.ietf-dprive-dtls-and-tls-profiles].

* DPPPS: DNS Privacy Policy and Practice Statement, see (#dns-privacy-policy-and-practice-statement).

* DNS privacy service: A resolver that offers service via a privacy-enabling DNS
  server and provides either an informal statement of policy and practice with
  regard to users privacy or a formal DPPPS.

# Server capabilities to maximise DNS privacy

## General capabilities

In addition to Sections 9 and 11.1 of [@!I-D.ietf-dprive-dtls-and-tls-profiles] DNS privacy services SHOULD offer the following capabilities/options:

* QNAME minimisation [@!RFC7816]
* Management of TLS connections to optimise performance for clients using either
  * [@!RFC7766] and EDNS(0) Keepalive [@!RFC7828] and/or 
  * DNS Stateful Operations [@!I-D.ietf-dnsop-session-signal] 
* No requirement that clients use TLS session resumption [@!RFC5077] (or Domain
  Name System (DNS) Cookies [@!RFC7873])

DNS privacy services MAY offer the following capabilities:

* DNS privacy service on both port 853 and 443 (to circumvent blocking of
  port 853)
* A .onion [@RFC7686] service endpoint
* Aggressive Use of DNSSEC-Validated Cache [@RFC8198] to reduce the number of
  queries to authoritative servers to increase privacy.
* Run a copy of the root zone on loopback [@RFC7706] to avoid making queries to
  the root servers that might leak information.


QUESTION: Should we say anything here about filtering responses or DNSSEC
validation e.g. operators SHOULD provide an unfiltered service on an alternative
IP address if the 'main' address filters responses?

## Client query obfuscation

Since queries from recursive resolvers to authoritative servers are performed
using cleartext (at the time of writing), resolver services need to consider if
they may be leaking information about their client community via these upstream
queries (even when relevant techniques described above are employed). For
example, a resolver with a very small community of users risks exposing data in
this way and MAY want to obfuscate this traffic by mixing it with 'generated'
traffic to make client characterisation harder.

## Availability

As a general model of trust between users and service providers DNS privacy
services should have high availability. Denying access to an encrypted protocol
for DNS queries forces the user to switch providers, fallback to cleartext or
accept no DNS service for the outage.

## Authentication of DNS privacy services

To enable users to select a 'Strict Privacy' usage profile
[@?I-D.ietf-dprive-dtls-and-tls-profiles] DNS privacy services should provide
credentials in the form of either X.509 certificates, SPKI pinsets or TLSA
records. This in effect commits the DNS privacy service to a public identity
users will trust.

Anecdotal evidence to date highlights this requirement as one of the more
challenging aspects of running a DNS privacy service as management of such
credentials is new to DNS operators and system administrators.

### Generation and publication of certificates

It is RECOMMENDED that operators: 

* Choose a short, memorable authentication name for their service
* Automate the generation and publication of certificates
* Monitor certificates to prevent accidental expiration of certificates

### Management of SPKI pins

TODO

### TLSA records

TODO

# Operational management

## Limitations of using a pure TLS proxy

Some operators may choose to implement DNS-over-TLS using a combination of a TLS
proxy (e.g. [nginx](https://nginx.org/) or [haproxy](https://www.haproxy.org/))
because of proven robustness and capacity when handling large numbers of client
connections and good tooling. Currently, however, because such proxies typically
have no specific handling of DNS as a protocol over TLS or DTLS using them can
restrict traffic management at the proxy layer and at the DNS server. For
example, all traffic received by a nameserver behind such a proxy will appear to
originate from the proxy and DNS techniques such as ACLs or RRL will be hard or
impossible to implement in the nameserver.

## Anycast deployments

TODO:

# Server data handling

## Logging and monitoring

## Data retention 

## User tracking

## Providing data to third-parties

## Psuedo-anonymisation and de-identification methods

Bloom filters

ipcipher


# DNS privacy policy and practice statement

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

Many thanks to John Dickinson for review of and input to the first draft of this document.


# Changelog


draft-dickinson-dprive-bcp-op-00

* Initial commit


{backmatter}



