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
      country = "United Kingdom"
#   [[author]]
#    initials="B."
#    surname="Overeinder"
#    fullname="Benno J. Overeinder"
#    organization = "NLnet Labs"
#      [author.address]
#      email = "benno@nlnetLabs.nl"
#      [author.address.postal]
#      streets = ["Science Park 140"]
#      city = "Amsterdam"
#      code = "1098 XH"
#      country = "The Netherlands"
    [[author]]
     initials="R."
     surname="van Rijswijk-Deij"
     fullname="Roland M. van Rijswijk-Deij"
     organization = "SURFnet bv"
       [author.address]
       email = "roland.vanrijswijk@surfnet.nl"
       [author.address.postal]
       streets = ["PO Box 19035 "]
       city = "Utrecht"
       code = "3501 DA Utrecht"
       country = "The Netherlands"
#    [[author]]
#     initials="J."
#     surname="Todd"
#     fullname="John Todd"
#     organization = "Quad9"
#       [author.address]
#       email = "jtodd@quad9.net"
#       [author.address.postal]
#       streets = ["1442 A Walnut Street", "Suite 501"]
#       city = "Berkeley"
#       code = "CA 94709"
#       country = "United States"
    [[author]]
     initials="A."
     surname="Mankin"
     fullname="Allison Mankin"
     organization = "Salesforce"
       [author.address]
       email = "allison.mankin@gmail.com"
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
providing a means for clients to evaluate the privacy properties of a given DNS
privacy service. In particular, the framework identifies the elements that
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


* Privacy-enabling DNS server: A DNS server that implements DNS-over-TLS
  [RFC7858] and may optionally implement DNS-over-DTLS [RFC8094]. The server
  should also offer at least one of the credentials described in Section 8 of
  [@?I-D.ietf-dprive-dtls-and-tls-profiles] and implement the (D)TLS profile
  described in Section 9 of [@?I-D.ietf-dprive-dtls-and-tls-profiles].

* DPPPS: DNS Privacy Policy and Practice Statement, see
  (#dns-privacy-policy-and-practice-statement).

* DNS privacy service: The service that is offered via a privacy-enabling DNS
  server and is documented either in an informal statement of policy and
  practice with regard to users privacy or a formal DPPPS.

# Server capabilities to maximise DNS privacy

## General capabilities

In addition to Sections 9 and 11.1 of [@!I-D.ietf-dprive-dtls-and-tls-profiles] DNS privacy services SHOULD offer the following capabilities/options:

* QNAME minimisation [@!RFC7816]
* Management of TLS connections to optimise performance for clients using either
  * [@!RFC7766] and EDNS(0) Keepalive [@!RFC7828] and/or 
  * DNS Stateful Operations [@!I-D.ietf-dnsop-session-signal] 
* No requirement that clients must use TLS session resumption [@!RFC5077] (or
  Domain Name System (DNS) Cookies [@!RFC7873])

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
IP address if the 'main' DNS privacy address filters responses? Or simply just
to say that the DNS privacy service should not differ from the 'normal' DNS
service in terms of such options.

## Client query obfuscation

Since queries from recursive resolvers to authoritative servers are performed
using cleartext (at the time of writing), resolver services need to consider the
extent to which they may be directly leaking information about their client
community via these upstream queries and what they can do to mitigate this
further. Note, that even when all the relevant techniques described above are
employed there may still be attacks possible, e.g.
[@Pitfalls-of-DNS-Encryption]. For example, a resolver with a very small
community of users risks exposing data in this way and MAY want to obfuscate
this traffic by mixing it with 'generated' traffic to make client
characterisation harder.

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
credentials is new to DNS operators.

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

Some operators may choose to implement DNS-over-TLS using a TLS proxy (e.g.
[nginx](https://nginx.org/) or [haproxy](https://www.haproxy.org/)) in front of
a DNS nameserver because of proven robustness and capacity when handling large
numbers of client connections, load balancing capabilities and good tooling.
Currently, however, because such proxies typically have no specific handling of
DNS as a protocol over TLS or DTLS using them can restrict traffic management at
the proxy layer and at the DNS server. For example, all traffic received by a
nameserver behind such a proxy will appear to originate from the proxy and DNS
techniques such as ACLs or RRL will be hard or impossible to implement in the
nameserver.

## Anycast deployments

TODO:

# Server data handling

The following are common activities for DNS service operators and in all cases
should be minimised or completely avoided if possible for DNS privacy services.
If data is retained it should be encrypted and either aggregated,
psuedo-anonymised or de-identified whenever possible.

* Logging and Monitoring: Only that required to sustain operation of the service
  and meet regulatory requirements.
* Data retention: Data SHOULD be retained for the shortest period deemed
  operationally feasible.
* User tracking: DNS privacy services SHOULD not track users. An exception may
  be malicious or anomalous use of the service.
* Providing data to third-parties (sharing, selling or renting): Operators
  SHOULD not provide data to third-parties without explicit consent from users
  (simply using the resolution service itself does not constitute consent).
* Access to stored personal data: Access SHOULD be minimised to only those
  personal who require access to perform operational duties.

## Psuedo-anonymisation and de-identification methods

There is active discussion in the space of effective psuedo-anonymisation of
personal data in DNS query logs. To-date this has focussed on
psuedo-anonymisation of client IP addresses, however there are as yet no
standards for this that are unencumbered by patents. This section briefly
references some know methods in this space at the time of writing.

### ipcipher

[@ipcipher-spec] is a psuedo-anonymisation technique which encrypts IPv4 and IPv6
addresses such that any address encrypts to a valid address. At the time of
writing the specification is under review and may be the subject of a future
IETF draft.

### Bloom filters

There is also on going work in the area of using Bloom filters [@bloom-filter]
as a privacy-enhancing technology for DNS monitoring. The goal of this work is
to allow operators to identify so-called Indicators of Compromise (IOCs)
originating from specific subnets without storing information about,
or be able to monitor the DNS queries of an individual user.

TODO: Add a reference to this work

# DNS privacy policy and practice statement

## Current privacy statements

TODO: Compare main elements of Google vs Quad9 vs OpenDNS

## Recommended contents of a DPPPS

* Policy: This section should explain the policy for gathering and disseminating
  information collected by the DNS privacy service.
  * Specify clearly what data (including whether it is aggregated,
    psuedo-anonymised or de-identified) is
    * Collected and retained by the operator (and for how long)
    * Shared with, sold or rented to third-parties
  * Specify any exceptions to the above, for example malicious or anomalous
    behaviour
  * Declare any third-party affiliations or funding
  * Whether user DNS data is correlated or combined with any other personal
    information held by the operator
* Practice: This section should explain the current operational practices of the
  service.
  * Specify any temporary or permanent deviations from the policy for
    operational reasons
  * Provide specific details of which capabilities are provided on which address
    and ports
  * Specify the authentication name to be used (if any)
  * Specify the SPKI pinsets to be used (if any) and policy for rolling keys
  * Provide a contact email address for the service

## Enforcement/accountability

Transparency reports may help with building user trust that operators adhere to their policies and practices.

Independent monitoring should be performed where possible of:

* ECS, QNAME minimisation, EDNS(0) padding, etc.
* Filtering
* Uptime

# IANA considerations

None

# Security considerations

TODO: e.g. New issues for DoS defence, server admin policies

# Acknowledgements

Many thanks to John Dickinson for review of and input to the first draft of this
document.

Thanks to Benno Overeinder and John Todd for discussions on this topic. 


# Changelog

draft-dickinson-dprive-bcp-op-00

* Initial commit


<reference anchor='ipcipher-spec'
 target='https://powerdns.org/ipcipher/'>
    <front>
        <title>ipcipher: encrypting IP addresses</title>
        <author initials='B.' surname='Hubert' fullname='Bert Hubert'>
            <organization>PowerDNS</organization>
        </author>
        <date year='2018'/>
    </front>
</reference>

<reference anchor='Pitfalls-of-DNS-Encryption'
 target='https://www.ietf.org/mail-archive/web/dns-privacy/current/pdfWqAIUmEl47.pdf'>
    <front>
        <title>Pretty Bad Privacy: Pitfalls of DNS Encryption</title>
        <author initials='H.' surname='Shulman' fullname='Haya Shulman'>
            <organization>Fachbereich Informatik, Technische Universität Darmstadt</organization>
        </author>
        <date year='2014'/>
    </front>
</reference>

<reference anchor='bloom-filter'
 target='Communications of The ACM, 13(7):422–426, July 1970'>
    <front>
        <title>Space/Time Trade-offs in Hash Coding with Allowable Errors</title>
        <author initials='B.' surname='Bloom' fullname='Burton H. Bloom'>
        </author>
        <date year='1970'/>
    </front>
</reference>

{backmatter}



