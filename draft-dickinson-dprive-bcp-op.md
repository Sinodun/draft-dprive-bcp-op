%%%
    Title = "Recommendations for DNS Privacy Service Operators"
    abbrev = "DNS Privacy Service Recommendations"
    category = "bcp"
    docName= "draft-dickinson-bcp-op-00"
    ipr = "trust200902"
    area = "Internet"
    workgroup = "dprive"
    keyword = ["DNS"]
    date = 2018-03-05T00:00:00Z
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
   [[author]]
    initials="B."
    surname="Overeinder"
    fullname="Benno J. Overeinder"
    organization = "NLnet Labs"
      [author.address]
      email = "benno@nlnetLabs.nl"
      [author.address.postal]
      streets = ["Science Park 140"]
      city = "Amsterdam"
      code = "1098 XH"
      country = "The Netherlands"
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
operators who choose to offer DNS Privacy services.

This document also presents a framework to assist writers of DNS Privacy Policy
and Practices Statements (analogous to DNS Security Extensions (DNSSEC) Policies
and DNSSEC Practice Statements described in [@RFC6841]).

{mainmatter}

# Introduction

[NOTE: This document is submitted to the IETF for initial review and for
feedback on the best forum for future versions of this document.]

The Domain Name System (DNS) is at the core of the Internet. Everything a user
does knowingly or unknowingly on a device connected to the Internet makes use
of the DNS. The DNS was not originally designed with strong security or
privacy mechanisms. 

This document provides operational guidance related to DNS over encrypted
transports.

In recent years DNS resolvers which cater to a general audience of Internet
users have become more common. In the process of DNS resolving becoming at
least partially separated from general network ownership or access service
provision to users, a space has emerged for end-clients putting specific
demands on DNS resolving services, for instance on service quality and privacy
features. Operators of some resolvers may choose to enable protocols which
encrypt DNS on the wire to cater for users who are privacy conscious, and
commit to abstain from tracking or analyzing patterns of DNS requests from
individual users or groups of users or making such DNS request data available
to third-parties.

Whilst protocols that encrypt DNS messages on the wire provide protection
against certain attacks, the resolver operator still has (in principle) full
visibility of the query data for each user. Therefore, a trust relationship
exists. The ability of the operator to provide a transparent, well documented,
and secure privacy service will likely serve as a major differentiating factor
for privacy conscious users.

More recently the global legislative landscape with regard to personal data
collection, retention, and psuedonymization has seen significant activity
with differing requirements active in different jurisdictions. The impact of
these changes on data pertaining to the users of Internet Service Providers and
specifically DNS open resolvers is not fully understood at the time of writing.
In certain cases that these requirement may well conflict with the
IETF's end-to-end encryption principles.

This document also attempts to outline options for data handling for
operators of DNS privacy services.

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

## Scope

Whilst [@!RFC7626] describes the privacy issues and risks associated
with the use of the DNS by Internet users. This document is concerned with
best practice considerations for operators providing DNS privacy services on a
Privacy-enabling DNS server. It covers the following areas (taken from
[@!RFC7626]):

* data on the wire between a stub and a resolver
* data "at rest" on a recursive server (in logs and in the cache)
* data sent onwards from the resolver

## Documents

There are various documents that describe protocol changes that have either
the potential to increase or
decrease the privacy of the DNS. Note this does not imply that some documents
are good or bad, better or worse, just that some features or usages of DNS may
bring benefits at the price of a reduction in privacy. These documents are
listed in the following three sections.

### Documents with the potential to increase DNS privacy

These documents are limited in scope to communications between stub
clients and recursive resolvers.

* Specification for DNS over Transport Layer Security (TLS) [@!RFC7858],
  referred to here as simply 'DNS-over-TLS'.
* DNS over Datagram Transport Layer Security (DTLS) [@!RFC8094], referred to
  here simply as 'DNS-over-DTLS'. Note that this document has the Category of
  Experimental.
* DNS over HTTPS [@!I-D.ietf-doh-dns-over-https]
* Usage Profiles [@!RFC8310]
* Padding [@!RFC7830] and [@!I-D.ietf-dprive-padding-policy]

These documents apply to recursive to authoritative DNS but are relevant when
considering the operation of a recursive server.

* Qname minimization [@!RFC7816]

### Documents with the potential to decrease DNS privacy

* A DNS Packet Capture Format [@?I-D.ietf-dnsop-dns-capture-format]
* Client Subnet in DNS Queries [@!RFC7871]
* Passive DNS TODO: need ref

### Related documents

* Operational requirements for DNS-over-TCP [@?I-D.ietf-dnsop-dns-tcp-requirements]
* TLS connection management [@!RFC7766]
* EDNS(0) Keepalive [@!RFC7828] 
* DNS Stateful Operations [@!I-D.ietf-dnsop-session-signal]
* TLS session resumption [@!RFC5077]
* DNS Cookies [@!RFC7873])

# Terminology

The key words described in [@!RFC8174] are not used in this document. 
However, in order to give some guidence on the importance of the 
various recommendations in this document the following terms are
used in decending order of importance

* EXPECTED
* COULD
* MIGHT

Privacy terminology is as described in Section 3 of [@!RFC6973].

DNS terminology is as described in [@?I-D.ietf-dnsop-terminology-bis] 
with the following additions:

* Privacy-enabling DNS server: A DNS server (most likely a Full-service 
  resolver) that implements DNS-over-TLS
  [RFC7858] and may optionally implement DNS-over-DTLS [RFC8094]. The server
  should also offer at least one of the credentials described in Section 8 of
  [@!RFC8310] and implement the (D)TLS profile
  described in Section 9 of [@!RFC8310].

* DPPPS: DNS Privacy Policy and Practice Statement, see
  (#dns-privacy-policy-and-practice-statement).

* DNS privacy service: The service that is offered via a privacy-enabling DNS
  server and is documented either in an informal statement of policy and
  practice with regard to users privacy or a formal DPPPS.

# Recommendations for DNS Privacy Services

## Transport recommendations

A DNS privacy service is EXPECTED to be made available over one or more of the following transports

* DNS-over-TLS
* DNS-over-HTTPS

A DNS privacy service COULD also be provided over DNS-over-DTLS, IPSec, DNSCrypt or VPNs.
However, use of these transports for DNS are not standardized and any discussion of 
best practice for providing such service is out of scope for ths document.

## Protocol recommendations

In the case of DNS-over-TLS, TLS profiles from Section 9 and the Countermeasures 
to DNS Traffic Analysis from section 11.1of [@!RFC8310] are EXPECTED to be used.

DNS privacy services COULD also consider the following capabilities/options:

* QNAME minimisation [@!RFC7816]
* Management of TLS connections to optimise performance for clients using either
  * [@!RFC7766] and EDNS(0) Keepalive [@!RFC7828] and/or 
  * DNS Stateful Operations [@!I-D.ietf-dnsop-session-signal] 
* Clients should not be required to use TLS session resumption [@!RFC5077] or Domain Name System (DNS) Cookies [@!RFC7873]

DNS privacy services MIGHT offer the following capabilities:

* DNS privacy service on both port 853 and 443 (to circumvent blocking of
  port 853)
* A .onion [@RFC7686] service endpoint
* Aggressive Use of DNSSEC-Validated Cache [@RFC8198] to reduce the number of
  queries to authoritative servers to increase privacy.
* Run a copy of the root zone on loopback [@RFC7706] to avoid making queries to
  the root servers that might leak information.
* DNS privacy service should not differ from the 'normal' DNS
  service in terms of such options as filtering, 
  DNSSEC as they would on the providers non-encrypted service

## Client query obfuscation

Since queries from recursive resolvers to authoritative servers are performed
using cleartext (at the time of writing), resolver services need to consider the
extent to which they may be directly leaking information about their client
community via these upstream queries and what they can do to mitigate this
further. Note, that even when all the relevant techniques described above are
employed there may still be attacks possible, e.g.
[@Pitfalls-of-DNS-Encryption]. For example, a resolver with a very small
community of users risks exposing data in this way and COULD obfuscate
this traffic by mixing it with 'generated' traffic to make client
characterisation harder.

## Availability

DNS privacy services are EXPECTED be engineered for high availability. A failed 
DNS privacy service could force the user to switch providers, fallback to cleartext or
accept no DNS service for the outage.

## Authentication of DNS privacy services

To enable users to select a 'Strict Privacy' usage profile
[@!RFC8310] DNS privacy services should provide
credentials in the form of either X.509 certificates, SPKI pinsets or TLSA
records. This in effect commits the DNS privacy service to a public identity
users will trust.

Anecdotal evidence to date highlights this requirement as one of the more
challenging aspects of running a DNS privacy service as management of such
credentials is new to DNS operators.

### Generation and publication of certificates

It is recommended that operators: 

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
[nginx](https://nginx.org/), [haproxy](https://www.haproxy.org/) or 
[stunnel](https://kb.isc.org/article/AA-01386/0/DNS-over-TLS.html)) in front of
a DNS nameserver because of proven robustness and capacity when handling large
numbers of client connections, load balancing capabilities and good tooling.
Currently, however, because such proxies typically have no specific handling of
DNS as a protocol over TLS or DTLS using them can restrict traffic management at
the proxy layer and at the DNS server. For example, all traffic received by a
nameserver behind such a proxy will appear to originate from the proxy and DNS
techniques such as ACLs or RRL will be hard or impossible to implement in the
nameserver.

Say something about dnsdist

## Anycast deployments

TODO:

# Server data handling

The following are common activities for DNS service operators and in all cases
should be minimised or completely avoided if possible for DNS privacy services.
If data is retained it should be encrypted and either aggregated,
psuedonymised or anonymised whenever possible.

* Logging and Monitoring: Only that required to sustain operation of the service
  and, to the extent that such exists, meet regulatory requirements.
* Data SHOULD only be retained for the shortest period deemed operationally useful.
* DNS privacy services SHOULD not track users except for the particular purpose of 
  detecting and remedying technically malicious or anomalous use of the service.
* Operators SHOULD not provide data to third-parties without explicit consent from users
  (simply using the resolution service itself does not constitute consent).
* Data access SHOULD be minimised to only those
  personal who require access to perform operational duties.

## Psuedonymisation and Anonymisation methods

There is active discussion in the space of effective psuedonymisation of
personal data in DNS query logs. To-date this has focussed on
psuedonymisation of client IP addresses, however there are as yet no
standards for this that are unencumbered by patents. This section briefly
references some known methods in this space at the time of writing.

### ipcipher

[@ipcipher-spec] is a psuedonymisation technique which encrypts IPv4 and IPv6
addresses such that any address encrypts to a valid address. At the time of
writing the specification is under review and may be the subject of a future
IETF draft.

### Bloom filters

There is also on-going work in the area of using Bloom filters as a
privacy-enhancing technology for DNS monitoring [@DNS-bloom-filter]. The goal of
this work is to allow operators to identify so-called Indicators of Compromise
(IOCs) originating from specific subnets without storing information about, or
be able to monitor the DNS queries of an individual user.


# DNS privacy policy and practice statement

## Recommended contents of a DPPPS

1. Policy: This section should explain, with reference to section 3 of this document
  the policy for gathering and disseminating
  information collected by the DNS privacy service.
  1.1. Specify clearly what data (including whether it is aggregated,
    psuedonymised or anonymized) is
    1.1.1. Collected and retained by the operator (and for how long)
    1.1.2. Shared with, sold or rented to third-parties
  1.2. Specify any exceptions to the above, for example malicious or anomalous
    behaviour
  1.3. Declare any third-party affiliations or funding
  1.4. Whether user DNS data is correlated or combined with any other personal
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

## Current privacy statements

### Google
https://developers.google.com/speed/public-dns/privacy
Describes what they log and how long for. However it is missing any discussion of
* Temorary Logs 
  * Stores full IP address
  * Retention 24-48 hours
* Permanent Logs
  * Stores user's geolocation information: i.e. geocode, region ID, city ID, and metro code

### Quad9
https://www.quad9.net/policy/

### OpenDNS
https://www.cisco.com/c/en/us/about/legal/privacy-full.html

### Cloudflare
https://developers.cloudflare.com/1.1.1.1/commitment-to-privacy/
https://developers.cloudflare.com/1.1.1.1/commitment-to-privacy/privacy-policy/privacy-policy/
https://developers.cloudflare.com/1.1.1.1/commitment-to-privacy/privacy-policy/firefox/


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

Many thanks to Amelia Andersdotter for a very thorough review of this document 
and to John Dickinson for review of and input to the early drafts of this document.

Thanks to Benno Overeinder and John Todd for discussions on this topic. 


# Changelog
draft-dickinson-dprive-bcp-op-001

* reworked the Terminology, Introduction and Scope
* Added Document section
* Applied most of Amelia Andersdotter's suggested changes.

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

<reference anchor='DNS-bloom-filter'
 target=' https://tnc18.geant.org/getfile/3823'>
    <front>
        <title>Let a Thousand Filters Bloom. DNS-Based Threat Monitoring That Respects User Privacy</title>
        <author initials='R.' surname='van Rijswijk-Deij' fullname='Roland van Rijswijk-Deij'>
         <organization>SURFnet bv</organization>
        </author>
        <author initials='M.' surname='Bomhoff' fullname='Matthijs Bomhoff'>
         <organization>Quarantainenet B.V.</organization>
        </author>
        <author initials='R.' surname='Dolmans' fullname='Ralph Dolmans'>
         <organization>NLnet Labs Foundation</organization>
        </author>
        <date year='2018'/>
    </front>
</reference>

{backmatter}



