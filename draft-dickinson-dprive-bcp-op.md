%%%
    Title = "Recommendations for DNS Privacy Service Operators"
    abbrev = "DNS Privacy Service Recommendations"
    category = "bcp"
    docName= "draft-dickinson-bcp-op-01"
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
feedback on the best forum for future versions of this document. Discussion of
DoH [@!I-D.ietf-doh-dns-over-https] is included here
in anticipation of that draft progressing to be an RFC.]

The Domain Name System (DNS) is at the core of the Internet; almost every
activity on the Internet starts with a DNS query (and often several). However
the DNS was not originally designed with strong security or privacy mechanisms.
A number of developments have taken place in recent years which aim to increase
the privacy of the DNS system and these are now seeing some deployment. This
latest evolution of the DNS presents new challenges to operators and this
document attempts to provide an overview of considerations for privacy focussed
DNS services.

In recent years there has also been an increase in the availability of "open
resolvers" [@?I-D.ietf-dnsop-terminology-bis] which users may prefer to use
instead of the default network resolver because they offer a specific feature
(e.g. good reachability, encrypted transport, strong privacy policy, filtering
(or lack of), etc.). These open resolvers have tended to be at the forefront of
adoption of privacy related enhancements but it is anticipated that operators of
other resolver services will follow.

Whilst protocols that encrypt DNS messages on the wire provide protection
against certain attacks, the resolver operator still has (in principle) full
visibility of the query data for each user. Therefore, a trust relationship
exists. The ability of the operator to provide a transparent, well documented,
and secure privacy service will likely serve as a major differentiating factor
for privacy conscious users.

It should also be noted that the choice of a user to configure a single resolver
(or a fixed set of resolvers) and an encrypted transport to use in all network
environments has both advantages and disadvantages. For example the user has a
clear expectation of which resolvers have visibility of their query data however
this resolver/transport selection may provide an added mechanism to track them
as they move across network environments.

More recently the global legislative landscape with regard to personal data
collection, retention, and pseudonymization has seen significant activity with
differing requirements active in different jurisdictions. For example the user
of a service and the service itself may be in jurisdictions with conflicting
legislation. It is an untested area that simply using a DNS resolution service
constitutes consent from the user for the operator to process their query data.
The impact of recent legislative changes on data pertaining to the users of both
Internet Service Providers and DNS open resolvers is not fully understood at the
time of writing.

This document has two main goals:

* To provide operational guidance related to DNS over encrypted
transports and to outline recommendations for data handling for
operators of DNS privacy services.

* To introduce the DNS Privacy Policy
and Practice Statement (DPPPS) and present a framework to assist writers of 
this document. A DPPPS is a document an operator can publish
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
best practice considerations for operators providing DNS privacy services. It
includes (but is not limited to) considerations in the following areas (taken from [@!RFC7626]):

1. Data on the wire between a stub and a resolver
2. Data "at rest" on a recursive server (e.g. in logs)
3. Data sent onwards from the resolver either on the wire or shared with a third
party

Whilst the issues raised here are targeted at those operators who choose to
offer a DNS Privacy service, considerations for areas 2 and 3 could equally
apply to operators who offer DNS only over unencrypted transports but who would
like to align with privacy best practice.

Privacy considerations specifically from the perspective of an end user, or
those for operators of authoritative nameservers are out of scope.

## Documents

There are various documents that describe protocol changes that have the
potential to either increase or decrease the privacy of the DNS. Note this does
not imply that some documents are good or bad, better or worse, just that (for
example) some features may bring functional benefits at the price of a reduction
in privacy and conversely some features increase privacy with an accompanying
increase in complexity. A selection of the most relevant documents are listed in
the following three sections for reference, however, this is neither an
exhaustive list nor a definitive statement on the characteristic of the
document.

### Documents with the potential to increase DNS privacy

These documents are limited in scope to communications between stub
clients and recursive resolvers:

* 'Specification for DNS over Transport Layer Security (TLS)' [@!RFC7858],
  referred to here as simply 'DNS-over-TLS'.
* 'DNS over Datagram Transport Layer Security (DTLS)' [@!RFC8094], referred to
  here simply as 'DNS-over-DTLS'. Note that this document has the Category of
  Experimental.
* 'DNS Queries over HTTPS (DoH)' [@!I-D.ietf-doh-dns-over-https]
* 'Usage Profiles for DNS over TLS and DNS over DTLS' [@!RFC8310]
* 'The EDNS(0) Padding Option' [@!RFC7830] and 'Padding Policy for EDNS(0)' [@!I-D.ietf-dprive-padding-policy]

These documents apply to recursive to authoritative DNS but are relevant when
considering the operation of a recursive server:

* 'DNS Query Name Minimisation to Improve Privacy' [@!RFC7816] referred to here as simply 'QNAME minimization'

### Documents with the potential to decrease DNS privacy

These documents relate to functionality that could provide increased tracking of
user activity as a side effect:

* Client Subnet in DNS Queries [@!RFC7871]
* DNS Cookies [@!RFC7873])
* TLS session resumption [@!RFC5077]
* A DNS Packet Capture Format [@?I-D.ietf-dnsop-dns-capture-format]
* Passive DNS TODO: need ref

### Related operational documents

* DNS Transport over TCP - Implementation Requirements [@!RFC7766]
* Operational requirements for DNS-over-TCP [@?I-D.ietf-dnsop-dns-tcp-requirements]
* The edns-tcp-keepalive EDNS0 Option [@!RFC7828]
* DNS Stateful Operations [@!I-D.ietf-dnsop-session-signal]

# Terminology

The key words described in [@!RFC8174] are not used in this document because the
intention here is not to prescribe policy but to provide indicators of best
practice. Therefore, in order to give some guidance on the importance of the 
various recommendations in this document the following terms are
used in descending order of importance

* EXPECTED (similar to [@!RFC8174] MUST)
* OUGHT (similar to [@!RFC8174] OUGHT)
* MIGHT (similar to [@!RFC8174] MAY)

Privacy terminology is as described in Section 3 of [@!RFC6973].

DNS terminology is as described in [@?I-D.ietf-dnsop-terminology-bis] 
with the following additions:

* Privacy-enabling DNS server: A DNS server (most likely a Full-service
  resolver) that implements DNS-over-TLS [RFC7858] and/or DOH
  [@!I-D.ietf-doh-dns-over-https], and may optionally implement DNS-over-DTLS
  [RFC8094]. A DNS-over-(D)TLS server should also offer at least one of the
  credentials described in Section 8 of [@!RFC8310] and implement the (D)TLS
  profile described in Section 9 of [@!RFC8310].
  
  [TODO: This updates [@!RFC8310]]

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

A DNS privacy service OUGHT also be provided over DNS-over-DTLS, IPSec, DNSCrypt
or VPNs. However, use of these transports for DNS are not standardized and any
discussion of best practice for providing such service is out of scope for this
document.

## Protocol recommendations

In the case of DNS-over-TLS, TLS profiles from Section 9 and the Countermeasures 
to DNS Traffic Analysis from section 11.1 of [@!RFC8310] are EXPECTED to be used. This includes but is not limited to:

* Implementing only (D)TLS 1.2 or later
* Adhering to [@RFC7525]
* Implementing EDNS(0) Padding [RFC7830]
* Honoring a SOURCE PREFIX-LENGTH set to 0 in a query containing the EDNS(0)
  Client subnet option

DNS privacy services OUGHT also consider the following capabilities/options:

* QNAME minimisation [@!RFC7816]
* No use of the EDNS(0) Client subnet option in upstream queries
* Implementing [@I-D.ietf-tls-dnssec-chain-extension]
* Providing TLSA DANE records for the nameserver
* Management of TLS connections to optimise performance for clients using either
  * [@!RFC7766] and EDNS(0) Keepalive [@!RFC7828] and/or 
  * DNS Stateful Operations [@!I-D.ietf-dnsop-session-signal] 
* Clients should not be required to use TLS session resumption [@!RFC5077] or Domain Name System (DNS) Cookies [@!RFC7873]

DNS privacy services MIGHT offer the following capabilities:

* A DNS privacy service on both port 853 and 443 (to circumvent blocking of
  port 853). *RvRD: I think we should probably add a note about the ambiguity between DNS-over-TLS and DoH this can cause, how about: "We note that this practice may require revision when DoH becomes more widely deployed, because of the potential use of the same ports for two incompatible types of service."*
* A .onion [@RFC7686] service endpoint
* Aggressive Use of DNSSEC-Validated Cache [@RFC8198] to reduce the number of
  queries to authoritative servers to increase privacy.
* Run a copy of the root zone on loopback [@RFC7706] to avoid making queries to
  the root servers that might leak information.

## Service recommendations

### Availability

DNS privacy services are EXPECTED be engineered for high availability. A failed
DNS privacy service could force the user to switch providers, fallback to
cleartext or accept no DNS service for the outage. *RvRD: maybe add: "Particular care OUGHT to be taken to protect DNS privacy services against denial-of-service attacks, as experience has shown that unavailability of DNS resolving because of attacks is a significant motivation for users to switch services." -- we could also cite my student's paper as it contains an example of such an event.*

### Service options

A DNS privacy service is EXPECTED to deliver the same level of service offered on un-encrypted
channels in terms of such options as filtering (or lack of), DNSSEC validation,
etc. To do so would unfairly disadvantage users of the privacy service.

## Client query obfuscation

Since queries from recursive resolvers to authoritative servers are performed
using cleartext (at the time of writing), resolver services need to consider the
extent to which they may be directly leaking information about their client
community via these upstream queries and what they can do to mitigate this
further. Note, that even when all the relevant techniques described above are
employed there may still be attacks possible, e.g.
[@Pitfalls-of-DNS-Encryption]. For example, a resolver with a very small
community of users risks exposing data in this way and OUGHT obfuscate this
traffic by mixing it with 'generated' traffic to make client characterisation
harder. The resolver OUGHT also employ aggressive pre-fetch techniques as a
further measure to counter traffic analysis.

At the time of writing there are no standardized or widely recognized techniques
to perform such obfuscation or bulk pre-fetches.

*RvRD: this is sort of a slippery slope; personally, I would advocate hiding in the masses (large DNS privacy services) over obfuscation techniques. The risk of a false sense of security is real I think. It sparked a thought though, perhaps multiple smaller DNS privacy services can somehow collaborate and randomly share upstream queries with eachother, this might homogenize what their traffic looks like to the outside world. (I hope you get what I mean)*

## Authentication of DNS privacy services

To enable users to select a 'Strict Privacy' usage profile
[@!RFC8310] DNS privacy services OUGHT to provide
credentials in the form of either X.509 certificates, SPKI pinsets or TLSA
records. This in effect commits the DNS privacy service to a public identity
users will trust.

Anecdotal evidence to date highlights this requirement as one of the more
challenging aspects for operators of traditional DNS resolvers that choose to
additionally provide a DNS privacy service as management of such credentials is
new to those DNS operators.

### Generation and publication of certificates

It is recommended that operators: 

* Choose a short, memorable authentication name for their service
* Automate the generation and publication of certificates
* Monitor certificates to prevent accidental expiration of certificates
* Consider re-use of the public/private keypair in the case of a service provided through DNS-over-TLS, as trust pin management by users is undefined, and may be hard to troubleshoot for both users and operators of a DNS privcy service (*RvRD: do we think it makes sense to add this?*)

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


# Server data handling

The following are common activities for DNS service operators and in all cases
should be minimised or completely avoided if possible for DNS privacy services.
If data is retained it should be encrypted and either aggregated,
pseudonymised or anonymised whenever possible.

* Transient data (e.g. that is used for real time monitoring and threat analysis
  which might be held only memory) OUGHT to be retained for the shortest possible period
  deemed operationally feasible.
* Retention of DNS traffic logs OUGHT be only those required to sustain
  operation of the service and, to the extent that such exists, meet regulatory
  requirements.
* DNS privacy services OUGHT not track users except for the particular purpose
  of detecting and remedying technically malicious (e.g. DoS) or anomalous use
  of the service
* Operators OUGHT not provide data to third-parties without explicit consent
  from users (we take the stance here that simply using the resolution service
  itself does not constitute consent).
* Data access OUGHT be minimised to only those
  personnel who require access to perform operational duties.
* Operators OUGHT to consider including specific guidelines for the collection of aggregated and/or anonymised data for research purposes, within or outside of their own organisation

TODO: Data for research vs operations... how to still motivate operators to share anonymised data? (*RvRD: how about the last bullet I added, could that be a starting point?*)

## Pseudonymisation and anonymisation methods

There is active discussion in the space of effective pseudonymisation of
personal data in DNS query logs. To-date this has focussed on
pseudonymisation of client IP addresses, however there are as yet no
standards for this that are unencumbered by patents. This section briefly
references some known methods in this space at the time of writing.

### ipcipher

[@ipcipher-spec] is a pseudonymisation technique which encrypts IPv4 and IPv6
addresses such that any address encrypts to a valid address. At the time of
writing the specification is under review and may be the subject of a future
IETF draft. 

NOTE: There are some significant security concerns about the use of ipcipher
that have been voiced by the ipcipher authors and its inclusion here should be
reviewed.

### Bloom filters

There is also on-going work in the area of using Bloom filters as a
privacy-enhancing technology for DNS monitoring [@DNS-bloom-filter]. The goal of
this work is to allow operators to identify so-called Indicators of Compromise
(IOCs) originating from specific subnets without storing information about, or
be able to monitor the DNS queries of an individual user.

(*RvRD: if this stays in the document, I can expand on it, the thesis of my student is shaping up nicely so may be a good reference, he expects to finish end of August.*)


# DNS privacy policy and practice statement

## Recommended contents of a DPPPS

<!-- Work out how to do a numbered, nested list in markdown! -->

1 Policy.

1.1 Recommendations. This section should explain, with reference to section 
      (#recommendations-for-dns-privacy-services) of this document which 
      recommendations the DNS privacy service employs.

1.2. Data handling. This section should explain, with reference to section 
       (#server-data-handling) 
       of this document the policy for gathering and disseminating information 
       collected by the DNS privacy service. 

1.2.1. Specify clearly what data (including whether it is aggregated, 
        pseudonymised or anonymized) is:

1.2.1.1. Collected and retained by the operator (and for how long)

1.2.1.2. Shared with, sold or rented to third-parties

1.2.2 Specify any exceptions to the above, for example technically malicious or
anomalous behaviour

1.2.3 Declare any third-party affiliations or funding

1.2.4 Whether user DNS data is correlated or combined with any other personal
    information held by the operator

2 Practice. This section should explain the current operational practices of the service.

2.1 Specify any temporary or permanent deviations from the policy for
    operational reasons

2.2 Provide specific details of which capabilities are provided on which 
      address and ports

2.3 Specify the authentication name to be used (if any)

2.4 Specify the SPKI pinsets to be used (if any) and policy for rolling keys

2.5 Provide a contact email address for the service

## Current privacy statements

NOTE: An analysis of these statements will clearly only provide a snapshot at
the time of writing. It is included in this version of the draft to provide a
basis for the assessment of the contents of the DPPPS and is expected to be
removed or substantially re-worked in a future version.

### Google
https://developers.google.com/speed/public-dns/privacy

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
and to John Dickinson for review of and input to the early drafts of this
document.

Thanks to John Todd for discussions on this topic.

Sara Dickinson thanks the Open Technology Fund for a grant to support the work
on this document.


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



