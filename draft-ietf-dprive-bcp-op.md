%%%
    Title = "Recommendations for DNS Privacy Service Operators"
    abbrev = "DNS Privacy Service Recommendations"
    category = "bcp"
    docName= "draft-ietf-dprive-bcp-op-03"
    ipr = "trust200902"
    area = "Internet"
    workgroup = "dprive"
    keyword = ["DNS"]
    date = 2019-04-18T00:00:00Z
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
      streets = ["Science Park 400"]
      city = "Amsterdam"
      code = "1098 XH"
      country = "The Netherlands"
    [[author]]
     initials="R."
     surname="van Rijswijk-Deij"
     fullname="Roland M. van Rijswijk-Deij"
     organization = "NLnet Labs"
       [author.address]
       email = "roland@nlnetLabs.nl"
       [author.address.postal]
       streets = ["Science Park 400"]
       city = "Amsterdam"
       code = "1098 XH"
       country = "The Netherlands"
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
operators who choose to offer DNS Privacy services. With these recommendations,
the operator can make deliberate decisions regarding which services to provide, and how
the decisions and alternatives impact the privacy of users.

This document also presents a framework to assist writers of DNS Privacy Policy
and Practices Statements (analogous to DNS Security Extensions (DNSSEC) Policies
and DNSSEC Practice Statements described in [@RFC6841]).

{mainmatter}

# Introduction

The Domain Name System (DNS) is at the core of the Internet; almost every
activity on the Internet starts with a DNS query (and often several). However
the DNS was not originally designed with strong security or privacy mechanisms.
A number of developments have taken place in recent years which aim to increase
the privacy of the DNS system and these are now seeing some deployment. This
latest evolution of the DNS presents new challenges to operators and this
document attempts to provide an overview of considerations for privacy focused
DNS services.

In recent years there has also been an increase in the availability of "public
resolvers" [@?I-D.ietf-dnsop-terminology-bis] which users may prefer to use
instead of the default network resolver because they offer a specific feature
(e.g. good reachability, encrypted transport, strong privacy policy, filtering
(or lack of), etc.). These open resolvers have tended to be at the forefront of
adoption of privacy related enhancements but it is anticipated that operators of
other resolver services will follow.

Whilst protocols that encrypt DNS messages on the wire provide protection
against certain attacks, the resolver operator still has (in principle) full
visibility of the query data and transport identifiers for each user. Therefore,
a trust relationship exists. The ability of the operator to provide a
transparent, well documented, and secure privacy service will likely serve as a
major differentiating factor for privacy conscious users if they make an
active selection of which resolver to use.

It should also be noted that the choice of a user to configure a single resolver
(or a fixed set of resolvers) and an encrypted transport to use in all network
environments has both advantages and disadvantages. For example the user has a
clear expectation of which resolvers have visibility of their query data however
this resolver/transport selection may provide an added mechanism to track them
as they move across network environments. Commitments from operators to minimize
such tracking are also likely to play a role in user selection of resolvers.

More recently the global legislative landscape with regard to personal data
collection, retention, and pseudonymization has seen significant activity.
It is an untested area that simply using a DNS resolution service
constitutes consent from the user for the operator to process their query data.
The impact of recent legislative changes on data pertaining to the users of both
Internet Service Providers and public DNS resolvers is not fully understood at the
time of writing.

This document has two main goals:

* To provide operational and policy guidance related to DNS over encrypted
  transports and to outline recommendations for data handling for operators of
  DNS privacy services.

* To introduce the DNS Privacy Policy and Practice Statement (DPPPS) and present
  a framework to assist writers of this document. A DPPPS is a document that an
  operator can publish outlining their operational practices and commitments
  with regard to privacy thereby providing a means for clients to evaluate the
  privacy properties of a given DNS privacy service. In particular, the
  framework identifies the elements that should be considered in formulating a
  DPPPS. This document does not, however, define a particular Policy or Practice
  Statement, nor does it seek to provide legal advice or recommendations as to
  the contents.

Community insight [or judgment?] about operational practices can change
quickly, and experience shows that a Best Current Practice (BCP) document about
privacy and security is a point-in-time statement. Readers are advised to seek
out any errata or updates that apply to this document.


# Scope

"DNS Privacy Considerations" [@I-D.bortzmeyer-dprive-rfc7626-bis] describes the
general privacy issues and threats associated with the use of the DNS by
Internet users and much of the threat analysis here is lifted from that
document and from [@!RFC6973]. However this document is limited in scope to best
practice considerations for the provision of DNS privacy services by servers
(recursive resolvers) to clients (stub resolvers or forwarders). Privacy
considerations specifically from the perspective of an end user, or those for
operators of authoritative nameservers are out of scope.


This document includes (but is not limited to) considerations in the following
areas (taken from [@I-D.bortzmeyer-dprive-rfc7626-bis]):

1. Data "on the wire" between a client and a server
2. Data "at rest" on a server (e.g. in logs)
3. Data "sent onwards" from the server (either on the wire or shared with a
third party)

Whilst the issues raised here are targeted at those operators who choose to
offer a DNS privacy service, considerations for areas 2 and 3 could equally
apply to operators who only offer DNS over unencrypted transports but who would
like to align with privacy best practice.

# Privacy related documents

There are various documents that describe protocol changes that have the
potential to either increase or decrease the privacy of the DNS. Note this does
not imply that some documents are good or bad, better or worse, just that (for
example) some features may bring functional benefits at the price of a reduction
in privacy and conversely some features increase privacy with an accompanying
increase in complexity. A selection of the most relevant documents are listed in
(#documents) for reference.

# Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP 14 [@!RFC2119] and [@!RFC8174]
when, and only when, they appear in all capitals, as shown here.

DNS terminology is as described in [@?I-D.ietf-dnsop-terminology-bis] with one
modification: we restate the clause in the original definition of
Privacy-enabling DNS server in [@!RFC8310] to include the requirement that a DNS
over (D)TLS server should also offer at least one of the credentials described
in Section 8 and implement the (D)TLS profile described in Section 9 of
[@!RFC8310].

Other Terms:

* DPPPS: DNS Privacy Policy and Practice Statement, see
  (#dns-privacy-policy-and-practice-statement).

* DNS privacy service: The service that is offered via a privacy-enabling DNS
  server and is documented either in an informal statement of policy and
  practice with regard to users privacy or a formal DPPPS.

# Recommendations for DNS privacy services

We describe two classes of threats:

* 'Privacy Considerations for Internet Protocols' [@!RFC6973] Threats
  * Privacy terminology, threats to privacy and mitigations as described in
    Sections 3, 5 and 6 of [@!RFC6973].

* DNS Privacy Threats
  * These are threats to the users and operators of DNS privacy services that
    are not directly covered by [@!RFC6973]. These may be more operational in
    nature such as certificate management or service availability issues.

We describe three classes of actions that operators of DNS privacy
services can take:

* Threat mitigation for well understood and documented privacy threats to the
  users of the service and in some cases to the operators of the service.
* Optimization of privacy services from an operational or management perspective
* Additional options that could further enhance the privacy and usability of the
  service

This document does not specify policy only best practice, however for DNS
Privacy services to be considered compliant with these best practice guidelines
they SHOULD implement (where appropriate) all:

* Threat mitigations to be minimally compliant
* Optimizations to be moderately compliant
* Additional options to be maximally compliant

## On the wire between client and server

In this section we consider both data on the wire and the service provided to
the client.

### Transport recommendations

[@!RFC6973] Threats: 

* Surveillance:
  * Passive surveillance of traffic on the wire
    [@I-D.bortzmeyer-dprive-rfc7626-bis] Section 2.4.2.

DNS Privacy Threats:

* Active injection of spurious data or traffic

Mitigations:

A DNS privacy service can mitigate these threats by providing service over one
or more of the following transports

* DNS-over-TLS [@!RFC7858] and [@!RFC8310]
* DoH [@!RFC8484]

It is noted that a DNS privacy service can also be provided over DNS-over-DTLS
[@RFC8094], however this is an Experimental specification and there are no known
implementations at the time of writing.

It is also noted that DNS privacy service might be provided over IPSec, DNSCrypt
or VPNs. However, use of these transports for DNS are not standardized and any
discussion of best practice for providing such a service is out of scope for 
this document.

### Authentication of DNS privacy services

[@!RFC6973] Threats: 

* Surveillance: 
  * Active attacks that can redirect traffic to rogue servers
  [@I-D.bortzmeyer-dprive-rfc7626-bis] Section 2.5.3.

Mitigations:

DNS privacy services should ensure clients can authenticate the server. Note
that this, in effect, commits the DNS privacy service to a public identity users
will trust.

When using DNS-over-TLS clients that select a 'Strict Privacy' usage profile
[@!RFC8310] (to mitigate the threat of active attack on the client) require the
ability to authenticate the DNS server. To enable this, DNS privacy services
that offer DNS-over-TLS should provide credentials in the form of either X.509
certificates or SPKI pinsets.

When offering DoH [@!RFC8484], HTTPS requires authentication of the server as
part of the protocol.

NOTE: At this time the reference to the TLS DNSSEC chain extension draft has been removed as it is no longer considered an active TLS WG document.

Optimizations:

DNS privacy services can also consider the following capabilities/options:

* As recommended in [@!RFC8310] providing DANE TLSA records for the nameserver
  * In particular, the service could provide TLSA records such that
    authenticating solely via the PKIX infrastructure can be avoided.

#### Certificate management 

Anecdotal evidence to date highlights the management of certificates as one of
the more challenging aspects for operators of traditional DNS resolvers that
choose to additionally provide a DNS privacy service as management of such
credentials is new to those DNS operators.

It is noted that SPKI pinset management is described in [@RFC7858] but that key
pinning mechanisms in general have fallen out of favor operationally for
various reasons such as the logistical overhead of rolling keys.

DNS Privacy Threats: 

* Invalid certificates, resulting in an unavailable service.
* Mis-identification of a server by a client e.g. typos in URLs or
  authentication domain names

Mitigations:

It is recommended that operators:

* Follow the guidance in Section 6.5 of [@!RFC7525] with regards to certificate
revocation 
* Choose a short, memorable authentication name for the service
* Automate the generation and publication of certificates
* Monitor certificates to prevent accidental expiration of certificates

### Protocol recommendations

#### DNS-over-TLS

DNS Privacy Threats:

* Known attacks on TLS such as those described in [@RFC7457]
* Traffic analysis, for example: [Pitfalls of DNS Encryption](https://www.ietf.org/mail-archive/web/dns-privacy/current/pdfWqAIUmEl47.pdf)
* Potential for client tracking via transport identifiers
* Blocking of well known ports (e.g. 853 for DNS-over-TLS)

Mitigations:

In the case of DNS-over-TLS, TLS profiles from Section 9 and the
Countermeasures to DNS Traffic Analysis from section 11.1 of [@!RFC8310]
provide strong mitigations. This includes but is not limited to:

* Adhering to [@!RFC7525]
* Implementing only (D)TLS 1.2 or later as specified in [@!RFC8310]
* Implementing EDNS(0) Padding [@!RFC7830] using the guidelines in
  [@!RFC8467]
* Clients should not be required to use TLS session resumption [@!RFC5077] or
  Domain Name System (DNS) Cookies [@!RFC7873].
* A DNS-over-TLS privacy service on both port 853 and 443. This practice may not
  be possible if e.g. the operator deploys DoH on the same IP address.

Optimizations:

* Concurrent processing of pipelined queries, returning responses as soon as
  available, potentially out of order as specified in [@!RFC7766]. This is often
  called 'OOOR' - out-of-order responses. (Providing processing performance
  similar to HTTP multiplexing)
* Management of TLS connections to optimize performance for clients using either
  * [@!RFC7766] and EDNS(0) Keepalive [@!RFC7828] and/or 
  * DNS Stateful Operations [@!I-D.ietf-dnsop-session-signal]

Additional options that providers may consider:

* Offer a .onion [@RFC7686] service endpoint

#### DoH

DNS Privacy Threats:

* Known attacks on TLS such as those described in [@RFC7457]
* Traffic analysis, for example: [DNS Privacy not so private: the traffic analysis perspective](https://petsymposium.org/2018/files/hotpets/4-siby.pdf)
* Potential for client tracking via transport identifiers

Mitigations:

* Clients must be able to forego the use of HTTP Cookies [@!RFC6265] and still
  use the service
* Clients should not be required to include any headers beyond the absolute
  minimum to obtain service from a DoH server. (See Section 6.1 of
  [@I-D.ietf-httpbis-bcp56bis].)

### DNSSEC

DNS Privacy Threats:

* Users may be directed to bogus IP addresses for e.g. websites where they might
  reveal personal information to attackers.
  
Mitigations:

* All DNS privacy services must offer a DNS privacy service that performs DNSSEC
  validation. In addition they must be able to provide the DNSSEC RRs to the
  client so that it can perform its own validation.

The addition of encryption to DNS does not remove the need for DNSSEC
[@RFC4033] - they are independent and fully compatible protocols,
each solving different problems. The use of one does not diminish the need nor
the usefulness of the other.

While the use of an authenticated and encrypted transport protects origin
authentication and data integrity between a client and a DNS privacy service it
provides no proof (for a non-validating client) that the data provided by the
DNS privacy service was actually DNSSEC authenticated. As with cleartext DNS the
user is still solely trusting the AD bit (if present) set by the resolver.

It should also be noted that the use of an encrypted transport for DNS actually
solves many of the practical issues encountered by DNS validating clients e.g.
interference by middleboxes with cleartext DNS payloads is completely avoided.
In this sense a validating client that uses a DNS privacy service which supports
DNSSEC has a far simpler task in terms of DNS Roadblock avoidance.


### Availability

DNS Privacy Threats:

* A failed DNS privacy service could force the user to switch providers,
fallback to cleartext or accept no DNS service for the outage.

Mitigations:

A DNS privacy service must be engineered for high availability. Particular care
should to be taken to protect DNS privacy services against denial-of-service
attacks, as experience has shown that unavailability of DNS resolving because of
attacks is a significant motivation for users to switch services. See, for
example Section IV-C of [Passive Observations of a Large DNS Service: 2.5 Years
in the Life of
Google](http://tma.ifip.org/2018/wp-content/uploads/sites/3/2018/06/tma2018_paper30.pdf).

### Service options

DNS Privacy Threats: 

* Unfairly disadvantaging users of the privacy service with respect to the
  services available. This could force the user to switch providers, fallback to
  cleartext or accept no DNS service for the outage.

Mitigations:

A DNS privacy service should deliver the same level of service as offered on
un-encrypted channels in terms of such options as filtering (or lack thereof), 
DNSSEC validation, etc. 

### Impact on Operators

DNS Privacy Threats: 

* Increased use of encryption impacts operator ability to manage their network [@!RFC8404]

Many monitoring solutions for DNS traffic rely on the plain text nature of 
this traffic and work by intercepting traffic on the wire, either using a 
separate view on the connection between clients and the resolver, or as a 
separate process on the resolver system that inspects network traffic. Such 
solutions will no longer function when traffic between clients and resolvers is 
encrypted. There are, however, legitimate reasons for operators to inspect DNS 
traffic, e.g. to monitor for network security threats. Operators may therefore 
need to invest in alternative means of monitoring that relies on either the
resolver software directly, or exporting DNS traffic from the resolver using
e.g. [dnstap](http://dnstap.info).

Optimization:

When implementing alternative means for traffic monitoring, operators of a
DNS privacy service should consider using privacy conscious means to do so (see,
for example, the discussion on the use of Bloom Filters in the #documents
appendix in this document).

### Limitations of using a pure TLS proxy

DNS Privacy Threats: 

* Limited ability to manage or monitor incoming connections using DNS specific
  techniques
* Misconfiguration of the target server could lead to data leakage if the proxy
  to target server path is not encrypted.

Optimization:

Some operators may choose to implement DNS-over-TLS using a TLS proxy (e.g.
[nginx](https://nginx.org/), [haproxy](https://www.haproxy.org/) or
[stunnel](https://kb.isc.org/article/AA-01386/0/DNS-over-TLS.html)) in front of
a DNS nameserver because of proven robustness and capacity when handling large
numbers of client connections, load balancing capabilities and good tooling.
Currently, however, because such proxies typically have no specific handling of
DNS as a protocol over TLS or DTLS using them can restrict traffic management at
the proxy layer and at the DNS server. For example, all traffic received by a
nameserver behind such a proxy will appear to originate from the proxy and DNS
techniques such as ACLs, RRL or DNS64 will be hard or impossible to implement in
the nameserver.

Operators may choose to use a DNS aware proxy such as
[dnsdist](https://dnsdist.org) which offer custom options (similar to that
proposed in [@I-D.bellis-dnsop-xpf]) to add source information to packets
to address this shortcoming. It should be noted that such options potentially
significantly increase the leaked information in the event of a
misconfiguration.


## Data at rest on the server

### Data handling

[@!RFC6973] Threats:

* Surveillance
* Stored data compromise
* Correlation
* Identification
* Secondary use
* Disclosure

Other Threats

* Contravention of legal requirements not to process user data?

Mitigations:

The following are common activities for DNS service operators and in all cases
should be minimized or completely avoided if possible for DNS privacy services.
If data is retained it should be encrypted and either aggregated, pseudonymized
or anonymized whenever possible. In general the principle of data minimization
described in [@!RFC6973] should be applied.

* Transient data (e.g. that is used for real time monitoring and threat analysis
  which might be held only memory) should be retained for the shortest possible
  period deemed operationally feasible.
* The retention period of DNS traffic logs should be only those required to
  sustain operation of the service and, to the extent that such exists, meet
  regulatory requirements.
* DNS privacy services should not track users except for the particular purpose
  of detecting and remedying technically malicious (e.g. DoS) or anomalous use
  of the service.
* Data access should be minimized to only those personnel who require access to
  perform operational duties.

Optimizations:

* Consider use of full disk encryption for logs and data capture storage.

### Data minimization of network traffic

Data minimization refers to collecting, using, disclosing, and storing the
minimal data necessary to perform a task, and this can be achieved by
removing or obfuscating privacy-sensitive information in network traffic logs.
This is typically personal data, or data that can be used to link a record to an
individual, but may also include revealing other confidential information, for
example on the structure of an internal corporate network.

The problem of effectively ensuring that DNS traffic logs contain no or minimal
privacy-sensitive information is not one that currently has a generally agreed
solution or any Standards to inform this discussion. This section presents and
overview of current techniques to simply provide reference on the current
status of this work.

Research into data minimization techniques (and particularly IP address
pseudonymization/anonymization) was sparked in the late 1990s/early 2000s,
partly driven by the desire to share significant corpuses of traffic captures
for research purposes. Several techniques reflecting different requirements in
this area and different performance/resource tradeoffs emerged over the course
of the decade. Developments over the last decade have been both a blessing and a
curse; the large increase in size between an IPv4 and an IPv6 address, for
example, renders some techniques impractical, but also makes available a much
larger amount of input entropy, the better to resist brute force
re-identification attacks that have grown in practicality over the period.

Techniques employed may be broadly categorized as either anonymization or
pseudonymization. The following discussion uses the definitions from [@!RFC6973]
Section 3, with additional observations from [van Dijkhuizen et
al.](https://doi.org/10.1145/3182660)

* Anonymization. To enable anonymity of an individual, there must exist a set of
  individuals that appear to have the same attribute(s) as the individual. To
  the attacker or the observer, these individuals must appear indistinguishable
  from each other.

* Pseudonymization. The true identity is deterministically replaced with an
  alternate identity (a pseudonym). When the pseudonymization schema is known,
  the process can be reversed, so the original identity becomes known again.

In practice there is a fine line between the two; for example, how to categorize
a deterministic algorithm for data minimization of IP addresses that produces a
group of pseudonyms for a single given address.


### IP address pseudonymization and anonymization methods

As [@I-D.bortzmeyer-dprive-rfc7626-bis] makes clear, the big privacy risk in
DNS is connecting DNS queries to an individual and the major vector for this in
DNS traffic is the client IP address.


There is active discussion in the space of effective pseudonymization of IP
addresses in DNS traffic logs, however there seems to be no single solution that
is widely recognized as suitable for all or most use cases. There are also as
yet no standards for this that are unencumbered by patents. The following table
presents a high level comparison of various techniques employed or under
development today and classifies them according to categorization of technique
and other properties. The list of techniques includes the main techniques in
current use, but does not claim to be comprehensive. (#ip-address-techniques)
provides a more detailed survey of these techniques and definitions for the
categories and properties listed below.

![Figure showing comparison of IP address techniques (SVG)](https://github.com/Sinodun/draft-dprive-bcp-op/blob/master/draft-00/ip_techniques_table.svg)

The choice of which method to use for a particular application will depend on
the requirements of that application and consideration of the threat analysis of
the particular situation.

For example, a common goal is that distributed packet captures must be in an
existing data format such as PCAP [@pcap] or C-DNS
[@I-D.ietf-dnsop-dns-capture-format] that can be used as input to existing
analysis tools. In that case, use of a format-preserving technique is
essential. This, though, is not cost-free - several authors (e.g. [Brenker &
Arnes]
(https://pdfs.semanticscholar.org/7b34/12c951cebe71cd2cddac5fda164fb2138a44.pdf))
have observed that, as the entropy in an IPv4 address is limited, given
a de-identified log from a target, if an attacker is capable of ensuring
packets are captured by the target and the attacker can send forged traffic
with arbitrary source and destination addresses to that target, any
format-preserving pseudonymization is vulnerable to an attack along the lines
of a cryptographic chosen plaintext attack.



### Pseudonymization, anonymization or discarding of other correlation data

DNS Privacy Threats:

* IP TTL/Hoplimit can be used to fingerprint client OS
* Tracking of TCP sessions
* Tracking of TLS sessions and session resumption mechanisms
* Resolvers _might_ receive client identifiers e.g. MAC addresses in EDNS(0)
  options - some CPE devices are known to add them.
* HTTP headers

Mitigations:

* Data minimization or discarding of such correlation data

TODO: More analysis here. 

### Cache snooping

[@!RFC6973] Threats: 

* Surveillance:
  * Profiling of client queries by malicious third parties

Mitigations:

* See [ISC Knowledge database on cache snooping](https://kb.isc.org/docs/aa-00482) for an example discussion on defending against cache snooping

TODO: Describe other techniques to defend against cache snooping


## Data sent onwards from the server

In this section we consider both data sent on the wire in upstream queries and
data shared with third parties.

### Protocol recommendations

[@!RFC6973] Threats: 

* Surveillance:
  * Transmission of identifying data upstream.

Mitigations:

As specified in [@!RFC8310] for DNS-over-TLS but applicable to any DNS Privacy
services the server should:

* Implement QNAME minimization [@!RFC7816]
* Honor a SOURCE PREFIX-LENGTH set to 0 in a query containing the EDNS(0)
  Client Subnet (ECS) option and not send an ECS option in upstream queries.

Optimizations:

* The server should either 
  * not use the ECS option in upstream queries at all, or
  * offer alternative services, one that sends ECS and one that does not.

If operators do offer a service that sends the ECS options upstream they should
use the shortest prefix that is operationally feasible (NOTE: the authors
believe they will be able to add a reference for advice here soon) and ideally
use a policy of whitelisting upstream servers to send ECS to in order to
minimize data leakage. Operators should make clear in any policy statement what
prefix length they actually send and the specific policy used.

Whitelisting has the benefit that not only does the operator know which upstream
servers can use ECS but also allows the operator to decide which upstream
servers apply privacy policies that the operator is happy with. However some
operators consider whitelisting to incur significant operational overhead
compared to dynamic detection of ECS on authoritative servers.

<!-- *RvRD: note: I have a bachelor student working on this, who has been
looking at what are good prefix sizes to e.g. geo-locate a client to a country
or continent; will share results when available. I'm considering following up
on his work with a paper at some point to help the discussion about ECS
along.*-->

Additional options:

* Aggressive Use of DNSSEC-Validated Cache [@RFC8198] to reduce the number of
  queries to authoritative servers to increase privacy.
* Run a copy of the root zone on loopback [@RFC7706] to avoid making queries to
  the root servers that might leak information.

### Client query obfuscation

Additional options:

Since queries from recursive resolvers to authoritative servers are performed
using cleartext (at the time of writing), resolver services need to consider the
extent to which they may be directly leaking information about their client
community via these upstream queries and what they can do to mitigate this
further. Note, that even when all the relevant techniques described above are
employed there may still be attacks possible, e.g.
[@Pitfalls-of-DNS-Encryption]. For example, a resolver with a very small
community of users risks exposing data in this way and OUGHT obfuscate this
traffic by mixing it with 'generated' traffic to make client characterization
harder. The resolver could also employ aggressive pre-fetch techniques as a
further measure to counter traffic analysis.

At the time of writing there are no standardized or widely recognized techniques
to perform such obfuscation or bulk pre-fetches.

Another technique that particularly small operators may consider is forwarding
local traffic to a larger resolver (with a privacy policy that aligns with their
own practices) over an encrypted protocol so that the upstream queries are
obfuscated among those of the large resolver.


### Data sharing

[@!RFC6973] Threats:

* Surveillance
* Stored data compromise
* Correlation
* Identification
* Secondary use
* Disclosure

DNS Privacy Threats:

* Contravention of legal requirements not to process user data?

Mitigations:

Operators should not provide identifiable data to third-parties without explicit
consent from clients (we take the stance here that simply using the resolution
service itself does not constitute consent).

Even when consent is granted operators should employ data minimization
techniques such as those described in (#data-handling) if data is shared with
third-parties. 

Operators should consider including specific guidelines for the collection of
aggregated and/or anonymized data for research purposes, within or outside of
their own organization. See [SURFnet's policy](https://surf.nl/datasharing) on
data sharing for research as an example.

TODO: More on data for research vs operations... how to still motivate operators
to share anonymized data?

TODO: Guidelines for when consent is granted?

TODO: Applies to server data handling too.. could operators offer alternatives
services one that implies consent for data processing, one that doesn't?


# DNS privacy policy and practice statement

## Recommended contents of a DPPPS

### Policy

1. Make an explicit statement that IP addressses are treated as PII
1. State if IP addresses are being logged
1. Specify clearly what data (including whether it is aggregated, 
        pseudonymized or anonymized and the conditions of data transfer) is:
    - Collected and retained by the operator, and for what period it is retained
    - Shared with partners
    - Shared, sold or rented to third-parties
1. Specify any exceptions to the above, for example technically malicious or
anomalous behavior
1. Declare any partners, third-party affiliations or sources of funding
1. Whether user DNS data is correlated or combined with any other personal
      information held by the operator
1. Result filtering. This section should explain whether the operator filters, edits or
alters in any way the replies that it receives from the authoritative servers for each
DNS zone, before forwarding them to the clients. For each category listed below, the
operator should also specify how the filtering lists are created and managed, whether it
employs any third-party sources for such lists, and which ones.
    - Specify if any replies are being filtered out or altered for network and computer
    security reasons (e.g. preventing connections to malware-spreading websites or botnet
    control servers)
    - Specify if any replies are being filtered out or altered for mandatory legal
    reasons, due to applicable legislation or binding orders by courts and other public
    authorities
    - Specify if any replies are being filtered out or altered for voluntary legal
    reasons, due to an internal policy by the operator aiming at reducing potential legal
    risks
    - Specify if any replies are being filtered out or altered for any other reason,
    including commercial ones

### Practice

This section should explain the current operational practices of the service.

1. Specify any temporary or permanent deviations from the policy for
    operational reasons
1. With reference to section (#recommendations-for-dns-privacy-services) provide 
    specific details of which capabilities are provided on which client facing addresses
    and ports
1. Specify the authentication name to be used (if any) and if TLSA records are 
    published (including options used in the TLSA records)
1. Specify the SPKI pinsets to be used (if any) and policy for rolling keys
1. Provide contact/support information for the service
1. Jurisdiction. This section should communicate the applicable jurisdictions and law
enforcement regimes under which the service is being provided.
    - Specify the entity or entities that will control the data and be responsible for
    their treatment, and their legal place of business
    - Specify, either directly or by pointing to the applicable privacy policy, the
    relevant privacy laws that apply to the treatment of the data, the rights that users
    enjoy in regard to their own personal information that is treated by the service, and
    how they can contact the operator to enforce them
    - Specify the countries in which the servers handling the DNS requests and the data
    are located (if the operator applies a geolocation policy so that requests from
    certain countries are only served by certain servers, this should be specified as
    well)
    - Specify whether the operator has any agreement in place with law enforcement
    agencies, or other public and private parties dealing with security and intelligence,
    to give them access to the servers and/or to the data
1.  Describe how consent is obtained from the user of the DNS privacy service 
differentiating
    - Uninformed users for whom this trust relationship is implicit
    - Privacy-conscious users, that make an explicit trust choice
    
    (this may prove relevant in the context of e.g. the GDPR as it relates to consent)


## Current policy and privacy statements

A tabular comparison of existing policy and privacy statements from various DNS
Privacy service operators based on the proposed DPPPS structure can be found on
[dnsprivacy.org](https://dnsprivacy.org/wiki/display/DP/Comparison+of+policy+and+privacy+statements).

We note that the existing set of policies vary widely in style, content and
detail and it is not uncommon for the full text for a given operator to equate
to more than 10 pages of moderate font sized A4 text. It is a non-trivial task
today for a user to extract a meaningful overview of the different services on
offer.

## Enforcement/accountability

Transparency reports may help with building user trust that operators adhere to
their policies and practices.

Independent monitoring or analysis could be performed where possible of:

* ECS, QNAME minimization, EDNS(0) padding, etc.
* Filtering
* Uptime

This is by analogy with e.g. several TLS or website analysis tools that are
currently available e.g. [SSL Labs](https://www.ssllabs.com/ssltest/) or
[Internet.nl](https://internet.nl).

Additionally operators could choose to engage the services of a third party auditor to verify their compliance with their published DPPPS.

# IANA considerations

None

# Security considerations

Security considerations for DNS-over-TCP are given in [@RFC7766], many of which
are generally applicable to session based DNS.

TODO: e.g. New issues for DoS defence, server admin policies

# Acknowledgements

Many thanks to Amelia Andersdotter for a very thorough review of the first draft
of this document. Thanks to John Todd for discussions on this topic, and to
Stephane Bortzmeyer, Puneet Sood and Vittorio Bertola for review. Thanks to
Daniel Kahn Gillmor, Barry Green, Paul Hoffman, Dan York, John Reed, Lorenzo
Colitti for comments at the mic. Thanks to Loganaden Velvindron for useful
updates to the text.

Sara Dickinson thanks the Open Technology Fund for a grant to support the work
on this document.


# Contributors

The below individuals contributed significantly to the document:

John Dickinson\\
Sinodun Internet Technologies\\
Magdalen Centre\\
Oxford Science Park\\
Oxford OX4 4GA\\
United Kingdom

Jim Hague\\
Sinodun Internet Technologies\\
Magdalen Centre\\
Oxford Science Park\\
Oxford OX4 4GA\\
United Kingdom

# Changelog

draft-ietf-dprive-bcp-op-02

* Change 'open resolver' for 'public resolver'
* Minor editorial changes
* Remove recommendation to run a separate TLS 1.3 service
* Move TLSA to purely a optimisation in Section 5.2.1
* Update reference on minimal DoH headers.
* Add reference on user switching provider after service issues in Section 5.1.4
* Add text in Section 5.1.6 on impact on operators.
* Add text on additional threat to TLS proxy use (Section 5.1.7)
* Add reference in Section 5.3.1 on example policies.

draft-ietf-dprive-bcp-op-01

* Many minor editorial fixes
* Update DoH reference to RFC8484 and add more text on DoH
* Split threat descriptions into ones directly referencing RFC6973 and other DNS Privacy threats
* Improve threat descriptions throughout
* Remove reference to the DNSSEC TLS Chain Extension draft until new version submitted.
* Clarify use of whitelisting for ECS
* Re-structure the DPPPS, add Result filtering section.
* Remove the direct inclusion of privacy policy comparison, now just reference dnsprivacy.org and an example of such work.
* Add an appendix briefly discussing DNSSEC
* Update affiliation of 1 author

draft-ietf-dprive-bcp-op-00

* Initial commit of re-named document after adoption to replace
  draft-dickinson-dprive-bcp-op-01


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

<reference anchor='pcap' target='http://www.tcpdump.org/'>
    <front>
        <title>PCAP</title>
        <author>
            <organization>tcpdump.org</organization>
        </author>
        <date year='2016'/>
    </front>
</reference>


<!--These lines are needed to generate references for citations that appear only
in the appendix-->
[-@RFC6235]
[-@!RFC7871]
[-@RFC4033]
[-@?I-D.ietf-dnsop-dns-capture-format]
[-@?I-D.ietf-dnsop-dns-tcp-requirements]

{backmatter}

# Documents

This section provides an overview of some DNS privacy related documents,
however, this is neither an exhaustive list nor a definitive statement on the
characteristic of the document.


## Potential increases in DNS privacy

These documents are limited in scope to communications between stub
clients and recursive resolvers:

* 'Specification for DNS over Transport Layer Security (TLS)' [@!RFC7858],
  referred to here as 'DNS-over-TLS'.
* 'DNS over Datagram Transport Layer Security (DTLS)' [@RFC8094], referred to
  here as 'DNS-over-DTLS'. Note that this document has the Category of
  Experimental.
* 'DNS Queries over HTTPS (DoH)' [@!RFC8484] referred to
  here as DoH.
* 'Usage Profiles for DNS over TLS and DNS over DTLS' [@!RFC8310]
* 'The EDNS(0) Padding Option' [@!RFC7830] and 'Padding Policy for EDNS(0)'
  [@!RFC8467]

These documents apply to recursive to authoritative DNS but are relevant when
considering the operation of a recursive server:

* 'DNS Query Name minimization to Improve Privacy' [@!RFC7816] referred to here
  as 'QNAME minimization'

## Potential decreases in DNS privacy

These documents relate to functionality that could provide increased tracking of
user activity as a side effect:

* 'Client Subnet in DNS Queries' [@!RFC7871]
* 'Domain Name System (DNS) Cookies' [@!RFC7873])
* 'Transport Layer Security (TLS) Session Resumption without Server-Side State'
  [@!RFC5077] referred to here as simply TLS session resumption.
* 'A DNS Packet Capture Format' [@?I-D.ietf-dnsop-dns-capture-format]
* Passive DNS [@?I-D.ietf-dnsop-terminology-bis]

Note that depending on the specifics of the implementation
[@!RFC8484] may also provide increased tracking.

## Related operational documents

* 'DNS Transport over TCP - Implementation Requirements' [@!RFC7766]
* 'Operational requirements for DNS-over-TCP'
  [@?I-D.ietf-dnsop-dns-tcp-requirements]
* 'The edns-tcp-keepalive EDNS0 Option' [@!RFC7828]
* 'DNS Stateful Operations' [@!I-D.ietf-dnsop-session-signal]

# IP address techniques

Data minimization methods may be categorized by the processing used and the
properties of their outputs. The following builds on the categorization
employed in [@RFC6235]:

* Format-preserving. Normally when encrypting, the original data length and
  patterns in the data should be hidden from an attacker. Some applications of
  de-identification, such as network capture de-identification, require that the
  de-identified data is of the same form as the original data, to allow the data
  to be parsed in the same way as the original.
* Prefix preservation. Values such as IP addresses and MAC addresses contain
  prefix information that can be valuable in analysis, e.g. manufacturer ID in
  MAC addresses, subnet in IP addresses. Prefix preservation ensures that
  prefixes are de-identified consistently; e.g. if two IP addresses are from the
  same subnet, a prefix preserving de-identification will ensure that their
  de-identified counterparts will also share a subnet. Prefix preservation may
  be fixed (i.e. based on a user selected prefix length identified in advance to
  be preserved ) or general.
* Replacement. A one-to-one replacement of a field to a new value of the same
  type, for example using a regular expression. 
* Filtering. Removing (and thus truncating) or replacing data in a field. Field
  data can be overwritten, often with zeros, either partially (grey marking) or
  completely (black marking).
* Generalization. Data is replaced by more general data with reduced
  specificity. One example would be to replace all TCP/UDP port numbers with one
  of two fixed values indicating whether the original port was ephemeral
  (>=1024) or non-ephemeral (>1024). Another example, precision degradation,
  reduces the accuracy of e.g. a numeric value or a timestamp.
* Enumeration. With data from a well-ordered set, replace the first data item
  data using a random initial value and then allocate ordered values for
  subsequent data items. When used with timestamp data, this preserves ordering
  but loses precision and distance.
* Reordering/shuffling. Preserving the original data, but rearranging its order,
  often in a random manner.
* Random substitution. As replacement, but using randomly generated replacement
  values.
* Cryptographic permutation. Using a permutation function, such as a hash
  function or cryptographic block cipher, to generate a replacement
  de-identified value.
  
## Google Analytics non-prefix filtering

Since May 2010, [Google Analytics has provided a facility]
(https://support.google.com/analytics/answer/2763052?hl=en) that allows website
owners to request that all their users IP addresses are anonymized within
Google Analytics processing. This very basic anonymization simply sets to zero
the least significant 8 bits of IPv4 addresses, and the least significant 80
bits of IPv6 addresses. The level of anonymization this produces is perhaps
questionable. There are [some analysis results]
(https://www.conversionworks.co.uk/blog/2017/05/19/anonymize-ip-geo-impact-test/) 
which suggest that the impact of
this on reducing the accuracy of determining the user's location from their IP
address is less than might be hoped; the average discrepancy in identification
of the user city for UK users is no more than 17%. 

Anonymization: Format-preserving, Filtering (grey marking).

## dnswasher

Since 2006, PowerDNS have included a de-identification tool [dnswasher]
(https://github.com/edmonds/pdns/blob/master/pdns/dnswasher.cc) with
their PowerDNS product. This is a PCAP filter that performs a one-to-one mapping
of end user IP addresses with an anonymized address. A table of user IP
addresses and their de-identified counterparts is kept; the first IPv4 user
addresses is translated to 0.0.0.1, the second to 0.0.0.2 and so on. The
de-identified address therefore depends on the order that addresses arrive in
the input, and running over a large amount of data the address translation
tables can grow to a significant size. 

Anonymization: Format-preserving, Enumeration.

## Prefix-preserving map

Used in [TCPdpriv]( http://ita.ee.lbl.gov/html/contrib/tcpdpriv.html), 
this algorithm stores a set of original and anonymised IP
address pairs. When a new IP address arrives, it is compared with previous
addresses to determine the longest prefix match. The new address is anonymized
by using the same prefix, with the remainder of the address anonymized with a
random value. The use of a random value means that TCPdrpiv is not
deterministic; different anonymized values will be generated on each run. The
need to store previous addresses means that TCPdpriv has significant and
unbounded memory requirements, and because of the need to allocated anonymized
addresses sequentially cannot be used in parallel processing. 

Anonymization: Format-preserving, prefix preservation (general).

## Cryptographic Prefix-Preserving Pseudonymisation

Cryptographic prefix-preserving pseudonymisation was originally proposed as an
improvement to the prefix-preserving map implemented in TCPdpriv, described in
[Xu et al.](http://an.kaist.ac.kr/~sbmoon/paper/intl-journal/2004-cn-anon.pdf) 
and implemented in the [Crypto-PAn tool]
(https://www.cc.gatech.edu/computing/Telecomm/projects/cryptopan/). 
Crypto-PAn is now frequently
used as an acronym for the algorithm. Initially it was described for IPv4
addresses only; extension for IPv6 addresses was proposed in [Harvan &
Schönwälder](http://mharvan.net/talks/noms-ip_anon.pdf) and implemented in 
snmpdump. This uses a cryptographic algorithm
rather than a random value, and thus pseudonymity is determined uniquely by the
encryption key, and is deterministic. It requires a separate AES encryption for
each output bit, so has a non-trivial calculation overhead. This can be
mitigated to some extent (for IPv4, at least) by pre-calculating results for
some number of prefix bits. 

Pseudonymization: Format-preserving, prefix preservation (general).

## Top-hash Subtree-replicated Anonymisation

Proposed in [Ramaswamy & Wolf](http://www.ecs.umass.edu/ece/wolf/pubs/ton2007.pdf),
Top-hash Subtree-replicated Anonymisation (TSA)
originated in response to the requirement for faster processing than Crypto-PAn.
It used hashing for the most significant byte of an IPv4 address, and a
pre-calculated binary tree structure for the remainder of the address. To save
memory space, replication is used within the tree structure, reducing the size
of the pre-calculated structures to a few Mb for IPv4 addresses. Address
pseudonymization is done via hash and table lookup, and so requires minimal
computation. However, due to the much increased address space for IPv6, TSA is
not memory efficient for IPv6.

Pseudonymization: Format-preserving, prefix preservation (general).

## ipcipher

A [recently-released proposal from PowerDNS](
https://medium.com/@bert.hubert/on-ip-address-encryption-security-analysis-with-respect-for-privacy-dabe1201b476), 
[ipcipher](https://github.com/PowerDNS/ipcipher) is a simple
pseudonymization technique for IPv4 and IPv6 addresses. IPv6 addresses are
encrypted directly with AES-128 using a key (which may be derived from a
passphrase). IPv4 addresses are similarly encrypted, but using a recently
proposed encryption [ipcrypt](https://github.com/veorq/ipcrypt) suitable for 32bit
block lengths. However, the author of ipcrypt has [since indicated]
(https://www.ietf.org/mail-archive/web/cfrg/current/msg09494.html) that it has
low security, and further analysis has revealed it is vulnerable to attack.

Pseudonymization: Format-preserving, cryptographic permutation.

## Bloom filters

[van Rijswijk-Deij et al.](https://tnc18.geant.org/core/presentation/127) 
have recently described work using Bloom filters to
categorize query traffic and record the traffic as the state of multiple
filters. The goal of this work is to allow operators to identify so-called
Indicators of Compromise (IOCs) originating from specific subnets without
storing information about, or be able to monitor the DNS queries of an
individual user. By using a Bloom filter, it is possible to determine with a
high probability if, for example, a particular query was made, but the set of
queries made cannot be recovered from the filter. Similarly, by mixing queries
from a sufficient number of users in a single filter, it becomes practically
impossible to determine if a particular user performed a particular query. Large
numbers of queries can be tracked in a memory-efficient way. As filter status is
stored, this approach cannot be used to regenerate traffic, and so cannot be
used with tools used to process live traffic.

Anonymized: Generalization.


