%%%
    Title = "Recommendations for DNS Privacy Service Operators"
    abbrev = "DNS Privacy Service Recommendations"
    category = "bcp"
    docName= "draft-ietf-dprive-bcp-op-10"
    ipr = "trust200902"
    area = "Internet"
    workgroup = "dprive"
    keyword = ["DNS"]
    date = 2020-05-20T00:00:00Z
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
This document presents operational, policy, and security considerations for DNS
recursive resolver operators who choose to offer DNS Privacy services. With
these recommendations, the operator can make deliberate decisions regarding
which services to provide, and how the decisions and alternatives impact the
privacy of users.


This document also presents a non-normative framework to assist writers of a DNS Recursive
Operator Privacy Statement (analogous to DNS Security Extensions (DNSSEC)
Policies and DNSSEC Practice Statements described in RFC6841).


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
resolvers" [@!RFC8499] which users may prefer to use instead of the default
network resolver either because they offer a specific feature (e.g., good
reachability or encrypted transport) or because the network resolver lacks a specific feature (e.g., strong privacy policy or unfiltered responses).
These open resolvers have tended to be at the forefront of adoption of privacy
related enhancements but it is anticipated that operators of other resolver
services will follow.

Whilst protocols that encrypt DNS messages on the wire provide protection
against certain attacks, the resolver operator still has (in principle) full
visibility of the query data and transport identifiers for each user. Therefore,
a trust relationship exists. The ability of the operator to provide a
transparent, well documented, and secure privacy service will likely serve as a
major differentiating factor for privacy conscious users if they make an
active selection of which resolver to use.

It should also be noted that the choice of a user to configure a single resolver
(or a fixed set of resolvers) and an encrypted transport to use in all network
environments has both advantages and disadvantages. For example, the user has a
clear expectation of which resolvers have visibility of their query data however
this resolver/transport selection may provide an added mechanism to track them
as they move across network environments. Commitments from resolver operators to minimize such tracking as users move between networks are also likely to play a role in user selection of resolvers.

More recently the global legislative landscape with regard to personal data
collection, retention, and pseudonymization has seen significant activity.
Providing detailed practice advice about these areas to the operator is out of
scope, but (#data-sharing) describes some mitigations of data sharing risk.

This document has two main goals:

* To provide operational and policy guidance related to DNS over encrypted
  transports and to outline recommendations for data handling for operators of
  DNS privacy services.

* To introduce the DNS Recursive Operator Privacy (DROP) statement and present a
  framework to assist writers of this document. A DROP statement is a document
  that an operator should publish outlining their operational practices and
  commitments with regard to privacy thereby providing a means for clients to
  evaluate the measurable and claimed privacy properties of a given DNS privacy
  service. The framework identifies a set of elements and specifies an outline
  order for them. This document does not, however, define a particular Privacy
  statement, nor does it seek to provide legal advice as to the contents.

A desired operational impact is that all operators (both those providing
resolvers within networks and those operating large public services) can
demonstrate their commitment to user privacy thereby driving all DNS resolution
services to a more equitable footing. Choices for users would (in this ideal
world) be driven by other factors, e.g., differing security policies or minor
difference in operator policy, rather than gross disparities in privacy concerns.

Community insight [or judgment?] about operational practices can change
quickly, and experience shows that a Best Current Practice (BCP) document about
privacy and security is a point-in-time statement. Readers are advised to seek
out any updates that apply to this document.


# Scope

"DNS Privacy Considerations" [@?RFC7626] describes the
general privacy issues and threats associated with the use of the DNS by
Internet users and much of the threat analysis here is lifted from that
document and from [@!RFC6973]. However this document is limited in scope to best
practice considerations for the provision of DNS privacy services by servers
(recursive resolvers) to clients (stub resolvers or forwarders). Privacy
considerations specifically from the perspective of an end user, or those for
operators of authoritative nameservers are out of scope.


This document includes (but is not limited to) considerations in the following
areas:

1. Data "on the wire" between a client and a server.
2. Data "at rest" on a server (e.g., in logs).
3. Data "sent onwards" from the server (either on the wire or shared with a
third party).

Whilst the issues raised here are targeted at those operators who choose to
offer a DNS privacy service, considerations for areas 2 and 3 could equally
apply to operators who only offer DNS over unencrypted transports but who would
like to align with privacy best practice.

# Privacy related documents

There are various documents that describe protocol changes that have the
potential to either increase or decrease the privacy properties of the DNS. Note
this does not imply that some documents are good or bad, better or worse, just
that (for example) some features may bring functional benefits at the price of a
reduction in privacy and conversely some features increase privacy with an
accompanying increase in complexity. A selection of the most relevant documents
are listed in (#documents) for reference.

# Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP 14 [@!RFC2119] [@!RFC8174] 
when, and only when, they appear in all capitals, as shown here.

DNS terminology is as described in [@RFC8499] with one modification: we restate
the clause in the original definition of Privacy-enabling DNS server in
[@!RFC8310] to include the requirement that a DNS over (D)TLS server should also
offer at least one of the credentials described in Section 8 of [@!RFC8310] and
implement the (D)TLS profile described in Section 9 of [@!RFC8310].

Other Terms:

* DROP: DNS Recursive Operator Privacy statement, see
  (#dns-recursive-operator-privacy-drop-statement).

* DNS privacy service: The service that is offered via a privacy-enabling DNS
  server and is documented either in an informal statement of policy and
  practice with regard to users privacy or a formal DROP statement.

# Recommendations for DNS privacy services

In the following sections we first outline the threats relevant to the specific topic and then discuss the potential actions that can be taken to mitigate them.

We describe two classes of threats:

* Threats described in [@!RFC6973] 'Privacy Considerations for Internet Protocols'
  * Privacy terminology, threats to privacy, and mitigations as described in
    Sections 3, 5, and 6 of [@!RFC6973].

* DNS Privacy Threats
  * These are threats to the users and operators of DNS privacy services that
    are not directly covered by [@!RFC6973]. These may be more operational in
    nature such as certificate management or service availability issues.

We describe three classes of actions that operators of DNS privacy
services can take:

* Threat mitigation for well understood and documented privacy threats to the
  users of the service and in some cases to the operators of the service.
* Optimization of privacy services from an operational or management perspective.
* Additional options that could further enhance the privacy and usability of the
  service.

This document does not specify policy - only best practice, however for DNS
Privacy services to be considered compliant with these best practice guidelines
they SHOULD implement (where appropriate) all:

* Threat mitigations to be minimally compliant.
* Optimizations to be moderately compliant.
* Additional options to be maximally compliant.

## On the wire between client and server

In this section we consider both data on the wire and the service provided to
the client.

### Transport recommendations

[@!RFC6973] Threats: 

* Surveillance:
  * Passive surveillance of traffic on the wire

DNS Privacy Threats:

* Active injection of spurious data or traffic.

Mitigations:

A DNS privacy service can mitigate these threats by providing service over one
or more of the following transports

* DNS-over-TLS [@!RFC7858] and [@!RFC8310].
* DoH [@!RFC8484].

It is noted that a DNS privacy service can also be provided over DNS-over-DTLS
[@RFC8094], however this is an Experimental specification and there are no known
implementations at the time of writing.

It is also noted that DNS privacy service might be provided over IPSec,
DNSCrypt, or VPNs. However, use of these transports for DNS are not standardized
in DNS specific RFCs and any discussion of best practice for providing such a
service is out of scope for this document.

Whilst encryption of DNS traffic can protect against active injection this does
not diminish the need for DNSSEC, see (#dnssec).

### Authentication of DNS privacy services

[@!RFC6973] Threats: 

* Surveillance: 
  * Active attacks on client resolver configuration

Mitigations:

DNS privacy services should ensure clients can authenticate the server. Note
that this, in effect, commits the DNS privacy service to a public identity users
will trust.

When using DNS-over-TLS clients that select a 'Strict Privacy' usage profile
[@!RFC8310] (to mitigate the threat of active attack on the client) require the
ability to authenticate the DNS server. To enable this, DNS privacy services
that offer DNS-over-TLS need to provide credentials in the form of either X.509
certificates [@!RFC5280] or Subject Public Key Info (SPKI) pin sets [@!RFC8310].

When offering DoH [@!RFC8484], HTTPS requires authentication of the server as
part of the protocol.

Server operators should also follow the best practices with regard to Online
Certificate Status Protocol (OCSP) [@RFC2560] as described in [@RFC7525].

#### Certificate management 

Anecdotal evidence to date highlights the management of certificates as one of
the more challenging aspects for operators of traditional DNS resolvers that
choose to additionally provide a DNS privacy service as management of such
credentials is new to those DNS operators.

It is noted that SPKI pin set management is described in [@RFC7858] but that key
pinning mechanisms in general have fallen out of favor operationally for
various reasons such as the logistical overhead of rolling keys.

DNS Privacy Threats: 

* Invalid certificates, resulting in an unavailable service which might force a
  user to fallback to cleartext.
* Mis-identification of a server by a client e.g., typos in URLs or
  authentication domain names [@RFC8310] which accidentally direct clients to
  attacker controlled servers.

Mitigations:

It is recommended that operators:

* Follow the guidance in Section 6.5 of [@!RFC7525] with regards to certificate
revocation.
* Automate the generation, publication, and renewal of certificates. For example,
  ACME [@RFC8555] provides a mechanism to actively manage certificates through
  automation and has been implemented by a number of certificate authorities.
* Monitor certificates to prevent accidental expiration of certificates.
* Choose a short, memorable authentication domain name for the service.

### Protocol recommendations

#### DNS-over-TLS

DNS Privacy Threats:

* Known attacks on TLS such as those described in [@RFC7457].
* Traffic analysis, for example: [@Pitfalls-of-DNS-Encryption].
* Potential for client tracking via transport identifiers.
* Blocking of well known ports (e.g., 853 for DNS-over-TLS).

Mitigations:

In the case of DNS-over-TLS, TLS profiles from Section 9 of [@!RFC8310] and the
Countermeasures to DNS Traffic Analysis from section 11.1 of [@!RFC8310]
provide strong mitigations. This includes but is not limited to:

* Adhering to [@!RFC7525].
* Implementing only (D)TLS 1.2 or later as specified in [@!RFC8310].
* Implementing EDNS(0) Padding [@!RFC7830] using the guidelines in
  [@!RFC8467] or a successor specification.
* Servers should not degrade in any way the query service level provided to
  clients that do not use any form of session resumption mechanism, such as TLS
  session resumption [@RFC5077] with TLS 1.2, section 2.2 of [@RFC8446], or Domain
  Name System (DNS) Cookies [@RFC7873].
* A DNS-over-TLS privacy service on both port 853 and 443. If the operator deploys DoH on the same IP address this requires the use of the 'dot' ALPN value [@dot-ALPN].

Optimizations:

* Concurrent processing of pipelined queries, returning responses as soon as
  available, potentially out of order as specified in [@!RFC7766]. This is often
  called 'OOOR' - out-of-order responses (providing processing performance
  similar to HTTP multiplexing).
* Management of TLS connections to optimize performance for clients using either:
  * [@!RFC7766] and EDNS(0) Keepalive [@!RFC7828] and/or 
  * DNS Stateful Operations [@RFC8490].

#### DoH

DNS Privacy Threats:

* Known attacks on TLS such as those described in [@RFC7457].
* Traffic analysis, for example: [@DNS-Privacy-not-so-private].
* Potential for client tracking via transport identifiers.

Mitigations:

* Clients must be able to forego the use of HTTP Cookies [@RFC6265] and still
  use the service.
* Clients should not be required to include any headers beyond the absolute
  minimum to obtain service from a DoH server. (See Section 6.1 of
  [@I-D.ietf-httpbis-bcp56bis].)


### DNSSEC

DNS Privacy Threats:

* Users may be directed to bogus IP addresses for e.g., websites where they might
  reveal personal information to attackers.

Mitigations:

* All DNS privacy services must offer a DNS privacy service that performs Domain
  Name System Security Extensions (DNSSEC) validation. In addition they must be
  able to provide the DNSSEC RRs to the client so that it can perform its own
  validation.

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
DNSSEC has a far simpler task in terms of DNSSEC Roadblock avoidance [@RFC8027].


### Availability

DNS Privacy Threats:

* A failed DNS privacy service could force the user to switch providers,
fallback to cleartext or accept no DNS service for the outage.

Mitigations:

A DNS privacy service should strive to engineer encrypted services to the same
availability level as any unencrypted services they provide. Particular care
should to be taken to protect DNS privacy services against denial-of-service
attacks, as experience has shown that unavailability of DNS resolving because of
attacks is a significant motivation for users to switch services. See, for
example Section IV-C of [@Passive-Observations-of-a-Large-DNS Service].

Techniques such as those described in Section 10 of [RFC7766] can be of use to operators to defend against such attacks. 

### Service options

DNS Privacy Threats: 

* Unfairly disadvantaging users of the privacy service with respect to the
  services available. This could force the user to switch providers, fallback to
  cleartext or accept no DNS service for the outage.

Mitigations:

A DNS privacy service should deliver the same level of service as offered on
un-encrypted channels in terms of options such as filtering (or lack thereof),
DNSSEC validation, etc.

### Impact of Encryption on Monitoring by DNS Privacy Service Operators

DNS Privacy Threats: 

* Increased use of encryption can impact DNS privacy service operator ability to
  monitor traffic and therefore manage their DNS servers [@!RFC8404].

Many monitoring solutions for DNS traffic rely on the plain text nature of this
traffic and work by intercepting traffic on the wire, either using a separate
view on the connection between clients and the resolver, or as a separate
process on the resolver system that inspects network traffic. Such solutions
will no longer function when traffic between clients and resolvers is encrypted.
Many DNS privacy service operators still have need to inspect DNS traffic, e.g.,
to monitor for network security threats. Operators may therefore need to invest
in alternative means of monitoring that relies on either the resolver software
directly, or exporting DNS traffic from the resolver using e.g., [@dnstap].

Optimization:

When implementing alternative means for traffic monitoring, operators of a DNS
privacy service should consider using privacy conscious means to do so (see
section (#data-at-rest-on-the-server) for more details on data handling and also
the discussion on the use of Bloom Filters in (#ip-address-techniques).

### Limitations of fronting a DNS privacy service with a pure TLS proxy

DNS Privacy Threats: 

* Limited ability to manage or monitor incoming connections using DNS specific
  techniques.
* Misconfiguration (e.g., of the target server address in the proxy
  configuration) could lead to data leakage if the proxy to target server path
  is not encrypted.

Optimization:

Some operators may choose to implement DNS-over-TLS using a TLS proxy (e.g.
[@nginx], [@haproxy], or
[@stunnel]) in front of
a DNS nameserver because of proven robustness and capacity when handling large
numbers of client connections, load balancing capabilities and good tooling.
Currently, however, because such proxies typically have no specific handling of
DNS as a protocol over TLS or DTLS using them can restrict traffic management at
the proxy layer and at the DNS server. For example, all traffic received by a
nameserver behind such a proxy will appear to originate from the proxy and DNS
techniques such as ACLs, RRL, or DNS64 will be hard or impossible to implement in
the nameserver.

Operators may choose to use a DNS aware proxy such as
[@dnsdist] which offers custom options (similar to that
proposed in [@I-D.bellis-dnsop-xpf]) to add source information to packets
to address this shortcoming. It should be noted that such options potentially
significantly increase the leaked information in the event of a
misconfiguration.


## Data at rest on the server

### Data handling

[@!RFC6973] Threats:

* Surveillance.
* Stored data compromise.
* Correlation.
* Identification.
* Secondary use.
* Disclosure.

Other Threats

* Contravention of legal requirements not to process user data.

Mitigations:

The following are recommendations relating to common activities for DNS service
operators and in all cases such activities should be minimized or completely
avoided if possible for DNS privacy services. If data is retained it should be
encrypted and either aggregated, pseudonymized, or anonymized whenever possible.
In general the principle of data minimization described in [@!RFC6973] should be
applied.

* Transient data (e.g., that is used for real time monitoring and threat analysis
  which might be held only in memory) should be retained for the shortest
  possible period deemed operationally feasible.
* The retention period of DNS traffic logs should be only those required to
  sustain operation of the service and, to the extent that such exists, meet
  regulatory requirements.
* DNS privacy services should not track users except for the particular purpose
  of detecting and remedying technically malicious (e.g., DoS) or anomalous use
  of the service.
* Data access should be minimized to only those personnel who require access to
  perform operational duties. It should also be limited to anonymized or
  pseudonymized data where operationally feasible, with access to full logs (if
  any are held) only permitted when necessary.

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
solution or any standards to inform this discussion. This section presents an
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
Section 3, with additional observations from [@van-Dijkhuizen-et-al.]

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

A major privacy risk in DNS is connecting DNS queries to an individual and the
major vector for this in DNS traffic is the client IP address.

There is active discussion in the space of effective pseudonymization of IP
addresses in DNS traffic logs, however there seems to be no single solution that
is widely recognized as suitable for all or most use cases. There are also as
yet no standards for this that are unencumbered by patents. 

(#ip-address-techniques) provides a more detailed survey of various techniques
employed or under development in 2019.

### Pseudonymization, anonymization, or discarding of other correlation data

DNS Privacy Threats:

* Fingerprinting of the client OS via various means including: IP TTL/Hoplimit,
  TCP parameters (e.g., window size, ECN support, SACK), OS specific DNS query
  patterns (e.g., for network connectivity, captive portal detection, or OS
  specific updates).
* Fingerprinting of the client application or TLS library by e.g., HTTP headers
  (e.g., User-Agent, Accept, Accept-Encoding), TLS version/Cipher suite
  combinations, or other connection parameters.
* Correlation of queries on multiple TCP sessions originating from the same IP
  address.
* Correlating of queries on multiple TLS sessions originating from the same
  client, including via session resumption mechanisms.
* Resolvers _might_ receive client identifiers e.g., MAC addresses in EDNS(0)
  options - some Customer-premises equipment (CPE) devices are known to add them [@?MAC-address-EDNS].

Mitigations:

* Data minimization or discarding of such correlation data.

### Cache snooping

[@!RFC6973] Threats: 

* Surveillance:
  * Profiling of client queries by malicious third parties.

Mitigations:

* See [@ISC-Knowledge-database-on-cache-snooping] for an example discussion on
  defending against cache snooping.


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

* Implement QNAME minimization [@!RFC7816].
* Honor a SOURCE PREFIX-LENGTH set to 0 in a query containing the EDNS(0)
  Client Subnet (ECS) option and not send an ECS option in upstream queries.

Optimizations:

* As per Section 2 of [@RFC7871] the server should either:
  * not use the ECS option in upstream queries at all, or
  * offer alternative services, one that sends ECS and one that does not.

If operators do offer a service that sends the ECS options upstream they should
use the shortest prefix that is operationally feasible and ideally
use a policy of allowlisting upstream servers to send ECS to in order to
minimize data leakage. Operators should make clear in any policy statement what
prefix length they actually send and the specific policy used.

Allowlisting has the benefit that not only does the operator know which upstream
servers can use ECS but also allows the operator to decide which upstream
servers apply privacy policies that the operator is happy with. However some
operators consider allowlisting to incur significant operational overhead
compared to dynamic detection of ECS on authoritative servers.

Additional options:

* Aggressive Use of DNSSEC-Validated Cache [@RFC8198] and [@RFC8020]
  (NXDOMAIN: There Really Is Nothing Underneath) to reduce the number of queries
  to authoritative servers to increase privacy.
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
community of users risks exposing data in this way and ought to obfuscate this
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

* Surveillance.
* Stored data compromise.
* Correlation.
* Identification.
* Secondary use.
* Disclosure.

DNS Privacy Threats:

* Contravention of legal requirements not to process user data.

Mitigations:

Operators should not share identifiable data with third-parties.

If operators choose to share identifiable data with third-parties in specific
circumstance they should publish the terms under which data is shared.

Operators should consider including specific guidelines for the collection of
aggregated and/or anonymized data for research purposes, within or outside of
their own organization. This can benefit not only the operator (through
inclusion in novel research) but also the wider Internet community. See the policy published by SURFnet [@SURFnet-policy] on data sharing for research as
an example.

# DNS Recursive Operator Privacy (DROP) statement

To be compliant with this Best Common Practices document, a DNS Recursive
Operator SHOULD publish a DNS Recursive Operator Privacy Statement. Adopting the
outline, and including the headings in the order provided, is a benefit to
persons comparing multiple operators’ DROP statements.

(#current-policy-and-privacy-statements) provides a comparison of some existing
policy and privacy statements.

## Outline of a DROP statement

The contents of (#policy) and (#practice) are non-normative, other than the
order of the headings. Material under each topic is present to assist the
operator developing their own DROP statement and:

* Relates *only* to matters around to the technical operation of DNS privacy services, and not on any other matters.
* Does not attempt to offer an exhaustive list for the contents of a DROP statement.
* Is not intended to form the basis of any legal/compliance documentation.

(#example-drop-statement) provides an example (also non-normative) of a DROP
statement for a specific operator scenario.

### Policy

1. Treatment of IP addresses. Make an explicit statement that IP addresses are treated as personal data.

1. Data collection and sharing. Specify clearly what data (including IP addresses)
is:
    - Collected and retained by the operator, and for what period it is retained.
    - Shared with partners.
    - Shared, sold, or rented to third-parties.
    
    and in each case whether it is aggregated, pseudonymized, or anonymized and
    the conditions of data transfer.
    
1. Exceptions. Specify any exceptions to the above, for example, technically
malicious or anomalous behavior.

1. Associated entities. Declare any partners, third-party affiliations, or
sources of funding.

1. Correlation. Whether user DNS data is correlated or combined with any other
personal information held by the operator.

1. Result filtering. This section should explain whether the operator filters,
edits or alters in any way the replies that it receives from the authoritative
servers for each DNS zone, before forwarding them to the clients. For each
category listed below, the operator should also specify how the filtering lists
are created and managed, whether it employs any third-party sources for such
lists, and which ones.
    -  Specify if any replies are being filtered out or altered for network and
       computer security reasons (e.g., preventing connections to
       malware-spreading websites or botnet control servers).
    -  Specify if any replies are being filtered out or altered for mandatory
       legal reasons, due to applicable legislation or binding orders by courts
       and other public authorities.
    -  Specify if any replies are being filtered out or altered for voluntary
       legal reasons, due to an internal policy by the operator aiming at
       reducing potential legal risks.
    -  Specify if any replies are being filtered out or altered for any other
       reason, including commercial ones.

### Practice

Communicate the current operational practices of the service.

1. Deviations. Specify any temporary or permanent deviations from the policy for
    operational reasons.
    
1. Client facing capabilities. With reference to section
(#recommendations-for-dns-privacy-services) provide specific details of which
capabilities are provided on which client facing addresses and ports:
    1. For DoT, specify the authentication domain name to be used (if any).
    1. For DoT, specify the SPKI pin sets to be used (if any) and policy for
    rolling keys.
    
1. Upstream capabilities. With reference to section
(#data-sent-onwards-from-the-server) provide specific details of which
capabilities are provided upstream for data sent to authoritative servers.

1. Support. Provide contact/support information for the service.

1. Jurisdiction. This section should communicate the applicable jurisdictions
and law enforcement regimes under which the service is being provided.
    1. Specify the operator entity or entities that will control the data and be
    responsible for their treatment, and their legal place of business.
    1. Specify, either directly or by pointing to the applicable privacy policy,
    the relevant privacy laws that apply to the treatment of the data, the
    rights that users enjoy in regard to their own personal information that is
    treated by the service, and how they can contact the operator to enforce
    them.
    1. Additionally specify the countries in which the servers handling the DNS
    requests and the data are located (if the operator applies a geolocation
    policy so that requests from certain countries are only served by certain
    servers, this should be specified as well).
    1. Specify whether the operator has any agreement in place with law
    enforcement agencies, or other public and private parties dealing with
    security and intelligence, to give them access to the servers and/or to the
    data.


## Enforcement/accountability

Transparency reports may help with building user trust that operators adhere to
their policies and practices.

Independent monitoring or analysis could be performed where possible of:

* ECS, QNAME minimization, EDNS(0) padding, etc.
* Filtering.
* Uptime.

This is by analogy with several TLS or website analysis tools that are
currently available e.g., [@SSL-Labs] or
[@Internet.nl].

Additionally operators could choose to engage the services of a third party auditor to verify their compliance with their published DROP statement.

# IANA considerations

None

# Security considerations

Security considerations for DNS-over-TCP are given in [@RFC7766], many of which
are generally applicable to session based DNS. Guidance on operational requirements for DNS-over-TCP are also available in [I-D.dnsop-dns-tcp-requirements].

# Acknowledgements

Many thanks to Amelia Andersdotter for a very thorough review of the first draft
of this document and Stephen Farrell for a thorough review at WGLC and for
suggesting the inclusion of an example DROP statement. Thanks to John Todd for
discussions on this topic, and to Stephane Bortzmeyer, Puneet Sood and Vittorio
Bertola for review. Thanks to Daniel Kahn Gillmor, Barry Green, Paul Hoffman,
Dan York, Jon Reed, Lorenzo Colitti for comments at the mic. Thanks to
Loganaden Velvindron for useful updates to the text.

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

draft-ietf-dprive-bcp-op-10

* Remove direct references to draft-ietf-dprive-rfc7626-bis-05, instead have one general reference RFC7626
* Clarify that the DROP statement outline is non-normative and add some further
  qualifications about content
* Update wording on data sharing to remove explicit discussion of consent
* Move table in section 5.2.3 to an appendix
* Move section 6.2 to an appendix
* Corrections to references, typos and editorial updates from initial IESG
  comments.

draft-ietf-dprive-bcp-op-09

* Fix references so they match the correct section numbers in draft-ietf-dprive-rfc7626-bis-05

draft-ietf-dprive-bcp-op-08

* Address IETF Last call comments.

draft-ietf-dprive-bcp-op-07

* Editorial changes following AD review.
* Change all URIs to Informational References.

draft-ietf-dprive-bcp-op-06

* Final minor changes from second WGLC.

draft-ietf-dprive-bcp-op-05

* Remove some text on consent:
    * Paragraph 2 in section 5.3.3
    * Item 6 in the DROP Practice statement (and example)
* Remove .onion and TLSA options
* Include ACME as a reference for certificate management
* Update text on session resumption usage
* Update section 5.2.4 on client fingerprinting

draft-ietf-dprive-bcp-op-04

* Change DPPPS to DROP (DNS Recursive Operator Privacy) statement
* Update structure of DROP slightly
* Add example DROP statement
* Add text about restricting access to full logs
* Move table in section 5.2.3 from SVG to inline table
* Fix many editorial and reference nits

draft-ietf-dprive-bcp-op-03

* Add paragraph about operational impact
* Move DNSSEC requirement out of the Appendix into main text as a privacy threat
  that should be mitigated
* Add TLS version/Cipher suite as tracking threat
* Add reference to Mozilla TRR policy
* Remove several TODOs and QUESTIONS.

draft-ietf-dprive-bcp-op-02

* Change 'open resolver' for 'public resolver'
* Minor editorial changes
* Remove recommendation to run a separate TLS 1.3 service
* Move TLSA to purely a optimization in Section 5.2.1
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
* Clarify use of allowlisting for ECS
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
 target='https://dl.acm.org/citation.cfm?id=2665959'>
    <front>
        <title>Pretty Bad Privacy: Pitfalls of DNS Encryption</title>
        <author initials='H.' surname='Shulman' fullname='Haya Shulman'>
            <organization>Fachbereich Informatik, Technische Universität Darmstadt</organization>
        </author>
        <date year='2014'/>
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

<reference anchor='DNS-Privacy-not-so-private'
 target='https://petsymposium.org/2018/files/hotpets/4-siby.pdf'>
    <front>
        <title>DNS Privacy not so private: the traffic analysis perspective.</title>
        <author initials='S.' surname='Silby'> </author>
        <author initials='M.' surname='Juarez'> </author>
        <author initials='N.' surname='Vallina-Rodriguez'> </author>
        <author initials='C.' surname='Troncosol'> </author>
        <date year='2019'/>
    </front>
</reference>

<reference anchor='Passive-Observations-of-a-Large-DNS'
           target='http://tma.ifip.org/2018/wp-content/uploads/sites/3/2018/06/tma2018_paper30.pdf'>
    <front>
        <title>Passive Observations of a Large DNS Service: 2.5 Years in the Life of Google</title>
          <author initials='W. B.' surname='de Vries'> </author>
          <author initials='R.' surname='van Rijswijk-Deij'> </author>
          <author initials='P.' surname='de Boer'> </author>
          <author initials='A.' surname='Pras'> </author>
        <date year='2018'/>
    </front>
</reference>

<reference anchor='dnstap' target='http://dnstap.info'>
    <front>
        <title>DNSTAP</title>
        <author>
            <organization>dnstap.info</organization>
        </author>
        <date year='2019'/>
    </front>
</reference>

<reference anchor='nginx' target='https://nginx.org/'>
    <front>
        <title>NGINX</title>
        <author>
            <organization>nginx.org</organization>
        </author>
        <date year='2019'/>
    </front>
</reference>

<reference anchor='haproxy' target='https://www.haproxy.org/'>
    <front>
        <title>HAPROXY</title>
        <author>
            <organization>haproxy.org</organization>
        </author>
        <date year='2019'/>
    </front>
</reference>

<reference anchor='stunnel' target='https://kb.isc.org/article/AA-01386/0/DNS-over-TLS.html'>
    <front>
        <title>DNS-over-TLS</title>
        <author>
            <organization>ISC Knowledge Database</organization>
        </author>
        <date year='2018'/>
    </front>
</reference>

<reference anchor='dnsdist' target='https://dnsdist.org'>
    <front>
        <title>dnsdist Overview</title>
        <author>
            <organization>PowerDNS</organization>
        </author>
        <date year='2019'/>
    </front>
</reference>

<reference anchor='van-Dijkhuizen-et-al.'
           target='https://doi.org/10.1145/3182660'>
    <front>
        <title>A Survey of Network Traffic Anonymisation Techniques and Implementations</title>
          <author initials='N.' surname='Van Dijkhuizen	'> </author>
          <author initials='J.' surname='Van Der Ham'> </author>
        <date year='2018'/>
    </front>
</reference>

<reference anchor='ISC-Knowledge-database-on-cache-snooping' 
   target='https://kb.isc.org/docs/aa-00482'>
    <front>
        <title>DNS Cache snooping - should I be concerned?</title>
        <author>
            <organization>ISC Knowledge Database</organization>
        </author>
        <date year='2018'/>
    </front>
</reference>

<reference anchor='SURFnet-policy' 
   target='https://surf.nl/datasharing'>
    <front>
        <title>SURFnet Data Sharing Policy</title>
        <author>
            <organization>SURFnet</organization>
        </author>
        <date year='2016'/>
    </front>
</reference>

<reference anchor='policy-comparison' 
   target='https://dnsprivacy.org/wiki/display/DP/Comparison+of+policy+and+privacy+statements+2019'>
    <front>
        <title>Comparison of policy and privacy statements 2019</title>
        <author>
            <organization>dnsprivacy.org</organization>
        </author>
        <date year='2019'/>
    </front>
</reference>

<reference anchor='DoH-resolver-policy' 
   target='https://wiki.mozilla.org/Security/DOH-resolver-policy'>
    <front>
        <title>Security/DOH-resolver-policy</title>
        <author>
            <organization>Mozilla</organization>
        </author>
        <date year='2019'/>
    </front>
</reference>

<reference anchor='SSL-Labs' target='https://www.ssllabs.com/ssltest/'>
    <front>
        <title>SSL Server Test</title>
        <author>
            <organization>SSL Labs</organization>
        </author>
        <date year='2019'/>
    </front>
</reference>

<reference anchor='Internet.nl' target='https://internet.nl'>
    <front>
        <title>Internet.nl Is Your Internet Up To Date?</title>
        <author>
            <organization>Internet.nl</organization>
        </author>
        <date year='2019'/>
    </front>
</reference>

<reference anchor='Brenker-and-Arnes'
           target='https://pdfs.semanticscholar.org/7b34/12c951cebe71cd2cddac5fda164fb2138a44.pdf'>
    <front>
        <title>CIRCUMVENTING IP-ADDRESS PSEUDONYMIZATION</title>
          <author initials='T.' surname='Brekne'> </author>
          <author initials='A.' surname='Arnes'> </author>
        <date year='2005'/>
    </front>
</reference>

<reference anchor='IP-Anonymization-in-Analytics' target='https://support.google.com/analytics/answer/2763052?hl=en'>
    <front>
        <title>IP Anonymization in Analytics</title>
        <author>
            <organization>Google</organization>
        </author>
        <date year='2019'/>
    </front>
</reference>

<reference anchor='Geolocation-Impact-Assessement' 
          target='https://support.google.com/analytics/answer/2763052?hl=en'>
    <front>
        <title>Anonymize IP Geolocation Accuracy Impact Assessment</title>
        <author>
            <organization>Conversion Works</organization>
        </author>
        <date year='2017'/>
    </front>
</reference>

<reference anchor='dnswasher' target='https://github.com/PowerDNS/pdns/blob/master/pdns/dnswasher.cc'>
    <front>
        <title>dnswasher</title>
        <author>
            <organization>PowerDNS</organization>
        </author>
        <date year='2019'/>
    </front>
</reference>

<reference anchor='TCPdpriv' target='http://ita.ee.lbl.gov/html/contrib/tcpdpriv.html'>
    <front>
        <title>TCPdpriv</title>
        <author>
            <organization>Ipsilon Networks, Inc.</organization>
        </author>
        <date year='2005'/>
    </front>
</reference>

<reference anchor='Xu-et-al.'
           target='http://an.kaist.ac.kr/~sbmoon/paper/intl-journal/2004-cn-anon.pdf'>
    <front>
        <title>Prefix-preserving IP address anonymization: measurement-based security evaluation and a new cryptography-based scheme</title>
          <author initials='J.' surname='Fan'> </author>
          <author initials='J.' surname='Xu'> </author>
          <author initials='M. H.' surname='Ammar'> </author>
          <author initials='S. B.' surname='Moon'> </author>
        <date year='2004'/>
    </front>
</reference>

<reference anchor='Crypto-PAn' target='https://github.com/CESNET/ipfixcol/tree/master/base/src/intermediate/anonymization/Crypto-PAn'>
    <front>
        <title>Crypto-PAn</title>
        <author>
            <organization>CESNET</organization>
        </author>
        <date year='2015'/>
    </front>
</reference>

<reference anchor='Harvan'
           target='http://mharvan.net/talks/noms-ip_anon.pdf'>
    <front>
        <title>Prefix- and Lexicographical-order-preserving IP Address Anonymization</title>
          <author initials='M.' surname='Harvan'> </author>
        <date year='2006'/>
    </front>
</reference>

<reference anchor='Ramaswamy-and-Wolf'
           target='http://www.ecs.umass.edu/ece/wolf/pubs/ton2007.pdf'>
    <front>
        <title>High-Speed Prefix-Preserving IP Address Anonymization for Passive Measurement Systems</title>
          <author initials='R.' surname='Ramaswamy'> </author>
          <author initials='T.' surname='Wolf'> </author>
        <date year='2007'/>
    </front>
</reference>

<reference anchor='ipcipher1'
           target='https://medium.com/@bert.hubert/on-ip-address-encryption-security-analysis-with-respect-for-privacy-dabe1201b476'>
    <front>
        <title>On IP address encryption: security analysis with respect for privacy</title>
          <author initials='B.' surname='Hubert'> </author>
        <date year='2017'/>
    </front>
</reference>

<reference anchor='ipcipher2'
           target='https://github.com/PowerDNS/ipcipher'>
    <front>
        <title>ipcipher</title>
        <author>
            <organization>PowerDNS</organization>
        </author>
        <date year='2017'/>
    </front>
</reference>

<reference anchor='ipcrypt-analysis'
           target='https://www.ietf.org/mail-archive/web/cfrg/current/msg09494.html'>
    <front>
        <title>Analysis of ipcrypt?</title>
          <author initials='J.' surname='Aumasson'> </author>
        <date year='2018'/>
    </front>
</reference>

<reference anchor='ipcrypt'
           target='https://github.com/veorq/ipcrypt'>
    <front>
        <title>ipcrypt: IP-format-preserving encryption</title>
        <author>
            <organization>veorq</organization>
        </author>
        <date year='2015'/>
    </front>
</reference>

<reference anchor='Bloom-filter'
           target='http://dl.ifip.org/db/conf/im/im2019/189282.pdf'>
    <front>
        <title>Privacy-Conscious Threat Intelligence Using DNSBLOOM</title>
          <author initials='R.' surname='van Rijswijk-Deij'> </author>
          <author initials='G.' surname='Rijnders'> </author>
          <author initials='M.' surname='Bomhoff'> </author>
          <author initials='L.' surname='Allodi'> </author>
        <date year='2019'/>
    </front>
</reference>

<reference anchor='MAC-address-EDNS' target='https://lists.dns-oarc.net/pipermail/dns-operations/2016-January/014143.html'>
    <front>
        <title>Embedding MAC address in DNS requests for selective filtering IDs</title>
        <author>
           <organization>DNS-OARC mailing list</organization>
        </author>
        <date year='2016'/>
    </front>
</reference>

<reference anchor='dot-ALPN'
target='https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids'>
<front>
<title>TLS Application-Layer Protocol Negotiation (ALPN) Protocol IDs</title>
<author>
 <organization>IANA (iana.org)</organization>
</author>
<date year='2020'/>
</front>
</reference>

<!--These lines are needed to generate references for citations that appear only
in the appendix-->
[-@?RFC6235]
[-@!RFC7871]
[-@RFC4033]
[-@?RFC8618]
[-@?I-D.ietf-dnsop-dns-tcp-requirements]
[-@TCPdpriv]
[-@Geolocation-Impact-Assessement]
[-@IP-Anonymization-in-Analytics]
[-@Xu-et-al.]
[-@Crypto-PAn]
[-@Harvan]
[-@Ramaswamy-and-Wolf]
[-@ipcipher1]
[-@ipcipher2]
[-@ipcrypt-analysis]
[-@ipcrypt]
[-@Bloom-filter]
[-@Brenker-and-Arnes]
[-@DoH-resolver-policy]
[-@pcap]
[-@policy-comparison]


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
* 'Usage Profiles for DNS over TLS and DNS over DTLS' [@!RFC8310].
* 'The EDNS(0) Padding Option' [@!RFC7830] and 'Padding Policy for EDNS(0)'
  [@!RFC8467].

These documents apply to recursive and authoritative DNS but are relevant when
considering the operation of a recursive server:

* 'DNS Query Name minimization to Improve Privacy' [@!RFC7816] referred to here
  as 'QNAME minimization'.

## Potential decreases in DNS privacy

These documents relate to functionality that could provide increased tracking of
user activity as a side effect:

* 'Client Subnet in DNS Queries' [@!RFC7871].
* 'Domain Name System (DNS) Cookies' [@RFC7873]).
* 'Transport Layer Security (TLS) Session Resumption without Server-Side State'
  [@RFC5077] referred to here as simply TLS session resumption.
* [@RFC8446] Appendix C.4 describes Client Tracking Prevention in TLS 1.3
* 'A DNS Packet Capture Format' [@RFC8618].
* Passive DNS [@RFC8499].
* Section 8 of [@!RFC8484] outlines the privacy considerations of DoH. Note that
  depending on the specifics of a DoH implementation there may be increased
  identification and tracking compared to other DNS transports.

## Related operational documents

* 'DNS Transport over TCP - Implementation Requirements' [@!RFC7766].
* 'Operational requirements for DNS-over-TCP'
  [@?I-D.ietf-dnsop-dns-tcp-requirements].
* 'The edns-tcp-keepalive EDNS0 Option' [@!RFC7828].
* 'DNS Stateful Operations' [@RFC8490].

# IP address techniques

The following table presents a high level comparison of various techniques
employed or under development in 2019, and classifies them according to
categorization of technique and other properties. Both the specific techniques
and the categorisations are described in more detail in the following sections.
The list of techniques includes the main techniques in current use, but does not
claim to be comprehensive.

Categorization/Property    | GA | d | TC | C | TS | i | B
:--------------------------|--------|------|------|--------|-----|----------|---
Anonymization              |   X    |   X  |  X   |        |     |          | X
Pseudoanonymization        |        |      |      |    X   |  X  |    X     |
Format preserving          |   X    |   X  |  X   |    X   |  X  |    X     |
Prefix preserving          |        |      |  X   |    X   |  X  |          |
Replacement                |        |      |  X   |        |     |          |
Filtering                  |   X    |      |      |        |     |          |
Generalization             |        |      |      |        |     |          | X
Enumeration                |        |   X  |      |        |     |          |
Reordering/Shuffling       |        |      |  X   |        |     |          |
Random substitution        |        |      |  X   |        |     |          |
Cryptographic permutation  |        |      |      |   X    |  X  |    X     |
IPv6 issues                |        |      |      |        |  X  |          |
CPU intensive              |        |      |      |   X    |     |          |
Memory intensive           |        |      |  X   |        |     |          |
Security concerns          |        |      |      |        |     |     X    |
Table: Table 1: Classification of techniques

Legend of techniques: GA = Google Analytics, d = dnswasher, TC = TCPdpriv, C = CryptoPAn, TS = TSA, i = ipcipher, B = Bloom filter

The choice of which method to use for a particular application will depend on
the requirements of that application and consideration of the threat analysis of
the particular situation.

For example, a common goal is that distributed packet captures must be in an
existing data format such as PCAP [@pcap] or C-DNS [@RFC8618] that can be used
as input to existing analysis tools. In that case, use of a format-preserving
technique is essential. This, though, is not cost-free - several authors (e.g.,
[@Brenker-and-Arnes] have observed that, as the entropy in an IPv4 address is
limited, given a de-identified log from a target, if an attacker is capable of
ensuring packets are captured by the target and the attacker can send forged
traffic with arbitrary source and destination addresses to that target, any
format-preserving pseudonymization is vulnerable to an attack along the lines of
a cryptographic chosen plaintext attack.

## Categorization of techniques

Data minimization methods may be categorized by the processing used and the
properties of their outputs. The following builds on the categorization
employed in [@RFC6235]:

* Format-preserving. Normally when encrypting, the original data length and
  patterns in the data should be hidden from an attacker. Some applications of
  de-identification, such as network capture de-identification, require that the
  de-identified data is of the same form as the original data, to allow the data
  to be parsed in the same way as the original.
* Prefix preservation. Values such as IP addresses and MAC addresses contain
  prefix information that can be valuable in analysis, e.g., manufacturer ID in
  MAC addresses, subnet in IP addresses. Prefix preservation ensures that
  prefixes are de-identified consistently; e.g., if two IP addresses are from the
  same subnet, a prefix preserving de-identification will ensure that their
  de-identified counterparts will also share a subnet. Prefix preservation may
  be fixed (i.e. based on a user selected prefix length identified in advance to
  be preserved ) or general.
* Replacement. A one-to-one replacement of a field to a new value of the same
  type, for example, using a regular expression. 
* Filtering. Removing (and thus truncating) or replacing data in a field. Field
  data can be overwritten, often with zeros, either partially (grey marking) or
  completely (black marking).
* Generalization. Data is replaced by more general data with reduced
  specificity. One example would be to replace all TCP/UDP port numbers with one
  of two fixed values indicating whether the original port was ephemeral
  (>=1024) or non-ephemeral (>1024). Another example, precision degradation,
  reduces the accuracy of e.g., a numeric value or a timestamp.
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

## Specific techniques
  
### Google Analytics non-prefix filtering

Since May 2010, Google Analytics has provided a facility [@IP-Anonymization-in-Analytics] that allows website
owners to request that all their users IP addresses are anonymized within
Google Analytics processing. This very basic anonymization simply sets to zero
the least significant 8 bits of IPv4 addresses, and the least significant 80
bits of IPv6 addresses. The level of anonymization this produces is perhaps
questionable. There are some analysis results [@Geolocation-Impact-Assessement]
which suggest that the impact of
this on reducing the accuracy of determining the user's location from their IP
address is less than might be hoped; the average discrepancy in identification
of the user city for UK users is no more than 17%. 

Anonymization: Format-preserving, Filtering (grey marking).

### dnswasher

Since 2006, PowerDNS have included a de-identification tool [@dnswasher] with
their PowerDNS product. This is a PCAP filter that performs a one-to-one mapping
of end user IP addresses with an anonymized address. A table of user IP
addresses and their de-identified counterparts is kept; the first IPv4 user
addresses is translated to 0.0.0.1, the second to 0.0.0.2 and so on. The
de-identified address therefore depends on the order that addresses arrive in
the input, and running over a large amount of data the address translation
tables can grow to a significant size. 

Anonymization: Format-preserving, Enumeration.

### Prefix-preserving map

Used in [@TCPdpriv], 
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

### Cryptographic Prefix-Preserving Pseudonymization

Cryptographic prefix-preserving pseudonymization was originally proposed as an
improvement to the prefix-preserving map implemented in TCPdpriv, described in
[@Xu-et-al.] and implemented in the [@Crypto-PAn] tool. 
Crypto-PAn is now frequently
used as an acronym for the algorithm. Initially it was described for IPv4
addresses only; extension for IPv6 addresses was proposed in [@Harvan]. This uses a cryptographic algorithm
rather than a random value, and thus pseudonymity is determined uniquely by the
encryption key, and is deterministic. It requires a separate AES encryption for
each output bit, so has a non-trivial calculation overhead. This can be
mitigated to some extent (for IPv4, at least) by pre-calculating results for
some number of prefix bits. 

Pseudonymization: Format-preserving, prefix preservation (general).

### Top-hash Subtree-replicated Anonymization

Proposed in [@Ramaswamy-and-Wolf],
Top-hash Subtree-replicated Anonymization (TSA)
originated in response to the requirement for faster processing than Crypto-PAn.
It used hashing for the most significant byte of an IPv4 address, and a
pre-calculated binary tree structure for the remainder of the address. To save
memory space, replication is used within the tree structure, reducing the size
of the pre-calculated structures to a few Mb for IPv4 addresses. Address
pseudonymization is done via hash and table lookup, and so requires minimal
computation. However, due to the much increased address space for IPv6, TSA is
not memory efficient for IPv6.

Pseudonymization: Format-preserving, prefix preservation (general).

### ipcipher

A recently-released proposal from PowerDNS, ipcipher
[@ipcipher1] [@ipcipher2]  is a simple
pseudonymization technique for IPv4 and IPv6 addresses. IPv6 addresses are
encrypted directly with AES-128 using a key (which may be derived from a
passphrase). IPv4 addresses are similarly encrypted, but using a recently
proposed encryption [@ipcrypt] suitable for 32bit
block lengths. However, the author of ipcrypt has since indicated [@ipcrypt-analysis] that it has
low security, and further analysis has revealed it is vulnerable to attack.

Pseudonymization: Format-preserving, cryptographic permutation.

### Bloom filters

van Rijswijk-Deij et al. 
have recently described work using Bloom filters [@Bloom-filter] to
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

# Current policy and privacy statements

A tabular comparison of policy and privacy statements from various DNS
Privacy service operators based loosely on the proposed DROP structure can
be found at [@policy-comparison]. The analysis is based on the data
available in December 2019.

We note that the existing set of policies vary widely in style, content and
detail and it is not uncommon for the full text for a given operator to
equate to more than 10 pages of moderate font sized A4 text. It is a
non-trivial task today for a user to extract a meaningful overview of the
different services on offer.

It is also noted that Mozilla have published a DoH resolver policy
[@DoH-resolver-policy], which describes the minimum set of policy
requirements that a party must satisfy to be considered as a potential
partner for Mozilla’s Trusted Recursive Resolver (TRR) program.


# Example DROP statement

The following example DROP statement is very loosely based on some elements of
published privacy statements for some public resolvers, with additional fields
populated to illustrate the what the full contents of a DROP statement might
look like. This should not be interpreted as

* having been reviewed or approved by any operator in any way
* having any legal standing or validity at all
* being complete or exhaustive

This is a purely hypothetical example of a DROP statement to outline example
contents - in this case for a public resolver operator providing a basic DNS
Privacy service via one IP address and one DoH URI with security based
filtering. It does aim to meet minimal compliance as specified in
(#recommendations-for-dns-privacy-services).

## Policy

1. Treatment of IP addresses. Many nations classify IP addresses as personal
data, and we take a conservative approach in treating IP addresses as personal
data in all jurisdictions in which our systems reside.

1. Data collection and sharing.

    1. IP addresses. Our normal course of data management does
    not have any IP address information or other personal data logged to disk or
    transmitted out of the location in which the query was received. We may
    aggregate certain counters to larger network block levels for statistical
    collection purposes, but those counters do not maintain specific IP address
    data nor is the format or model of data stored capable of being
    reverse-engineered to ascertain what specific IP addresses made what
    queries.

    1. Data collected in logs. We do keep some generalized location information
    (at the city/metropolitan area level) so that we can conduct debugging and
    analyze abuse phenomena. We also use the collected information for the
    creation and sharing of telemetry (timestamp, geolocation, number of hits,
    first seen, last seen) for contributors, public publishing of general
    statistics of system use (protections, threat types, counts, etc.)

        When you use our DNS Services, here is the full list of items that are included in our logs:

        * Request domain name, e.g., example.net
        * Record type of requested domain, e.g., A, AAAA, NS, MX, TXT, etc.
        * Transport protocol on which the request arrived, i.e. UDP, TCP, DoT,  
          DoH
        * Origin IP general geolocation information: i.e. geocode, region ID, 
          city ID, and metro code
        * IP protocol version – IPv4 or IPv6
        * Response code sent, e.g., SUCCESS, SERVFAIL, NXDOMAIN, etc.
        * Absolute arrival time
        * Name of the specific instance that processed this request
        * IP address of the specific instance to which this request was 
          addressed (no relation to the requestor’s IP address)

        We may keep the following data as summary information, including all the
        above EXCEPT for data about the DNS record requested:

        * Currently-advertised BGP-summarized IP prefix/netmask of apparent
          client origin
        * Autonomous system number (BGP ASN) of apparent client origin

        All the above data may be kept in full or partial form in permanent
        archives.

    1. Sharing of data.

        Except as described in this document, we do not intentionally share,
        sell, or rent individual personal information associated with the
        requestor (i.e. source IP address or any other information that can
        positively identify the client using our infrastructure) with anyone
        without your consent.

        We generate and share high level anonymized aggregate statistics
        including threat metrics on threat type, geolocation, and if available,
        sector, as well as other vertical metrics including performance metrics
        on our DNS Services (i.e. number of threats blocked, infrastructure
        uptime) when available with our threat intelligence (TI) partners,
        academic researchers, or the public.

        Our DNS Services share anonymized data on specific domains queried
        (records such as domain, timestamp, geolocation, number of hits, first
        seen, last seen) with our threat intelligence partners. Our DNS Services
        also builds, stores, and may share certain DNS data streams which store
        high level information about domain resolved, query types, result codes,
        and timestamp. These streams do not contain IP address information of
        requestor and cannot be correlated to IP address or other personal data.

        We do not and never will share any of its data with marketers, nor will
        it use this data for demographic analysis.

1. Exceptions. There are exceptions to this storage model: In the event of
actions or observed behaviors which we deem malicious or anomalous, we may
utilize more detailed logging to collect more specific IP address data in the
process of normal network defence and mitigation. This collection and
transmission off-site will be limited to IP addresses that we determine are
involved in the event.

1. Associated entities. Details of our Threat Intelligence partners can be found
at our website page (insert link).

1. Correlation of Data. We do not correlate or combine information from our logs
with any personal information that you have provided us for other services, or
with your specific IP address.

1. Result filtering. 

    1. Filtering. We utilise cyber threat intelligence about malicious domains
    from a variety of public and private sources and blocks access to those
    malicious domains when your system attempts to contact them. An NXDOMAIN is
    returned for blocked sites.
    
     2. Censorship. We will not provide a censoring component and will limit our
    actions solely to the blocking of malicious domains around phishing,
    malware, and exploit kit domains.
    
     1. Accidental blocking. We implement allowlisting algorithms to make sure
    legitimate domains are not blocked by accident. However, in the rare case of
    blocking a legitimate domain, we work with the users to quickly allowlist
    that domain. Please use our support form (insert link) if you believe we are
    blocking a domain in error.


## Practice

1. Deviations from Policy. None in place since (insert date).

1. Client facing capabilities. 

    1. We offer UDP and TCP DNS on port 53 on (insert IP address)
    1. We offer DNS-over-TLS as specified in RFC7858 on (insert IP address). It
    is available on port 853 and port 443. We also implement RFC7766.
        1. The DoT authentication domain name used is (insert domain name).
        1. We do not publish SPKI pin sets.
    1. We offer DNS-over-HTTPS as specified in RFC8484 on (insert URI template). 
       Both POST and GET are supported.
    1. Both services offer TLS 1.2 and TLS 1.3.
    1. Both services pad DNS responses according to RFC8467.
    1. Both services provide DNSSEC validation.
    
1. Upstream capabilities.

    1. Our servers implement QNAME minimization.
    1. Our servers do not send ECS upstream.

1. Support. Support information for this service is available at (insert link).

1. Jurisdiction. 

    1. We operate as the legal entity (insert entity) registered in (insert
    country) as (insert company identifier e.g Company Number). Our Headquarters
    are located at (insert address).
    2. As such we operate under (insert country) law. For details of our company
    privacy policy see (insert link). For questions on this policy and
    enforcement contact our Data Protection Officer on (insert email address).
    3. We operate servers in the following countries (insert list).
    4. We have no agreements in place with law enforcement agencies to give them
    access to the data. Apart from as stated in the Policy section of this
    document with regard to cyber threat intelligence, we have no agreements in
    place with other public and private parties dealing with security and
    intelligence, to give them access to the servers and/or to the data.



