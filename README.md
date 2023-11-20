# Public DoH Lists

## Overview
Automatically generated blocklists in popular formats for public DNS-over-HTTPS (DoH) providers. A static list of known providers as at 11/2023 is augmented by regularly parsing the community maintained DNS Wiki pages of [Curl](https://github.com/curl/curl/wiki/DNS-over-HTTPS) and [AdGuard](https://github.com/AdguardTeam/KnowledgeBaseDNS/blob/master/docs/general/dns-providers.md).

## Automatic updates
The Python script is scheduled to run via Github Actions every second day at midnight UTC. If a change is detected, all blocklists will be updated and published automatically in-place.

## Intended use case
These lists can be used to limit the availability of DoH on networks where DNS policy is enforced (e.g. PiHole, AdGuard or other managed resolver).

The IP and Domain lists can be used in conjunction to block known DoH providers at both the network and resolver level. This combined approach is recommended, in particular above just blocking the IPs, as some providers will resolve to different server addresses based on the geolocation of the query.

It is also recommended that DNS-over-TLS / DNS-over-QUIC is blocked (TCP/UDP 853) and standard lookups are redirected to the desired resolver (NAT TCP/UDP 53).

## Overlap with standard DNS
Some entries on the DoH provider lists (notably 1.1.1.1 - Cloudflare and 8.8.8.8 - Google) overlap with standard DNS services.
