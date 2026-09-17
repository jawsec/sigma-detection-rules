# Indicator provenance and maintenance

Reviewed 2026-09-17. This is a small static selection, not a threat-intelligence
feed. An operator describing a mining pool does not make its domain malicious.
No Stratum handshake, share submission, maliciousness assessment, or DNS endpoint
uptime check was performed.

| Selected domain | Primary source inspected | Basis | Review due |
|---|---|---|---|
| `supportxmr.com` | [Operator site](https://www.supportxmr.com/) | Site identifies SupportXMR; retained as a pool-operator domain | 2026-10-17 |
| `moneroocean.stream` | [Operator dashboard](https://moneroocean.stream/) | Describes a Monero mining pool | 2026-10-17 |
| `2miners.com` | [Operator site](https://2miners.com/) | Describes mining pools and endpoints | 2026-10-17 |

The selector covers apex names, subdomains, and optional trailing dots. Apex
coverage deliberately includes website browsing. Domain-boundary suffixes avoid
matching `not2miners.com` or `2miners.com.example.test`. Raw IP connections and
unlisted pools are not covered.

The previous 21-domain list included historical operators and had no provenance
or review dates. Unverified entries were removed, including ethermine.org,
flexpool.io and minexmr.com. Removal means **not revalidated for this pack**; it
is not a claim about their current ownership, safety, or operational state.

The miner selector contains a small executable-name list and explicit Stratum
URI markers. Primary project references are [XMRig](https://xmrig.com/docs/miner/command-line-options),
[nanominer](https://github.com/nanopool/nanominer),
[lolMiner](https://github.com/Lolliedieb/lolMiner-releases), and
[NBMiner](https://github.com/NebuTech/NBMiner). Names are spoofable and versions
can change. They do not establish authorization or mining success.

The three wallet-lure strings are **unverified lexical heuristics**, not known-bad
domains: `wallet-connect-verify`, `metamask-verify`, `phantom-verify`. They have no
incident attribution or freshness claim. Adding a campaign IOC requires a cited
report, observed dates, expiry/review date, and a clear distinction between a
whole domain and a substring. Do not promote a keyword hunt into a critical alert.

Maintenance owner: jawsec. Review monthly and when an operator or upstream rule
changes. Check each retained domain's primary documentation, review ownership or
service changes, record evidence and review date here, update Sigma and the Wazuh
subset together, and rerun checks. Remove entries that cannot be justified.
A calendar due date does not implement automatic expiry; the owner must perform
the review. Refresh the ATT&CK snapshot separately when mappings change.

[SigmaHQ's existing Monero DNS rule](https://github.com/SigmaHQ/sigma/blob/2e8fd89f82d9104c1b30321a307254ddeea17de2/rules/network/dns/net_dns_pua_cryptocoin_mining_xmr.yml)
and [Zeek mining-pool content](https://github.com/SigmaHQ/sigma/blob/2e8fd89f82d9104c1b30321a307254ddeea17de2/rules/network/zeek/zeek_dns_mining_pools.yml)
show that this subject is already covered publicly. The local rule is not claimed
to be novel or more effective.
