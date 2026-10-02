# SOC & NGFW Home Lab: Palo Alto + Wazuh

A segmented home lab that combines a **Palo Alto next-generation firewall** with a **Wazuh SIEM** to practice the full blue-team loop: segment the network, enforce policy, simulate attacks, and detect them with custom rules.

> Built entirely on my own equipment for learning. No production or third-party systems were involved.

## Goals

- Design a zoned network (WAN / LAN / DMZ) and enforce it with application-aware firewall policy
- Collect endpoint and network logs in a SIEM
- Write custom detection rules and validate them against real attack tooling

## Architecture

| Machine | Role | Zone |
|---|---|---|
| Palo Alto NGFW | Perimeter firewall, zone segmentation, app control | n/a |
| Wazuh manager | SIEM: log collection, correlation, alerting | `[TODO]` |
| Desktop workstation | Monitored endpoint (Wazuh agent) | `[TODO]` |
| Metasploitable2 | Intentionally vulnerable target | `[TODO]` |
| Kali Linux | Attacker machine | `[TODO]` |

- **Firewall:** Palo Alto `[TODO: VM-Series / PAN-OS version]`
- **SIEM:** Wazuh `[TODO: exact version, e.g. 4.x]`
- **Hypervisor:** `[TODO: VirtualBox / VMware / Proxmox / EVE-NG]`

`[TODO: add network diagram -> architecture/network-diagram.png]`

## Firewall policy

Security rules are evaluated top to bottom. Screenshot: `screenshots/palo-alto-security-policy.png`

| # | Rule | From -> To | Applications | Action |
|---|---|---|---|---|
| 1 | LAN-to-DMZ-allow | LAN -> DMZ | any | Allow (disabled) |
| 2 | WAN2DMZ-allow | WAN -> DMZ (10.0.30.10 only) | any | Allow + security profile |
| 3 | LAN2WAN-block-apps | LAN -> WAN | BitTorrent, Facebook, Psiphon, Tor, Ultrasurf | Deny |
| 4 | Block-quic | LAN -> WAN | QUIC | Deny |
| 5 | LAN2WAN allow | LAN -> WAN | any (application-default ports) | Allow + security profile |
| 6 | DMZ2LAN deny | DMZ -> LAN | any | Deny |
| 7 | WAN2LAN deny | WAN -> LAN | any | Deny |
| 8 | Block-Unknown-Apps | any -> any | unknown-tcp, unknown-udp | Deny |
| 9 | intrazone-default | intrazone | any | Allow |
| 10 | interzone-default | interzone | any | Deny |

**Design notes**

- **DMZ isolation:** only one DMZ host is reachable from WAN, and the DMZ cannot initiate connections into the LAN, which limits lateral movement if the exposed host is compromised.
- **Anonymizer and P2P blocking:** Tor, Psiphon, Ultrasurf and BitTorrent are denied from LAN. QUIC is blocked so traffic falls back to TCP/TLS, where the firewall can inspect it.
- **Default deny:** anything not explicitly allowed between zones is dropped by the interzone rule.
- `[TODO: security profiles attached to rules 2 and 5, e.g. Antivirus, Vulnerability Protection, Anti-Spyware, URL Filtering]`

## Log pipeline

- Wazuh agents on `[TODO: which machines]` -> Wazuh manager
- Palo Alto logs `[TODO: forwarded to Wazuh via syslog? which log types: traffic, threat, system]`

## Attack simulations & detection

| Attack | Tool | Technique (MITRE ATT&CK) | Detected? | How |
|---|---|---|---|---|
| Network scan | Nmap | T1046 Network Service Discovery | `[TODO: re-test]` | `[TODO]` |
| Brute force | Hydra against `[TODO: SSH / FTP / Telnet]` | T1110 Brute Force | Yes | Custom Wazuh rules (`/var/ossec/etc/rules/local_rules.xml`) |

### Custom rules

`[TODO: paste or link configs/wazuh/local_rules.xml and explain each rule: what it matches, rule ID, level, frequency/timeframe]`

### Results

`[TODO: for each test, record time to alert, alert level, any false positives, and what you tuned]`

## What I learned

- `[TODO: 3 to 4 honest bullets, e.g. rule ordering in PAN-OS, how brute-force correlation works in Wazuh, what was hard]`

## Possible improvements

- Forward firewall threat logs to Wazuh and correlate with endpoint events
- Add detection for further scenarios (web attacks, reverse shells, suspicious process execution)
- Map every custom rule to a MITRE ATT&CK technique
- Add Wazuh active response to block repeat offenders automatically

## Repository structure

```
soc-ngfw-lab/
├── README.md
├── architecture/
│   └── network-diagram.png
├── configs/
│   └── wazuh/local_rules.xml
├── attacks/
│   └── attack-scenarios.md
├── results/
│   └── detection-results.md
└── screenshots/
```

## Disclaimer

For educational use in an isolated lab only. Never run these tools against systems you do not own or have permission to test.
