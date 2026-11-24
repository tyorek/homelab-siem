# Syslog collector build record (P2): CT 112 `syslog`

**Date:** 2026-11-23, 08:15-08:30 CST · **Runbook:** `rsyslog-collector-standup-runbook.md` sections 3.2-3.7 and 3.9 · **Done via:** pve web shell (root@pam) · **Status:** collector built and listening; RB5009 lease and lockdown (3.1, 3.8) applied 08:31. No sources are sending yet (P3, section 4).

## What was built

| Item | As built |
|---|---|
| CT | 112 `syslog`, unprivileged, Debian 13.8 (`hot1:vztmpl/debian-13-standard_13.6-1_amd64.tar.zst`, upgraded), 1 core, 512 MB, no swap, 8 GB on `hot1`, onboot=1, nesting=1 |
| Network | net0 on **vmbr1** tag 99, firewall=1, static 192.168.99.11/28 gw .1, MAC `02:00:5E:6F:8E:6E`, DNS 192.168.15.9 / 10.20.0.9, search home.arpa |
| Storage | `/srv/syslog` on pve root (42 GB free at build), 100000:100004 0750, mp0 at `/var/log/remote` in CT 112 |
| Packages | rsyslog 8.2504.0, nfdump 1.7.5, nftables 1.1.3, logrotate 3.22.0, curl 8.14.1 |
| rsyslog | `/etc/rsyslog.d/10-remote.conf` as runbook 3.5; UDP 514 on v4, dedicated ruleset, per-device files keyed on source IP |
| nfcapd | `nfcapd-collector.service`, UDP 2055 bound to 192.168.99.11, `flows/rb5009` + `flows/fw-edge` (2750 root:adm); the package's own `nfdump.service` disabled |
| Host firewall | nftables as runbook 3.6, loaded and enforcing (policy drop) |
| Retention | logrotate `/etc/logrotate.d/remote` (30 days, dry-run OK); `/etc/cron.d/nfexpire` 30 days |
| Time zone | America/Chicago; receive stamps are RFC 3339 with -06:00 |
| Agent box | CT 107 `mp0: /srv/syslog,mp=/srv/syslog,ro=1`, `agent` added to `adm`, CT rebooted 08:25 (supervisor-chat and wazuh-agent came back), nfdump installed with its listener disabled |
| Freshness check | `/usr/local/bin/syslog-freshness` installed; cron line in `/etc/cron.d/syslog-freshness` is **commented out** until a Kuma push URL is set |

Copies of every config file are in `MikroTik & Service Configs/syslog-collector-ct112/`.

## Deviations from the runbook

- **Bridge is vmbr1, not vmbr0.** Copied from CT 107 as the runbook says; the VLAN 99 guests (107, 110, 111) all sit on vmbr1, where pve's own vmbr1.99 lives.
- **Template already present on `hot1`**, so no `pveam download`; `local` doesn't hold vztmpl on this host. Rootfs on `hot1` like CT 107.
- **IPv6 disabled inside the CT** (`/etc/sysctl.d/90-disable-ipv6.conf`). It picked up a GUA and a ULA by SLAAC on first boot, and the 3.8 lockdown is IPv4-only, so v6 would have been an unfiltered egress path. rsyslog still binds `[::]:514`, which is harmless with v6 off.
- **The other VLAN 99 CTs use DHCP; this one is static**, per the runbook. That makes the lease reservation in 3.1 the important part (see open items).
- **Install ran as a transient systemd unit** (`systemd-run`) after a web-console drop killed the first apt run halfway through. `dpkg --configure -a` ran clean and the final install returned rc 0.

## Verification done

- 192.168.99.11 silent on ARP and absent from every guest config before creation.
- `rsyslogd -N1` clean; rsyslog, nfcapd-collector and nftables active and enabled; `ss` shows 0.0.0.0:514 and 192.168.99.11:2055.
- Loopback test line written in the expected format (`2026-11-23T08:24:30.643273-06:00 127.0.0.1 user.notice ...`) to `_unknown/`, which was then removed.
- A syslog line sent from pve (192.168.99.2, not on the allow list) was dropped by nftables; SSH from pve accepted.
- From CT 107: `sudo -u agent ls /srv/syslog` works; `touch /srv/syslog/x` gives "Read-only file system".

## Open items

1. ~~RB5009 lease and lockdown~~ **Applied 2026-11-23 08:31 in winbox.** Pre-checks matched the runbook (`dhcp7` on mgmtbridge99, no existing .11 lease, anchor rules present once). The `syslog:` rules sit at positions 21-24, directly above "forward: mgmt vlan99 to all vlans" (25). The lease for `02:00:5E:6F:8E:6E` shows `waiting`, which is expected because the CT is static. Functional test from CT 112: DNS resolves, HTTPS to the internet is blocked, and TCP 445 to DC1 is blocked. Counters after the test: DNS udp 3 packets, drop-all-other 11 packets (logged as SYSLOG-DROP).
2. Uptime Kuma: create the push monitor, put its URL in `/usr/local/bin/syslog-freshness`, then uncomment the cron line.
3. P3 / section 4: dual-send on RB5009 and AG01-03, heartbeat schedulers, RB5009 traffic-flow, fw-edge NetFlow, Suricata eve, remote syslog and rule logging, plus the RB5009 "syslog: fw-edge to collector" rule. Flag the changes in the next digest so they aren't triaged as drift.
4. Optional: enroll CT 112 as Wazuh agent 16. The 3.8 rules allow 1514/1515 to the manager.
5. Section 5 verification once sources are sending.

## P3 progress (2026-11-23, 08:34-08:44)

**RB5009 (section 4.0, 4.1 and its 4.2 rule), applied 08:35 in winbox.** Added a `collector` logging action (UDP to 192.168.99.11:514, src 192.168.99.1), info/warning/error/critical rules on it, and a `syslog-heartbeat` scheduler (10 min). Added the `syslog: fw-edge to collector` forward rule above "forward: isolate vlans". Enabled traffic-flow on bridge5, bridge15, bridge20, bridge25, bridge30 and mgmtbridge99 (active 1m, inactive 15s; cache-entries left at 256k) with an IPFIX target to .11:2055 from src .1. Pre-checks matched the runbook: the existing `remote` action was untouched, traffic-flow had been disabled, and there was no heartbeat. nfcapd registered the IPFIX exporter at 08:35:15. The first full window (08:35-08:40) held 2,731 flows (about 117k packets and 148 MB) with internal pre-NAT source addresses.

**AG01, AG02, AG03 (section 4.0), applied 08:39, 08:42 and 08:43.** The same action, four rules and heartbeat, sending from .4, .5 and .6. All three have their mgmt99 address from DHCP (flag `D`), so the src-address depends on those leases staying fixed. AG03 reports as a hEX (mmips) rather than a CRS305. The existing `remote` actions to Wazuh were unchanged on every device.

**Collector check, 08:44.** `rb5009/`, `ag01/`, `ag02/` and `ag03/` each hold their `collector test <device>` line and a first heartbeat (the scheduler fires once at creation). There is no `_unknown/`. Every line arrives as `user.notice` because RouterOS's default remote format doesn't carry severity, so the topic text (for example `script,info`) is the field to read severity from.

**fw-edge (section 4.2), applied 08:45-08:48 through the OPNsense API from the logged-in GUI session.** Before the changes, the live settings matched the runbook: NetFlow capture was off (no interfaces, active timeout 1800), Suricata eve HTTP/TLS logging and eve syslog output were off, there was no remote syslog destination, and the rules 1030-1055 / 1061 / 1066 / 2041 / 2042 / 2051 all had log off. No separate backup was downloaded. OPNsense keeps every save in System > Configuration > History, and the nightly config push to the agent box will capture the new state.
- **Remote syslog:** destination uuid `78626478-...`, UDP(4) to 192.168.99.11:514, programs `audit,filterlog,suricata`, levels info and above. It arrives from 172.16.255.1 with OPNsense's RFC 3164 header kept verbatim. Note that the header time is UTC, while the collector's own stamp is local.
- **NetFlow:** v9, capture on DMZ (opt2/vlan02) only, no egress-only interfaces, target 192.168.99.11:2055, active 60 s, inactive 15 s, local collection off. Service status active. nfcapd registered the v9 exporter, and the 08:45-08:50 window held 221 flows (about 633 KB), with DMZ hosts on one side: caddy to pve:8006, buauth to the Wazuh manager, the admin desktop to NPM:443, and IPv6 link-local and broadcast MNDP from the DMZ segment.
- **Rule logging:** log turned on for exactly 20 rules (1030-1036, 1040-1045, 1050, 1055, 1061, 1066, 2041, 2042, 2051), then applied. A before/after diff of all 86 rules showed only those 20 `log` fields changed. This build has no `savepoint` endpoint, so the change was applied without the 60-second auto-rollback.
- **Suricata:** eve HTTP (extended, header dump "None") and TLS (extended) on, eve syslog output on. Restarted with your go-ahead. The engine stopped at 08:48:02 and was running again at 08:48:17, so DMZ and public-handoff traffic stopped for about 15 seconds. Afterwards internet egress from pve was confirmed, service status was running, and the alert list was intact. Re-check that new alerts keep appearing alongside NetFlow over the next few hours.

**Runbook gap found: OPNsense's "eve syslog output" sends alerts only.** The GUI help text says it sends alerts in eve format, and that drop logs stay with the internal logger. So the HTTP and TLS records the runbook expected in syslog go only to fw-edge's local `eve.json`. The Wazuh agent ships that file to the manager, but per section 4.2 the built-in rules should match those event types at level 0, which means they are processed and not stored. Today the TLS/SNI and HTTP metadata is therefore stored only on fw-edge's disk, under OPNsense's log retention. Options for P7/P8, not yet decided:
- A Wazuh local rule that raises `event_type` tls/http to a stored level, which puts them in the indexer rather than the collector.
- A small shipper on fw-edge that forwards eve.json to .11.
- Reading them from the Wazuh archive if `logall` is ever turned on.

The collector currently gets Suricata alerts and engine messages only.

**Collector state at 08:50:** `rb5009/`, `ag01/`, `ag02/`, `ag03/` and `fw-edge/` are all populated (fw-edge had 190 filterlog, 22 audit and 4 suricata lines in its first three minutes), plus `flows/rb5009` and `flows/fw-edge`. There is no `_unknown/`. P3 is complete.

**Still open:**
1. The Uptime Kuma push monitor, then uncomment `/etc/cron.d/syslog-freshness`.
2. A digest note so tonight's mikrotik-audit diff (logging action, rules, scheduler and traffic-flow on all four devices, plus the five new `syslog:` filter rules on the RB5009) and the fw-edge config push aren't triaged as drift.
3. ~~Decide on the Suricata metadata path above~~: done, see "eve.json forwarder" below.
4. Wait a week, then check sizing with `du -sh /srv/syslog/*` and the RB5009 traffic-flow cache.
5. Optional: Wazuh agent 16 on CT 112.

## eve.json forwarder (2026-11-23, 08:53-09:08)

**Why:** the SIEM can't take the HTTP/TLS volume. In the first six minutes after turning on eve HTTP/TLS logging, `eve.json` grew about 336 KB, roughly 80 MB/day against about 3.6 MB/week for alerts alone. Two things that were already sending that load to Wazuh were found and fixed:
- The os-wazuh-agent plugin read the whole of `eve.json` (log_format json).
- Its syslog bridge to Wazuh includes `program("suricata")`, so with eve syslog output on, every alert reached the manager twice.

**Access path:** QEMU guest agent from the pve root shell (`qm guest exec 109`). The helper `/root/fe` on pve runs a command inside fw-edge and prints stdout, stderr and rc. Files go in over `--pass-stdin`: one guest-exec carrying a roughly 2 KB inline argument timed out and wedged qemu-ga until it was restarted through the OPNsense service API.

**Wazuh: http/tls kept off the manager.**
- Plugin setting `logcollector.suricata_eve_log` set to 0 (the template now renders `<!-- disabled -->`).
- `/var/ossec/etc/shared/default/agent.conf` on the siem gained an `<agent_config name="fw-edge">` block that reads `/var/log/suricata/eve.json` as json with `<ignore type="PCRE2">"event_type":"(http|tls)"</ignore>`. `verify-agent-conf` returned OK.
- The backup is at `/var/ossec/etc/agent.conf.default.bak-20261123`, moved out of the shared folder so it isn't pushed to the 15 agents. A copy of the block is in `MikroTik & Service Configs/fw-edge-eve-forwarder/`.
- The agent picked it up at 14:57:34Z. Verification: since then the agent's logcollector counted 17 eve events against 19 non-http/tls lines in the file (timing skew), while skipping 220 http/tls lines. The manager's alerts.json still gets fw-edge Suricata alerts (latest 15:02:40Z at the check).
- Because this lives in the manager's agent.conf, OPNsense plugin updates can't undo it. If the plugin's eve toggle is ever turned back on, alerts would be double-read again.

**Suricata:** eve syslog output turned back off (HTTP/TLS logging stays on in eve.json), with your go-ahead for a second restart. The engine stopped at 09:04:36 and was running again at 09:04:52 (16 s without DMZ or internet traffic). Afterwards internet was confirmed, there was no eve JSON in syslog, and `type: syslog` is absent from suricata.yaml. The Suricata engine messages (start and stop) still reach the collector and Wazuh as `program("suricata")`. That matters for T1562, because a stopped IPS shows up.

**Forwarder on fw-edge:** `/usr/local/etc/syslog-ng.conf.d/zz-eve-collector.conf`, copy in `MikroTik & Service Configs/fw-edge-eve-forwarder/`.
- A syslog-ng `file()` source follows `eve.json` (follow-freq 1, no-parse, program `suricata-eve`, local5.info, 64 KB message size) and sends to a UDP network destination at 192.168.99.11:514 (IPv4).
- It's a native drop-in, so nothing new is installed. Every OPNsense log path reads only `s_all`, so this source doesn't leak into the local logs or the Wazuh bridge. The syntax check passed, and it was loaded with `syslog-ng-ctl reload` at 15:01Z.
- It sends every eve record (alert, drop, anomaly, http, tls, ssh), so the collector now gets drops, which syslog never carried.
- syslog-ng resumes from its persist file after a restart, and it follows newsyslog's weekly rotation of eve.json.

**Collector:**
- `10-remote.conf` routes `$programname == "suricata-eve"` from fw-edge to `/var/log/remote/fw-edge/eve.log`, in the same line format as the other files (backup `/root/10-remote.conf.bak-20261123` in CT 112). logrotate's `*/*.log` glob covers it.
- `syslog-freshness` now also flags `fw-edge-eve` if eve.log goes 20 minutes without a write.
- Every received record parsed as JSON. The largest so far was 1,806 bytes, and none were truncated.

**Delivery and loss:**
- The startup backlog (about 600 records sent in one burst at reload) lost about 340 records somewhere between fw-edge and the collector. The collector showed 0 UDP receive or buffer errors, so the loss happened upstream.
- In steady state, delivery matched (17 written, 15 received over 30 s with snapshot skew).
- Expect a burst loss like that only after syslog-ng has been down. That's the UDP trade-off already accepted in the runbook.

**Side effect to know:** restarting rsyslog on the collector makes fw-edge's sends bounce with ICMP "connection refused". syslog-ng then marks the destination broken for its 60 s `time_reopen`, which cost about a minute of fw-edge syslog at 08:58:56-08:59:57. Restart rsyslog in a quiet moment, or add `time-reopen(5)` to `d_eve_collector` if that matters.

**Sizing note:** fw-edge's own `eve.json` will now hold about a week of http/tls (around 0.5 GB at the observed rate) before the Sunday rotation. `/var/log` has 21 GB free. On the collector it adds roughly 80 MB/day before compression, which is still within the section 2 estimate.

## DNS servers as sources (2026-11-23, 09:11-09:23)

**Sources added:** primenodetls 192.168.15.9 (Technitium, CT 103 on pve), secnodetls 192.168.15.10 and tertnodetls 192.168.15.11 (Unbound, CT 104/105 on pve), buauth 10.20.0.9 (Technitium), bunode1 10.20.0.13 and bunode2 10.20.0.14 (Unbound). All six are Ubuntu 26.04. The last three are libvirt-LXC containers on pibox, registered with machined as `lxc-<pid>-<name>` and reached from the OMV container terminal's host shell with `sudo nsenter -t <machinectl Leader> -a`. That shell runs as `labadmin` with passwordless sudo, and `lxc-ls` doesn't see these containers. Input to that terminal goes in as a paste event, because typed keystrokes lose spaces.

**On each server:** `/etc/rsyslog.d/90-collector.conf` forwards `*.info` over UDP to 192.168.99.11:514 in the traditional forward format, with an in-memory LinkedList queue so a collector outage never blocks local logging. `/etc/cron.d/syslog-heartbeat` logs a `syslog-heartbeat` line every 10 minutes, because the Unbound nodes (verbosity 1, log-queries off) are otherwise nearly silent. Copies are in `MikroTik & Service Configs/dns-syslog-forwarding/`. Each host's test line arrived in its own file under `/var/log/remote/<name>/`.

**Network path:**
- **RB5009:** address lists `syslog-dns-vlan15` and `syslog-dns-dmz`, plus two forward accepts above "forward: isolate vlans". VLAN 15 traffic is pinned to in-interface bridge15, and the DMZ resolvers to vlan100-public-handoff, the same anti-spoofing pattern as the existing buauth-to-DC rules. Record in `MikroTik & Service Configs/syslog-collector-dns-sources.rsc`.
- **fw-edge:** new DMZ rule 1051, pass UDP from alias `DMZ_RESOLVERS` (exactly the three) to 192.168.99.11:514, log on, ahead of block 1060.
- **Accepted risk:** this is a new DMZ-to-internal path, one-way UDP to a single port on the collector. A compromised DMZ resolver could flood or spoof lines into the collector, but can't get a session out of it. Rule 1051's pass logging makes any unusual use visible.

**Collector restructured so sources can be added without a restart:**
- **Lookup table:** IP-to-device mapping moved out of the rsyslog if/else chain into `/etc/rsyslog-devmap.json` (`lookup_table`, `reloadOnHUP="on"`, nomatch `_unknown`).
- **Named sets:** the nftables allow-lists became sets `syslog_src` and `flow_src`.
- **Adding a source from now on:** add it to the JSON and to the set (`nft add element inet filter syslog_src { ip }`, then mirror the change in `/etc/nftables.conf`), then run `systemctl kill -s HUP rsyslog`. No restart, so fw-edge's 60-second reopen gap doesn't happen.
- **The restructure itself** needed one last restart (09:14).
- **Backups:** the pre-change files are in `/root/pre-v2-20261123/` in CT 112.
- **Freshness check:** `syslog-freshness` now checks all six DNS hosts too (20-minute threshold, met by the heartbeat).

**What this does and doesn't capture yet:** this is the servers' system and service logging (sssd, systemd, cron, rsyslog, Unbound's own messages, the Technitium process's journal output) plus the heartbeat. It does **not** include DNS query logs:
- **Technitium (primenodetls, buauth):** query history isn't in syslog. primenodetls has no Technitium log folder, and its query logs go to the "Query Logs (PostgreSQL)" app. Shipping queries to the collector needs Technitium's Log Exporter app (syslog target 192.168.99.11), installed through each web console, which needs your login.
- **Unbound (secnode, tertnode, bunode1, bunode2):** `log-queries` is off. Those nodes only see Technitium's and OPNsense's cache misses, so their query logs would mostly duplicate what Technitium has, at a small per-query latency cost on resolvers that are tuned for latency.

**Seen on first contact:** primenodetls immediately sent an existing `sssd_be` "GSSAPI Error: Unspecified GSS failure" at daemon.err. That's worth a look on its own (its AD/Kerberos join).

## Technitium query logs (2026-11-23, 09:26-09:31)

**Installed:** Technitium's **Log Exporter** app 3.1.1 from the app store, on primenodetls and on buauth, through each console's session API. Only the Syslog sink is enabled, set to UDP to 192.168.99.11:514; the File and HTTP sinks stay off, and maxQueueSize is the default 1,000,000. The config is in `MikroTik & Service Configs/dns-syslog-forwarding/technitium-log-exporter-config.json`. The existing apps (Advanced Blocking, Query Logs (PostgreSQL)) are untouched, so the consoles' query-log views keep working.

**Record format:** each query arrives from the server's own address with program name `TechnitiumDNSServer` at local6.info, as an RFC 5424 line whose structured data carries `timestamp`, `clientIp`, `protocol`, `responseType`, `responseRtt`, `rCode`, `qName`, `qType` and `qClass`, plus the answer. The exporter nests a second `<182>1 ...` header inside the message, and the collector stores it verbatim like everything else.

**Collector: stream split.** A second lookup table, `/etc/rsyslog-streammap.json`, maps program name to a stream file (`TechnitiumDNSServer` to `queries`, `suricata-eve` to `eve`; anything else goes to the device's main log). Records from a mapped program are written to `/var/log/remote/<device>/<stream>.log`, so the query records are in `primenodetls/queries.log` and `buauth/queries.log`, and fw-edge's `eve.log` keeps its path. The table reloads on HUP like the device map, so future splits need no restart either.
- **Last restart:** the rule change needed one more restart, at 09:28:39. fw-edge's feed recovered by 09:30:07.
- **Backup:** pre-change config in `/root/pre-v3-20261123/` in CT 112.

**Verified:**
- primenodetls query records stopped landing in `primenodetls.log` and go only to `queries.log`.
- buauth's first records arrived. They are low volume, 3 in 90 s, the first being an `example.com` lookup that looks like a health probe.
- logrotate's `*/*.log` glob covers the new files.

**Volume:** primenodetls ran at about 4 queries/s (362 in 88 s on a Monday morning) at about 850 bytes per line, roughly 300 MB/day uncompressed. With daily compression (delaycompress keeps yesterday plain) the 30-day queries store should be a few GB. That is the largest stream on the collector now. `/srv` had 42 GB free. Re-check with `du -sh /srv/syslog/*/queries.log*` after a week.

**Privacy note:** `queries.log` is the whole household's DNS history (every client IP and name looked up) for 30 days, readable on the collector and, through the read-only mount, by the agent box's `agent` user. That's the data the detectors need, but it's worth keeping in mind for anything that reads or summarizes it, especially LLM-written reports.

**Unbound nodes:** per-query logging stays off on secnodetls, tertnodetls, bunode1 and bunode2. They only see Technitium's and OPNsense's cache misses, and these resolvers are tuned for latency.

## P1 (2026-11-23, 09:36)

The indexer plugin list on the siem includes `opensearch-anomaly-detection` and `opensearch-job-scheduler`. Decision, recorded in runbook section 8.1:
- **Plugin:** only for cheap detectors over the existing `wazuh-alerts-*` data (no new ingest).
- **P7:** stays a custom engine on the agent box, working on the collector's raw store and sending only findings to Wazuh.
- **Why:** indexing the raw store would bring back the SIEM load this build avoids.

The burn-in clock (P10) starts today; the earliest end is 2026-12-07.

## Anomaly engine (P7/P8/P9), 2026-11-23, 09:41-10:05

**Built and scheduled, learn-only until 2026-12-07.** Full description in `Scripts - Monitoring & Audit/anomaly-engine/README.md`; summary in runbook section 8.2.
- **Collector (CT 112):** `/usr/local/bin/flow-csv-export` plus `/etc/cron.d/flow-csv-export` (`1-59/5`) write slim gzipped flow CSVs (ts|te|src|dst|sport|dport|proto|flags|packets|bytes, full IPv6, plain numbers). The output dir is `/var/log/remote/flows-csv` (2750 root:adm), with 30-day expiry. Backfill: 34 files in under a second, about 28 KB per RB5009 5-minute file, roughly 8 MB/day per exporter.
- **Agent box (CT 107):** `/home/agent/agents/anomaly-engine/` (engine.py, config.json, run.sh, README.md), agent crontab `3-58/5`. A first run over everything since this morning took 1.5 s: about 50k RB5009 flows, 6k fw-edge flows, 5.4k DNS queries and 2.5k eve records.
- **Initiator logic fix during testing:** the first pass made 13 false DMZ findings (NPM and caddy answering the admin desktop, DNS probe replies). The cause is that the 1-minute active timeout splits sessions, so first-seen order inside one file is unreliable. Ports now decide first (service to ephemeral = reply). After the fix, only the real pibox IPv6 CLDAP leak remains.
- **Siem (CT 100):** `etc/rules/anomaly_engine_rules.xml` (100600 base, 100601-100619 per detector with ATT&CK and `$(anomaly_engine.summary)` descriptions), checked with wazuh-logtest. The manager was restarted at about 09:53 CST to load it. `agent.conf` gained a `claude_agents` block (backup `/var/ossec/etc/agent.conf.default.bak-20261123b`).
- **Agent pickup race:** the agent first logged "No such file" for `findings.jsonl`, because it read the new block before the file existed. Fixed by creating the file and restarting the agent.
- **Test alert:** one test finding was sent through. It shows as a level-7 "pipeline test" alert at 15:55:51Z, and will appear in today's wazuh-triage run.

## DNS zone parity and per-query round robin (2026-11-23, about 10:00 to 10:50 CST)

- **Zone parity:** buauth was missing pve.home.arpa, node.home.arpa, sup.example.com and digest.example.com, plus several AAAA records. They were added through the Technitium API (TTL 3600), and the zone fingerprints now match. Two things on buauth were left alone: an empty typo zone `digest.example.com`, and dc01/dc02.home.arpa, which only exist there and are fine that way. Advanced Blocking and the settings already matched. buauth's ULA was already in `dns-auth6`, so the add I tried was refused as a duplicate and nothing changed.
- **Router (RB5009), record in `MikroTik & Service Configs/syslog-collector-dns-round-robin.rsc`:**
  - VLAN 5 keeps its primary/fallback redirect to primenodetls. The v4 fallback-block gates were narrowed to 192.168.5.0/28.
  - VLANs 20/25/30 (interface list `DNS-RR`) are split by `nth=2,1` dst-nat between primenodetls and buauth, on v4 and v6, udp and tcp. There are disabled failover-to-primary rules for when buauth is down.
  - `dns-rr-check` runs every 30 s. It probes both resolvers with `:resolve` and toggles the rules. It logs only when it changes a rule, or when both resolvers fail. The first version used a `:global` that never matched in scheduler context, so it logged every run; it was replaced at 10:28. A self-heal test disabled the dmz v4 rule by hand, and the script turned it back on within one run.
  - VLAN 99/mgmt is deliberately outside the split, so probes and infra keep fixed resolvers.
- **Defects found by checking the resolvers' own logs, not the NAT counters:**
  - The NAT counters read 341/339, but buauth was only logging about 5 % of in-scope queries. There were two causes.
  - **(a)** The v6 gates "DNS fallback block LAN v6 udp/tcp" still matched every non-DMZ interface, so every v6 query sent to buauth was dropped in forward (822 drops). Clients retried until a query landed on primenodetls. Fixed by narrowing the gates to `in-interface=bridge5`; buauth started logging v6 clients within a minute.
  - **(b)** G9 (192.168.25.5) has "G9 block internet" (forward drop, `out-interface-list=WAN`). fw-edge's `vlan100-public-handoff` is in the WAN list, so G9's buauth half was dropped. Fixed by adding G9 to the new address-list `dns-rr-pin` and two pin dst-nat rules ahead of the split. Any device that gets an internet-block rule later needs the same entry.
- **Engine (CT 107):** deployed the resolver-share detector.
  - Added a `share` table, 15-minute windows, and a baseline per hour of day.
  - Outage-like windows outside 15-85 % are kept out of learning.
  - After 2026-12-07, a window at |z| >= 4 or an outage-like window raises `resolver_share_imbalance` and launches `investigate_dns_share.py`.
  - The investigator gathers counts, rcodes, RTT, top and one-sided clients, live probes, router NAT state over the agent's read-only SSH, and router log lines. `llm-report` then writes the triage per `investigations/dns-share/CLAUDE.md`, and an engine_status finding points at the report.
  - `--no-finding` is for manual or test runs.
  - `resolver_share.since` is 10:47 (after the fixes). Share rows from before then were deleted so the baseline starts clean.
  - Backup of the previous files: `backup-<ts>/`.
- **Siem (CT 100):** rule 100620 (level 9, T1562 plus T1071.004, groups dns and defense_evasion). It passed `wazuh-analysisd -t` and logtest, and the manager was restarted at about 10:48 CST. Backup: `/var/ossec/etc/anomaly_engine_rules.xml.bak-20261123b`.
- **Trade-offs to know:**
  - The split is per new connection. Normal stub resolvers use a new source port per query, so it's per query for them; a client that holds one UDP socket open sticks to one resolver until conntrack times out.
  - Each resolver keeps its own cache, so the cache hit rate drops.
  - buauth is one hop further (through fw-edge), and its RTT runs a few ms higher.
- **Router SSH for the investigator (11:01):** the RB5009 `agent` user now accepts 192.168.99.3 and 192.168.99.14 (CT 107). A new input accept for .14 on port 22 sits right after the existing agent rule. The read-only `agent-ro` group is unchanged. Verified from CT 107: `router_state()` returned the NAT prints. Rollback is in the round-robin `.rsc`.

## Detection board P4-P13 (2026-11-23 evening to 2026-11-24 01:10 CST)

P4, config and user changes. Decoders `config_change_decoders.xml` and rules `config_change_rules.xml` (100530-100550)
on the Wazuh manager; RouterOS change lines arrive through a `system,info,!account` logging rule to the existing
`remote` action on the RB5009 (23:17) and AG01-AG03 (00:40-00:41), and fw-edge's OPNsense audit log through the Wazuh
agent's localfile block. All four MikroTik devices and fw-edge were tested live (100532/100533/100536 on the router,
100536 from each switch, 100541-100548 on fw-edge). Record: `MikroTik & Service Configs/wazuh-p4-config-change-logging.rsc`.

P5, ATT&CK IDs on every custom rule: done (`wazuh-mikrotik-npm-rules.xml`, 100500-100527).

P6, Sigma: `Scripts - Monitoring & Audit/sigma2wazuh/`, 183 Sigma rules converted to 249 Wazuh rules (101000-101248),
deployed as sigma_rules.xml (sha d9d0ca3f...). Local filter for the LAN GUAs on the public-IP logon rules. A longer
false-positive watch on real traffic is still open.

P10, burn-in: the anomaly engine is learn-only until 2026-12-07; tune thresholds after.

P11/P12/P13, attack-stories on CT 107 (`Scripts - Monitoring & Audit/attack-stories/`, README there). Hourly at :17;
joins ATT&CK-tagged Wazuh alerts and engine findings into stories, rule-based severity, Claude audit for high and
critical, Kuma push monitor `attack-stories` -> Discord, daily-digest section, dashboard at
https://digest.example.com/attack.html (Homepage "Agents" group, "Attack stories" iframe) with a 7-day timeline,
the current stories and an ATT&CK coverage matrix (286 custom rules over 86 techniques); Navigator layer
`attack-layer.json` downloadable from the page. Tuning in the first runs: pre-filter Sigma public-IP alerts suppressed,
Wazuh 87702 re-scored (T1110 -> T1046, level 6), burn-in-only stories capped at medium, 0.0.0.0 and :: as hubs.
First real alerts: the 23:17 router changes (labadmin) and the 00:40 switch logging changes (admin), both correctly
flagged as "probably you, confirm".

Kuma push monitors added 2026-11-24: attack-stories (75 min), anomaly-engine (15 min, pushed by its run.sh), syslog
freshness (15 min, CT 112 cron enabled). Tokens were read straight from Kuma's database into agent.env and the
freshness script, never printed.

Found while doing this: CT 107 is now 192.168.99.14 (DHCP; it was .3). CT 210's Proxmox firewall still allows only .3
to Ollama (11434) and ping, so every agent's local-model call times out and escalates to Claude (first seen in
wazuh-triage at 00:05 on 2026-11-24). Fix: change the two `-source 192.168.99.3` rules in /etc/pve/firewall/210.fw to
.14 and pin .14 as a static DHCP lease. Awaiting the admin's OK.

## Loose ends, 2026-11-24 01:00-01:12 CST

- primenodetls sssd GSSAPI "Server not found in Kerberos database" (about 3,500 a day, first seen
  2026-10-25): the DCs' GUAs reverse-resolve to the ISP PTR names (syn-2600-...), and Kerberos's default rdns
  canonicalised the LDAP host to that name, so it asked for ldap/syn-2600-...@HOME.ARPA. Fixed with
  `rdns = false` and `dns_canonicalize_hostname = false` in /etc/krb5.conf [libdefaults] (backup krb5.conf.bak-20261124),
  sssd restarted 01:06:55; no errors since, AD lookups work. Any other Linux domain member with the same symptom
  takes the same two lines.
- anomaly-engine README on CT 107 refreshed (dns-rr-pin note, Kuma heartbeat).
- fw-edge rule 1062 is disabled since 2026-11-08 (Surfshark design), so the order problem only matters on a VPN
  restore; noted in the OPNsense runbook's restore line.
- Still open: CT 210 firewall .3 -> .14 (approval), buauth's leftover typo zone (approval to delete), pibox IPv6
  CLDAP to the DCs (pibox-side fix, see below), sizing check about 2026-11-30, Sigma false-positive watch.
- pibox CLDAP: winbind's DC locator pings every address the DCs' names resolve to, AAAA first. Pinning dc01/dc02 to
  their v4 addresses in pibox's /etc/hosts (hosts: files first in nsswitch) stops the v6 attempts without opening
  DMZ-to-DC v6; the alternative is the long-pending v6 route plus a fw-edge allow, which is the larger exposure.

## Approved fixes, 2026-11-24 01:20-01:30 CST

- CT 210 (llm) Proxmox firewall: both `-source 192.168.99.3` rules (Ollama 11434, ping) now `-source 192.168.99.14`
  (backup /root/210.fw.bak-20261124 on pve). From CT 107: Ollama /api/tags 200, ping answered. Agents use the local
  model again from their next runs.
- RB5009: static DHCP lease on dhcp7 (mgmtbridge99) for CT 107, 192.168.99.14, MAC matching 107.conf, comment
  "agents CT 107 (agent box, anomaly engine), static since 2026-11-24". The box held .14 with no router lease at all.
  Rollback: /ip dhcp-server lease remove [find address=192.168.99.14]

- buauth: deleted the empty typo zone `digest.example.com` (only SOA and NS, checked first) through the API with
  The admin's web session, 01:26 CST. buauth now has 43 zones; `digest.example.com` is untouched.
- pibox: the admin pinned dc01/dc02 to 192.168.20.7/.6 in /etc/hosts (about 01:27 CST). fw-edge had been blocking 36
  IPv6 CLDAP (UDP 389) packets from pibox to VLAN 20 every 5 minutes; the 01:25 batch was the last, none at 01:30
  while fw-edge's filterlog kept flowing. OMV can rewrite /etc/hosts on a network apply; re-check after one.

## CT 107 back on 192.168.99.3 (2026-11-24 01:35-01:40 CST)

- Cause of the drift: CT 107 had `ip=dhcp`, and its DHCP client (udhcpc) takes a lease once and never renews. On
  the 2026-11-23 08:25 restart it came up on .14 instead of .3, and the router's lease then expired. Everything built
  for the old address broke quietly: the supervisor chat (NPM's sup.example.com proxy host and fw-edge's allow
  rule point at .3, giving a 502), and Ollama on CT 210 (firewall allowed only .3).
- Fix (the admin's choice): CT 107 is now static in Proxmox, `ip=192.168.99.3/28,gw=192.168.99.1` (IPv6 still dhcp;
  backup /root/107.conf.bak-20261124), and the RB5009 dhcp7 reservation for its MAC moved to .3 (comment "agents CT
  107 ... static .3 since 2026-11-24"). Container rebooted 01:38. Checked: sup.example.com 200 through NPM, Ollama
  200, Wazuh indexer search works, supervisor-chat, wazuh-agent and cron active.
- CT 210's firewall now allows both .3 and .14 (Ollama, ping). The .14 entries added the night before are now unused
  and harmless: CT 210 firewall lines, RB5009 user `agent` address list, and the input rule "agent: input RouterOS
  SSH from anomaly-engine box CT107". Remove them whenever convenient; nothing else uses .14.
- .14 leftovers removed 2026-11-24 04:25 CST: CT 210 firewall .14 lines (Ollama still 200 from .3); RB5009 user
  `agent` address back to 192.168.99.3/32 only; input rule "agent: input RouterOS SSH from anomaly-engine box CT107"
  (src 192.168.99.14) removed. No other .14 references on pve, CT 100, 110, 111 or 112.

## attack-stories scoring change (2026-11-24 04:20)

The 03:17 run raised a critical story (687569e6e1) from two routine level-5 events on desktop-01: the
EasyAntiCheat_EOS kernel driver service install (7045, 11:08 on the 23rd) and a Volume Shadow Copy mount (Ntfs 98,
02:19). Three tactics from two weak events was enough for "critical". A tactic chain now needs n >= 3 events with
one at level >= 8 for critical, and n >= 2 with one at level >= 7 for high (level 10/12 alone still escalate).
Re-scored: 0 critical, 4 high, 4 medium, 11 low. Stories also only re-alert when they get worse (higher max level
or a new tactic), not when more events of the same kind join.

## Attack-stories drill-down, blocked-attempt cap, supervisor Mermaid (2026-11-24, ~04:40–05:10)

Dashboard tiles (critical/high/medium/low stories, ATT&CK alerts 24 h) are now buttons that open a drill-down panel with a drop-down when there is more than one item; picking one draws its ATT&CK chain (tactics in kill-chain order with techniques, events, max level and rules), its position in the Enterprise matrix, an events-over-time strip and the event list, with deep links `attack.html?cat=&story=` and an "open full view" link from the Homepage embed. attack_layer.py also writes attack-techniques.json (names + official tactics). stories.py adds rules, tech_detail, all_blocked and per-event outcome to each story plus top-level alert_groups; a story whose core events are all failed attempts (NPM status 400/401/403/404/405/444/499 via `data.id`, firewall block rules 87701/87702, engine dmz_firewall_block) is capped at medium. `data.id` had to be added to the indexer `_source` list before the cap matched anything. Result: 9a71d00b95 stays critical (the admin's own 04:25 cleanup), the three internet scanners a35f9145d7 (8.234.35.234), 0f51aea086 (103.59.161.68) and d91ce1cad9 (139.59.244.94) dropped to medium. The 04:45 critical Discord alert was those two stories (our cleanup plus the then-uncapped scanner). Backups: CT 107 `stories.py.pre-blocked`, `config.json.pre-blocked`; CT 111 `/root/attack.html.pre-blocked`.

Supervisor chat renders Mermaid: patch_mermaid.py vendored mermaid.min.js at `/static/mermaid.min.js`, renders ```mermaid fences (strict, dark), CSP script-src 'self' 'unsafe-inline', and the supervisor CLAUDE.md "Diagrams" section tells Gemma to answer diagram requests with a Mermaid ATT&CK-chain flowchart plus a drill-down link. Verified in the browser by rendering a four-tactic chain through the page's own blk()/mmdRun() under the live CSP. Backups `*.pre-mermaid`.
