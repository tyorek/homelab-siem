# Wazuh SIEM expansion: network syslog, NPM access logs, switch hardening and a threat map

**Date:** 2026-11-20 (about 09:50-11:25 CST) · **Environment:** homelab lab (siem CT 100 at 192.168.5.12, Wazuh 4.14;
RB5009 + AG01/AG02 CRS305 + AG03 hEX on RouterOS 7.23.5; pibox/NPM; fw-edge OPNsense) · **Status:** complete, open items below
· **Raw timestamped log:** `Archive/wazuh-syslog-mikrotik-npm-rollout-worklog-2026-11-20.md`

## Summary

Before today Wazuh only saw hosts that could run an agent. The devices that actually enforce the network's security
boundaries (the RB5009 and the three access switches) sent it nothing: the router's firewall-drop logs, including the
VLAN 25 zero-trust drops, lived in a 2,000-line RAM buffer, and NPM's access logs for the 12 internet-facing proxy hosts
were never collected. By the end of the session the Wazuh manager is the syslog receiver for the whole MikroTik fabric,
NPM's access logs flow in with the visitor's real IP instead of Cloudflare's, custom decoders and 21 rules turn both into
alerts, the switches no longer hold IP addresses on the DMZ or other data VLANs, and a new "Threat Detection Heat Map"
dashboard plots attack sources, including Suricata's block-list hits, which Wazuh previously could not geolocate. The new
pipeline produced a real finding within minutes (the agent box retrying undeliverable mail every few seconds), which was
traced and fixed.

## 1. Starting state

The manager already had a UDP 514 syslog `<remote>` block (allowed 192.168.5.1 and 192.168.99.4-.6) added at 09:58, and
`wazuh-remoted -t` / `wazuh-analysisd -t` passed, but the manager had been running since 2026-11-09, so nothing was
listening. Fifteen agents were registered; all were active except the laptop DESKTOP-K49Q9G5. fw-edge's OPNsense agent
plugin was already sending filterlog and Suricata eve. The pibox agent only sent dpkg, rootcheck, syscheck, journald and
netstat. On the RB5009 the built-in `remote` log action still pointed at 0.0.0.0, and the firewall topic went only to
`fwmemory`. No custom dashboards or visualizations existed, and the shared agent configuration was empty.

## 2. Wazuh manager: listener, decoders and rules

The manager was restarted to open the listener; `wazuh-remoted` now listens on 192.168.5.12:514/udp, and every agent that
was connected before reconnected. Two files were installed in CT 100 (owner wazuh:wazuh, mode 660), with sources in
`MikroTik & Service Configs/`: `wazuh-mikrotik-npm-decoders.xml` as `etc/decoders/mikrotik_npm_decoders.xml`, and
`wazuh-mikrotik-npm-rules.xml` as `etc/rules/mikrotik_npm_rules.xml`. The decoders parse RouterOS firewall lines
(log-prefix, chain, in/out interface, protocol, source and destination address and port, IPv4 and bracketed IPv6, with or
without ports and NAT fields, with or without the topic prefix RouterOS puts in front), RouterOS login success and failure
lines, and NPM's two access-log formats. The regexes were tested offline against sample lines before installing.

The first `wazuh-logtest` run exposed three problems, all fixed before going live. The two login decoders had been siblings
under one parent, and Wazuh applies only the first child whose prematch matches (a child without a prematch always wins), so
login fields came out empty; they are now two standalone decoders. Login-failure lines are claimed first by the built-in
syslog rule 2501, so rule 100510 is written as a child of 2501. NPM lines were being claimed by the built-in Zeus web-server
decoder, which has the same `[dd/Mon/yyyy:hh:mm:ss zone]` prematch; nothing in the lab runs Zeus, so `ossec.conf` now
carries `<rule_exclude>0255-zeus_rules.xml</rule_exclude>` and
`<decoder_exclude>ruleset/decoders/0390-zeus_decoders.xml</decoder_exclude>`. After the fixes all six sample lines hit the
intended rules.

| Rule | Level | Fires on |
|---|---|---|
| 100500 | 0 | any decoded MikroTik firewall line (parent) |
| 100501 | 3 | VLAN 25 inter-VLAN drop (log-prefix ISO25 / ISO25-6) |
| 100502 / 100503 | 10 | IoT device trying to reach VLAN 20 (domain/servers) / VLAN 99 (management) |
| 100504 | 8 | one IoT source dropped 20+ times in 2 minutes |
| 100505 / 100506 | 3 / 8 | ISO4 VLAN-isolation drop / same source 30+ times in 2 minutes |
| 100507 | 6 | agent box (192.168.99.3) egress outside its allow-list |
| 100510 / 100511 | 5 / 10 | router or switch login failure / 6+ from one source in 5 minutes |
| 100512 / 100513 / 100514 | 3 / 8 / 3 | login / login from outside VLAN 5 / login from VLAN 99 |
| 100520 | 0 | any NPM access line (parent) |
| 100521 / 100524 | 5 / 10 | 401/403 from a public address / 10+ from one source in 2 minutes |
| 100522 / 100523 | 0 | 401/403 from the LAN or DMZ (silenced) |
| 100525 | 7 | recon/exploit probe paths (`/.env`, `/.git/`, `wp-login.php`, `phpmyadmin`, ...) |
| 100526 | 6 | 20+ 404s from one source in 60 seconds |
| 100527 | 7 | 444 responses (the Next-Action / React Server Components drop) |

## 3. NPM access logs and the real client IP

NPM runs as a Docker container on pibox; its data volume is
`/srv/dev-disk-by-uuid-cfdb5281-09b1-4b52-a5ee-423579a88cec/data/nginxproxymanager/data` (from the compose file in OMV).
Instead of editing pibox, the manager pushes log collection to the pibox agent through the shared agent configuration: a
`<agent_config name="pibox">` block in `etc/shared/default/agent.conf` (source `wazuh-pibox-npm-agent.conf`) collects
`data/logs/proxy-host-*_access.log` and `fallback_access.log`. `verify-agent-conf` passed and agent 005 reported
"synchronized".

A phone test from off Wi-Fi to `sup.example.com/.env` fired rule 100525 from `proxy-host-20_access.log`, proving the
whole path, but the source address was 172.71.170.113, a Cloudflare edge. NPM's nginx.conf already trusts its generated
CDN list (which matches Cloudflare's published ranges) but takes the client address from `X-Real-IP`, which Cloudflare
doesn't send; adding a second `real_ip_header` at http level would be a duplicate-directive error. The fix was one
server-level line, `real_ip_header CF-Connecting-IP;`, appended to `/data/nginx/custom/server_proxy.conf` (the file that
already holds the 444 Next-Action block and that NPM includes in all 12 proxy hosts). `nginx -t` passed and nginx reloaded.
The retest produced four 100525 alerts from the phone's carrier address, confirmed by the admin. NPM's default catch-all host
doesn't include that file, so `fallback_access.log` still shows Cloudflare addresses; and because NPM also trusts the LAN
subnets, a LAN device could spoof the header, while internet clients outside Cloudflare's ranges cannot.

## 4. Router and switch syslog

On the RB5009 (winbox terminal) the existing `remote` action was pointed at 192.168.5.12:514/udp with source 192.168.5.1,
and the firewall, account, critical, error and warning topics were added to it as logging rules 5-9; the local `fwmemory`
rule is unchanged. A first attempt that used `bsd-syslog=yes` failed because that parameter doesn't exist on RouterOS
7.23.5; nothing was applied by it. AG01, AG02 and AG03 got the same action with source addresses 192.168.99.4, .5 and .6
and the account, critical, error, warning and interface topics (logging rules 4-8 on each). For every device a
`:log warning` test message was captured arriving at CT 100's interface on pve, `wazuh-remoted` logged the source as
allowed, and the discarded count stayed at 0. RouterOS sends its topic list in front of each message
(`script,warning ...`), which the decoders handle. The planned RB5009 forward rule for switch syslog was not needed: an
existing rule already lets VLAN 99 reach 192.168.5.12.

## 5. Switch management-plane cleanup

While configuring syslog it turned out that every switch held DHCP-assigned addresses on several data VLANs, each with its
own default route: AG01 on VLANs 5, 10 (DMZ), 15, 20 and 99; AG02 and AG03 on 5, 10 and 99. That made the switches'
management services reachable by IP from the DMZ and the client VLANs. Nothing in monitoring used those addresses (the
mikrotik-audit agent reaches the switches on VLAN 99). The data-VLAN DHCP clients were disabled rather than deleted, with
the comment "mgmt cleanup 2026-11-20: L3 on mgmt99 only", next to the existing VLAN 25 note ("IoT25: switch has no L3
presence on VLAN 25"). Each switch now has a single address (AG01 192.168.99.4, AG02 .5, AG03 .6) and a single default
route via 192.168.99.1. After each change the switch reached its gateway and the manager, its syslog arrived through the
router, and the audit agent's SSH login still worked; the winbox sessions, which connect by MAC address, stayed up. Layer-2
access (MAC-winbox, MAC-telnet, neighbor discovery on every VLAN the switch carries) is deliberately left open: the admin
manages the switches by MAC from VLAN 5 and is fine with it. AG03 is an hEX, not a CRS305.

## 6. First finding: the agent box's undeliverable mail

Within half an hour of the router feed going live, Threat Hunting showed 144 alerts of rule 100507: the agent box
(192.168.99.3) repeatedly trying to reach Microsoft's mail servers (52.101.x.x, `*.protection.outlook.com`) on TCP 25 and
being dropped by "agent: drop all other egress". The cause was Postfix, which TurnKey ships, holding 10 queued messages
(22 KB) for an Outlook.com mailbox: cron and system mail that could never leave VLAN 99. With the admin's choice (option 1,
queue deleted unread) the agent user's crontab was backed up to `/root/agent.crontab.pre-mailto` and given `MAILTO=""`
(all four `run.sh` jobs intact), the queue was cleared with `postsuper -d ALL`, and Postfix was stopped and disabled. The
last drop was logged at 10:59:48 and none followed. The agents already report through Uptime Kuma, Discord and the digest,
so nothing is lost.

## 7. "Threat Detection Heat Map" dashboard

Built through the dashboard's saved-objects API (Explore > Dashboards, id `threat-detection-heatmap`, index pattern
`wazuh-alerts-*`, default range 7 days), at https://192.168.5.12. It has four panels. The source map uses scaled circle
markers on a yellow-to-red scale: alerts at level 5 and above plus Suricata severity 1-2, city-level locations only, with the
home IPv6 prefix 2001:db8:4a00:1f00::/56 excluded. The Top 5 Source Countries table uses the same filter without the
city-level restriction. The detections-over-time heat map has threat categories as rows (Suricata, MikroTik firewall drops
including IoT, fw-edge repeated blocks, auth failures, attacks, web scans, invalid logins) and 3-hour slots as columns, with
compliance, package and config-change noise excluded. The Suricata inbound table lists signature and source for hits from
outside the network, with internal ranges, the home prefix and STUN excluded. One dashboard advanced setting was raised:
`visualization:heatmap:maxBuckets` from the default 50 to 250, because 7 days of 3-hour slots exceeded 50.

Three tuning decisions shaped the panels. About 37,000 "Windows Logon Success" alerts on DC01 and DC02 carried a location,
all local: the lab's own hosts on the the ISP IPv6 prefix. They are excluded by prefix rather than by excluding
Windows events, so a genuinely external Windows logon would still show. The first version of the time heat map grouped by
rule description, which embeds IP addresses, so nearly every alert became its own row; it now groups by stable rule
categories, with the category split ordered before the time split. The first map version in heat-map mode rendered as a
blue haze: at world zoom the grid cells are very large, and about half the mapped events (619 of 1,245) were country-only
GeoIP results stacked on country centroids. The US centroid in Kansas alone held 173 and set the color scale, so every real
location looked faint. A finer grid made the points disappear, so the panel now uses circle markers and plots city-level
locations only.

## 8. Suricata on the map: GeoIP enrichment

Wazuh's indexer ingest pipeline (`filebeat-7.10.2-wazuh-alerts-pipeline`) geolocates `srcip` and a few cloud-service
fields, but Suricata puts the attacker in `data.src_ip`, so none of its alerts had a location. The helper
`Scripts - Monitoring & Audit/wazuh-suricata-geoip.py` (copied to `/root/wz_geo.py` in CT 100; it talks to the indexer with
The admin client certificate, so no password is involved) added a sixth GeoIP processor for `data.src_ip`, writing the same
`GeoLocation` fields and running only when an alert has no location yet. It was added to both the live pipeline and Filebeat's
on-disk `pipeline.json` (so a pipeline reload keeps it), with backups of both. A simulation mapped DShield source
195.182.16.23 to France and left the internal 192.168.30.58 without a location. A one-off lookup-only pipeline then
backfilled the existing alerts: 17,749 updated in 5 seconds with no failures, of which 8,161 now have a location (the rest
have internal sources). Because Suricata logs its block-list hits at Wazuh level 3, the map filter includes Suricata severity
1-2 explicitly, which keeps block lists and exploit signatures and leaves out severity-3 informational noise such as STUN.
Over the last 7 days that gives 1,245 mapped threat events, led by DShield (319), the Spamhaus DROP lists (130+) and CINS
(39); top countries are the US (473), Bulgaria (83), South Africa (79), the Netherlands (70) and France (67).

## 9. Changes, backups and rollback

| System | Change | Backup / rollback |
|---|---|---|
| siem `ossec.conf` | syslog listener (added by the admin), Zeus rule/decoder exclusions | `/root/ossec.conf.pre-zeus-exclude` (CT 100) |
| siem decoders/rules | `mikrotik_npm_decoders.xml`, `mikrotik_npm_rules.xml` | delete both files, restart wazuh-manager |
| siem shared agent.conf | pibox NPM `localfile` block | `/root/agent.conf.pre-npm` (CT 100) |
| siem ingest pipeline | Suricata `data.src_ip` GeoIP processor (live + disk) | `/root/pipeline-live-pre-suricata-geo-20261120-171200.json`; `pipeline.json.pre-suricata-geo-20261120-171200` |
| Wazuh dashboard | 4 visualizations, 1 dashboard, `visualization:heatmap:maxBuckets` = 250 | delete the `td-*` objects and `threat-detection-heatmap`; reset the setting |
| NPM `server_proxy.conf` | `real_ip_header CF-Connecting-IP;` | `server_proxy.conf.pre-realip` (same folder) |
| RB5009 | `remote` action -> 192.168.5.12:514 from 192.168.5.1; logging rules 5-9 | `/system logging remove` rules 5-9; reset the action |
| AG01/AG02/AG03 | `remote` action -> 192.168.5.12:514 from .4/.5/.6; logging rules 4-8 | same as above |
| AG01/AG02/AG03 | data-VLAN DHCP clients disabled | `/ip dhcp-client enable [find comment~"mgmt cleanup"]` |
| agent box (CT 107) | `MAILTO=""`, mail queue deleted, Postfix disabled | `crontab -u agent /root/agent.crontab.pre-mailto`; `systemctl enable --now postfix` |

Tonight's mikrotik-audit diff will show the logging and DHCP-client changes on all four MikroTik devices; that is expected.

## 10. Open items

- fw-edge: the 11-01 config backup has the Wazuh agent's log-collection `remote_commands` enabled, which lets the manager
  push root commands to the edge firewall. Turn it off (Services > Wazuh Agent) unless shared-config commands are used.
- DESKTOP-K49Q9G5's agent is still disconnected (it was queue-full on 11-01).
- Homepage's router logins (rule 100514, about every 8 minutes) may be worth silencing by source address if they clutter
  the alert list.
- Only rule-matched events are stored (`logall` is off). Switch port up/down and other unmatched messages are received
  and discarded; add rules for them, or enable archives with a short retention, if they should be searchable.
- After a Wazuh upgrade, re-run `python3 /root/wz_geo.py apply` (idempotent) if Suricata alerts stop appearing on the map.
- The restart logs a harmless "Could not set resource limit for file descriptors" error (unprivileged LXC); add
  `lxc.prlimit.nofile: 458752` to `/etc/pve/lxc/100.conf` to silence it.
- Still to build: the VLAN 25 zero-trust flow panel. Its data (rules 100501-100504) now exists.

## 11. Lessons worth keeping

The quickest way to find gaps in a SIEM is to ask which devices enforce policy but can't run an agent; here that was the
whole network fabric. Wazuh decoder behavior is easy to get wrong: only the first matching child decoder runs, built-in rules
can claim lines before custom root rules see them, and a generic built-in decoder (Zeus) can silently capture a log format
that merely looks similar. `wazuh-logtest` caught all three before go-live. Behind a CDN, a reverse proxy's logs are only
useful for detection once the real-IP header matches what the CDN actually sends. GeoIP enrichment is tied to specific field
names, so tools that use a different field (Suricata's `src_ip`) need their own pipeline step. On a map, country-only GeoIP
results pile up on country centroids and can distort the picture more than they inform it. Finally, a new data source paid
off immediately: the first alert stream it produced was a real misconfiguration on the agent box.

## Also completed today

The OSINT news digest (`Scripts - Monitoring & Audit/osint-digest-feeds.json`, deployed to
`/home/agent/agents/osint-digest/feeds.json`) gained Axios and WSJ alongside its existing Politico, NYT and NY Post feeds,
for 25 feeds in total. Axios's own feed is blocked by Cloudflare bot protection from the agent box (403 regardless of
User-Agent), so it comes through a Google News search feed limited to axios.com; WSJ uses the Dow Jones feeds for Politics
(center, US) and World (center, world). Both WSJ feeds and the Google News feed returned 200 from the box.
