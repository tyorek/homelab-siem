# Syslog collector stand-up: raw log and flow store for local attacker-behavior detection

**Date:** 2026-11-21 · **Status:** P2 collector built 2026-11-23 (CT 112, see `syslog-collector-build-record-2026-11-23.md`); RB5009 lease and lockdown applied; P3 sources live 2026-11-23 (see build record, incl. the eve-syslog-is-alerts-only gap in 4.2, closed by the syslog-ng eve.json forwarder) · **Covers:** task board items P2 (rsyslog collector LXC) and
P3 (dual-send from the RB5009 and AG01-03), plus flow export from the RB5009 and DMZ visibility from fw-edge so allowed
connections are recorded, with the hand-off points for P4 and P7/P8 · **Source diagram:**
`Runbooks & Setup Guides/Local attacker-behavior detection plan.png` · **Builds on:**
`Runbooks & Setup Guides/wazuh-syslog-mikrotik-npm-rollout.md` (2026-11-20, the "Done today" column) · **RouterOS steps
checked against:** RB5009 export 2026-11-21 02:00 (RouterOS 7.23.5); fw-edge rules against the 2026-11-21 rules export,
other fw-edge settings against the 2026-11-01 config backup

## 1. Why a second syslog destination

The plan's premise is that statistics find the anomalies and the local LLM only explains them. Statistics need a complete
baseline, and Wazuh can't provide one: `logall` is off, so the manager keeps only lines that match a rule and silently
discards the rest. Since 11-20 every MikroTik device sends to Wazuh, but switch port flaps, DHCP leases, CAPsMAN
associations, `system,info` config-change messages and every firewall line that doesn't hit rules 100500-100514 are
received and thrown away. Those unmatched lines are exactly what the anomaly engine's detectors are built on: a first-seen
MAC or DHCP client, a login at an unusual hour, a device that suddenly logs ten times its normal volume. The collector is a
plain rsyslog LXC on VLAN 99 that keeps every line, unfiltered and per device, for 30 days. The devices send to it in
parallel with Wazuh (dual-send) rather than through Wazuh or the other way round, so neither path depends on the other:
if the collector dies Wazuh alerting is untouched, and if the manager is restarting or being upgraded the raw record has
no gap.

Syslog only shows what a firewall rule was told to log, which on both firewalls is almost entirely drops. Allowed
connections, including a host calling home on a timer or a compromised DMZ server reaching out, are otherwise never
recorded anywhere. So the collector also receives connection flow records from both routing points: the RB5009 for the
internal VLANs (section 4.1) and fw-edge for the DMZ (section 4.2). The DMZ is the priority. It is the part of the
network the internet can reach, its servers have narrow and predictable behavior that makes anomalies stand out, and
today it is the least recorded part of the lab. The 30 days of raw logs and flows sit beside the indexer's alert history
and double as the forensic record when an alert needs context that Wazuh never stored.

## 2. Design at a glance

| Item | Decision |
|---|---|
| Host | New unprivileged LXC `syslog` on pve, Debian 13 standard template, 1 core, 512 MB RAM, no swap, 8 GB root |
| Address | 192.168.99.11/28, gateway 192.168.99.1 (proposed; confirm free first, see 3.1) |
| Log storage | Host directory `/srv/syslog` on pve, bind-mounted read-write at `/var/log/remote` in the collector and read-only at `/srv/syslog` in the agent box (CT 107) |
| Transport | UDP 514 for syslog, UDP 2055 for flows |
| Syslog layout | One directory and file per device: `rb5009/`, `ag01/`, `ag02/`, `ag03/`, `fw-edge/`, keyed on source IP, not hostname |
| Line format | Receive time (RFC 3339), source IP, facility.severity, then the device's message exactly as sent |
| Syslog sources | RB5009 from 192.168.99.1 and AG01/AG02/AG03 from .4/.5/.6, all severities except debug (P3); fw-edge from 172.16.255.1: filterlog, Suricata (alerts plus HTTP and TLS records) and audit |
| Flow sources | RB5009 IPFIX, ingress on the internal VLAN interfaces; fw-edge NetFlow v9 on the DMZ interface; both with a 1-minute active timeout |
| Flow layout | One `nfcapd` on UDP 2055 that splits by exporter into `flows/rb5009/` and `flows/fw-edge/`, 5-minute files in `YYYY/MM/DD/` folders |
| Retention | 30 days: logrotate for syslog, `nfexpire` for flows |
| Consumers | Anomaly engine on the agent box (P7) reads everything through the read-only mount |
| Health | Per-source freshness check pushing to Uptime Kuma; RouterOS heartbeat line every 10 minutes |

Several of these choices follow from how RouterOS sends syslog. Its default remote format is the topic list followed by the
message with no RFC 3164 timestamp or hostname (the `bsd-syslog` parameter doesn't exist on 7.23.5, which the 11-20 session
confirmed), so rsyslog's header parsing would invent a hostname and tag from the first words of the message. The collector
therefore names files by `fromhost-ip`, stamps lines with its own receive time, and stores `rawmsg-after-pri` verbatim so the
same text the Wazuh decoders already understand reaches the anomaly engine unchanged. OPNsense sends a proper header, and
storing it verbatim keeps that too. The bind mount, rather than a Proxmox managed volume, keeps the log directory
independent of the collector's lifecycle (destroying or rebuilding the CT doesn't take the logs with it) and lets the agent
box read it without any network path or credentials. Bind mounts are excluded from vzdump backups, which is acceptable for a
rolling 30-day raw store; back up the CT itself for its configuration.

Sizing is comfortable. Even a pessimistic million syslog lines a day at around 200 bytes is about 200 MB uncompressed, and
syslog compresses roughly ten to one. Suricata's HTTP and TLS records are the largest new syslog stream, but the DMZ's
traffic is dominated by a handful of servers, so it stays in the same range. Flow records add more: the household's hosts
open somewhere in the hundreds of thousands of connections a day, and the 1-minute active timeout adds a record per minute
for long-lived sessions, but at around 50-100 bytes per stored flow that's tens of MB a day. Altogether, 30 days should
stay within 10-15 GB. Check free space on the pve filesystem that holds `/srv` before starting (`df -h /srv`) and revisit
after the first week with `du -sh /srv/syslog/*`.

## 3. Build (P2)

### 3.1 Pick and reserve the address

The 11-01 cutover's incident I-13 came from a static address that DHCP was also handing out, so the address is reserved on
the router before the CT exists. The VLAN 99 pool is 192.168.99.2-.14; .1 router, .2 pve, .3 agent box, .4-.6 switches,
.7 Uptime Kuma, .8 Homepage, .9 `llm`, and .10 has been seen as a laptop lease. Confirm .11 is unused with
`/ip dhcp-server lease print where address~"192.168.99."` and `/ip arp print where address=192.168.99.11` in the winbox
terminal. After creating the CT in 3.2, bind the address to its MAC so DHCP can never give it away:

```
/ip dhcp-server lease add address=192.168.99.11 mac-address=<CT net0 MAC> server=dhcp7 comment="syslog collector CT"
```

With .11 taken, the /28 has three addresses left (.12-.14). That's worth keeping in mind for the next VLAN 99 service.

### 3.2 Host directory and container (pve shell)

```
CTID=$(pvesh get /cluster/nextid)
pct config 100 | grep rootfs        # storage the siem CT uses; use the same for the collector's root
pct config 107 | grep net0          # copy bridge and tag for VLAN 99 from the agent box
pveam update && pveam available --section system | grep debian-13
pveam download local <debian-13-standard template name>

mkdir -p /srv/syslog
chown 100000:100004 /srv/syslog     # root:adm as seen from inside an unprivileged CT
chmod 0750 /srv/syslog

pct create $CTID local:vztmpl/<debian-13-standard template name> \
  --hostname syslog --unprivileged 1 --cores 1 --memory 512 --swap 0 \
  --rootfs <storage>:8 \
  --net0 name=eth0,bridge=<as CT 107>,tag=99,ip=192.168.99.11/28,gw=192.168.99.1 \
  --nameserver "192.168.15.9 10.20.0.9" --searchdomain home.arpa \
  --mp0 /srv/syslog,mp=/var/log/remote \
  --onboot 1 --features nesting=1
pct config $CTID | grep -E "net0|mp0"    # note the MAC for the lease in 3.1
```

### 3.3 Install-time egress

The 2026-11-21 02:00 RB5009 export shows the RB5009 doesn't block VLAN 99 from the internet. `mgmtbridge99` is a member of
the LAN interface list, so `forward: lan to wan` accepts its traffic to the public handoff, and NAT happens on fw-edge.
That is also how pve, Uptime Kuma, Homepage and `llm` reach the internet today. The agent box is the only VLAN 99 host
with its own egress lockdown. A new CT at .11 can therefore run apt without a temporary RB5009 rule. Check first with
`curl -sI https://deb.debian.org | head -n 1` from inside the CT. If that fails, fw-edge's TRANSIT rules are what's
blocking it; add a temporary pass there for 192.168.99.11 to 80/443 and remove it after 3.4.

The collector shouldn't keep that access. Its egress lockdown in 3.8 is what takes it away, so apply 3.8 straight after the
packages (and the optional Wazuh agent) are installed.

### 3.4 Packages and time zone (inside the CT)

```
pct start $CTID && pct enter $CTID
apt update && apt -y full-upgrade
apt -y install rsyslog logrotate nftables curl nfdump
timedatectl set-timezone America/Chicago
```

The CT inherits the host's clock. Receive timestamps carry their UTC offset, so the time-of-day detector can work in local
time without guessing.

### 3.5 rsyslog configuration

`/etc/rsyslog.d/10-remote.conf`:

```
global(net.enableDNS="off")

module(load="imudp")
input(type="imudp" port="514" ruleset="remote")

template(name="RemoteFile" type="string" string="/var/log/remote/%$.dev%/%$.dev%.log")
template(name="RemoteLine" type="string"
         string="%timegenerated:::date-rfc3339% %fromhost-ip% %pri-text% %rawmsg-after-pri%\n")

ruleset(name="remote") {
  if $fromhost-ip == "192.168.99.1" then { set $.dev = "rb5009"; }
  else if $fromhost-ip == "192.168.99.4" then { set $.dev = "ag01"; }
  else if $fromhost-ip == "192.168.99.5" then { set $.dev = "ag02"; }
  else if $fromhost-ip == "192.168.99.6" then { set $.dev = "ag03"; }
  else if $fromhost-ip == "172.16.255.1" then { set $.dev = "fw-edge"; }
  else { set $.dev = "_unknown"; }
  action(type="omfile" dynaFile="RemoteFile" template="RemoteLine"
         fileCreateMode="0640" dirCreateMode="0750" fileGroup="adm" dirGroup="adm")
  stop
}
```

Binding the UDP input to its own ruleset keeps remote lines out of the collector's own `/var/log/syslog`, and the local
system logs stay out of `/var/log/remote`. The `_unknown` branch should stay empty because the firewall in 3.6 admits only
the five sources; if a file ever appears there, a device is sending from an unexpected source address. Validate and load
with `rsyslogd -N1 && systemctl restart rsyslog`, then `ss -ulpn | grep 514`.

### 3.5a Flow collector (nfcapd)

One `nfcapd` listens on UDP 2055 and writes each exporter's flows into its own directory, a new binary file every five
minutes in per-day folders. The directories are setgid and group adm so the agent box can read them through the same
read-only mount. If the package installed and started its own `nfdump` service, run `systemctl disable --now nfdump`
first. Check `nfcapd -h` for flag spelling on the installed version (the `-n ident,IP,directory` form for multiple
exporters is supported in both 1.6 and 1.7; 1.7 uses `-w` where 1.6 used `-l` for the single-directory form).

```
install -d -m 2750 -o root -g adm /var/log/remote/flows /var/log/remote/flows/rb5009 /var/log/remote/flows/fw-edge
```

`/etc/systemd/system/nfcapd-collector.service`:

```
[Unit]
Description=nfcapd flow collector (RB5009 IPFIX, fw-edge NetFlow v9)
After=network-online.target
Wants=network-online.target

[Service]
Group=adm
UMask=0027
ExecStart=/usr/bin/nfcapd -S 1 -t 300 -p 2055 -b 192.168.99.11 \
  -n rb5009,192.168.99.1,/var/log/remote/flows/rb5009 \
  -n fw-edge,172.16.255.1,/var/log/remote/flows/fw-edge
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

`systemctl daemon-reload && systemctl enable --now nfcapd-collector`, then `ss -ulpn | grep 2055`.

### 3.6 Host firewall (inside the CT)

`/etc/nftables.conf`:

```
#!/usr/sbin/nft -f
flush ruleset
table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    iif lo accept
    ct state established,related accept
    ip saddr { 192.168.99.1, 192.168.99.4, 192.168.99.5, 192.168.99.6, 172.16.255.1 } udp dport 514 accept
    ip saddr { 192.168.99.1, 172.16.255.1 } udp dport 2055 accept
    ip saddr { 192.168.5.9, 192.168.99.2 } tcp dport 22 accept
    icmp type echo-request accept
  }
}
```

`systemctl enable --now nftables`. If nftables refuses to load in the unprivileged CT, put the same allow list on the CT's
NIC with the Proxmox firewall instead. UDP syslog is spoofable, so the allow list limits who can write but doesn't prove
who wrote; that's an accepted limitation for a management-VLAN collector.

### 3.7 Retention

`/etc/logrotate.d/remote`:

```
/var/log/remote/*/*.log {
  daily
  rotate 30
  maxage 30
  dateext
  compress
  delaycompress
  missingok
  notifempty
  create 0640 root adm
  sharedscripts
  postrotate
    /usr/lib/rsyslog/rsyslog-rotate
  endscript
}
```

Dry-run with `logrotate -d /etc/logrotate.d/remote`. `delaycompress` leaves yesterday's file plain, which makes the
anomaly engine's daily pass simpler. The glob doesn't match nfcapd's files, so flow retention is handled separately by
`nfexpire` in `/etc/cron.d/nfexpire`:

```
17 0 * * * root /usr/bin/nfexpire -e /var/log/remote/flows/rb5009 -t 30d
19 0 * * * root /usr/bin/nfexpire -e /var/log/remote/flows/fw-edge -t 30d
```

### 3.8 Router lockdown for the collector (RB5009)

Without these rules, the collector could start connections to every VLAN, through "forward: mgmt vlan99 to all vlans
(excl. agent LXC)", and to the internet, through "forward: lan to wan". It only needs DNS and, if it gets a Wazuh agent,
the manager, so give it the same treatment as the agent box. Adding each rule with `place-before` the mgmt rule keeps them
in the order written, directly above it:

```
/ip firewall address-list add list=syslog-collector address=192.168.99.11 comment="rsyslog collector CT"
/ip firewall filter
add chain=forward action=accept src-address-list=syslog-collector dst-address-list=dns-auth protocol=udp dst-port=53 comment="syslog: DNS udp" place-before=[find comment="forward: mgmt vlan99 to all vlans (excl. agent LXC)"]
add chain=forward action=accept src-address-list=syslog-collector dst-address-list=dns-auth protocol=tcp dst-port=53 comment="syslog: DNS tcp" place-before=[find comment="forward: mgmt vlan99 to all vlans (excl. agent LXC)"]
add chain=forward action=accept src-address-list=syslog-collector dst-address=192.168.5.12 protocol=tcp dst-port=1514,1515 comment="syslog: Wazuh agent" place-before=[find comment="forward: mgmt vlan99 to all vlans (excl. agent LXC)"]
add chain=forward action=drop   src-address-list=syslog-collector log=yes log-prefix=SYSLOG-DROP comment="syslog: drop all other egress" place-before=[find comment="forward: mgmt vlan99 to all vlans (excl. agent LXC)"]
```

Re-check the result with a plain `/ip firewall filter print`, as the 10-01 notes recommend: the four `syslog:` rules
should sit directly above the mgmt rule. The drop is logged with its own prefix, the same as `AGENT-DROP`, because the
collector should never start a connection. If it does, that line in the RB5009's own log is worth an alert. Traffic from
the switches and the router itself to .11 stays on the same subnet and never reaches the forward chain, so these rules
don't affect their log delivery. fw-edge's traffic does cross the forward chain and gets its own inbound rule in 4.2.
Enrolling the collector as a Wazuh agent (agent 16) is optional but cheap: it puts the collector's own SSH and package
activity in the SIEM. Install it before applying these rules.

### 3.9 Read-only mount into the agent box

Confirm CT 107 is unprivileged (`pct config 107 | grep unprivileged`); with both CTs unprivileged on the default ID map,
root:adm inside one is root:adm inside the other. Pick the next free `mpN` on CT 107 and restart it between agent runs:

```
pct set 107 --mp<N> /srv/syslog,mp=/srv/syslog,ro=1
pct reboot 107
pct exec 107 -- usermod -aG adm agent
pct exec 107 -- sudo -u agent ls /srv/syslog
```

If CT 107 turns out to be privileged, the ID maps differ and the agent can't read the files. In that case fall back to an
SSH pull (rsync over the same VLAN, key restricted to a read-only command) instead of the mount. The engine reads flow files
with nfdump, so install the nfdump package on the agent box too.

## 4. Sources

### 4.0 Dual-send from the MikroTik fabric (P3)

Each device gets a second remote action named `collector`. The existing `remote` action and its rules are left exactly as
they are, so the Wazuh feed doesn't change. The collector rules use the four severity topics, which don't overlap (a message
has exactly one of info, warning, error or critical), so nothing is sent twice. Firewall lines are `firewall,info` and are
covered by `info`, and debug is left out.

RB5009 (winbox terminal). The source is the router's own VLAN 99 address, which is directly connected, so no forward rule
is involved:

```
/system logging action add name=collector target=remote remote=192.168.99.11 remote-port=514 remote-protocol=udp src-address=192.168.99.1
/system logging add topics=info     action=collector
/system logging add topics=warning  action=collector
/system logging add topics=error    action=collector
/system logging add topics=critical action=collector
```

AG01, AG02 and AG03: the same five lines with `src-address=192.168.99.4`, `.5` and `.6`. Their only L3 address is VLAN 99
since the 11-20 cleanup, so the collector is on-link.

Add a heartbeat on all four devices so a quiet switch can be told apart from a dead feed:

```
/system scheduler add name=syslog-heartbeat interval=10m on-event=":log info \"syslog-heartbeat\""
```

The heartbeat is `script,info`, so it reaches the collector but not Wazuh (the `remote` action carries no info topic).
Tonight's mikrotik-audit diff will show the new action, the four logging rules and the scheduler on every device, plus
the traffic-flow settings and the fw-edge forward rule on the RB5009, and the nightly fw-edge config push will show the
section 4.2 changes. That's all expected and is worth mentioning in the digest so it isn't triaged as drift.

### 4.1 Internal VLANs: traffic-flow export (RB5009)

As configured today, the RB5009's syslog only shows connections that a firewall rule logs, and those are almost all drops.
Allowed connections (every outbound session, every inter-VLAN connection the rules accept) leave no record, so a
compromised host beaconing out on a timer would be invisible. To fix that, the RB5009 exports every connection as an IPFIX
flow record to the collector.

The other way to do it would be `log=yes` on the accept rules. That was rejected for three reasons. Every new connection
would land in the `firewall` topic, which the existing `remote` action sends to Wazuh. The same flood would flush the
2,000-line `fwmemory` buffer within minutes, losing the local drop history. And a log line has no byte or packet counts,
which are half of what beaconing detection relies on. Flow export uses its own port and leaves syslog and Wazuh untouched.
It covers IPv4 and IPv6 (IPFIX, unlike NetFlow v5) and still sees fasttracked connections, a FastTrack restriction that
MikroTik removed in RouterOS 6.33.

Export is enabled on the internal L3 interfaces, so each record is taken as traffic enters the router. That means the
internal host's own address, before src-NAT to the public handoff, which is what the detectors need. It also captures
inter-VLAN connections and the internal side of connections into the DMZ. In the 2026-11-21 export, bridge5, bridge15,
bridge20, bridge25, bridge30 and mgmtbridge99 are the interfaces with addresses, and traffic-flow isn't configured yet.
bridge10 is left out on purpose: it now has no IPv4 address and its IPv6 addresses are disabled. It's a layer-2 bridge
that carries the DMZ segment between the RB5009's ports and fw-edge (over `vlan10-edge` on ether1). Routed DMZ traffic
never enters the RB5009 there.

```
/ip traffic-flow set enabled=yes interfaces=bridge5,bridge15,bridge20,bridge25,bridge30,mgmtbridge99 \
  active-flow-timeout=1m inactive-flow-timeout=15s
/ip traffic-flow target add dst-address=192.168.99.11 port=2055 version=ipfix src-address=192.168.99.1
```

The default active timeout is 30 minutes, which would make a long-lived C2 session one record per half hour. One minute
gives the engine a steady sample of long connections, at the cost of more records. The export from the router's own
address to .11 is on-link and doesn't touch the forward chain. After enabling it, watch `/system resource print` and the
traffic-flow cache in `/ip traffic-flow print` for a day; if the cache fills, raise `cache-entries`.

### 4.2 DMZ: fw-edge flows, Suricata metadata and logs

The DMZ hosts (pibox with NPM at 10.20.0.2, caddy at 10.20.0.7, buauth at 10.20.0.9, and the bunode LXCs on pibox) are the
part of the defensive footprint the internet touches directly. Since the 11-01 cutover, everything they exchange with the
internet or the internal VLANs passes through fw-edge. The RB5009 only sees the internal half of connections that internal
hosts open toward the DMZ; it never sees DMZ-to-internet traffic or inbound internet connections to NPM. fw-edge records
very little of that traffic:
- **NetFlow:** off (11-01 config backup).
- **Suricata eve HTTP and TLS logging:** off, so Wazuh gets Suricata alerts but no metadata (11-01 config backup).
- **Remote syslog:** no destination configured (11-01 config backup).
- **Rule logging:** in the 2026-11-21 rules export, five enabled rules log, all of them IPv4 blocks: 1060 (DMZ to
  private ranges), 1065 (DMZ to the firewall), 2025 (IoT to DMZ), 2040 (transit into the DMZ) and 2050 (management from
  transit). None of the IPv6 blocks log (1061, 1066, 2041, 2042, 2051), and no pass rule logs.

So allowed DMZ connections, in either direction, leave no record anywhere, and neither do blocked IPv6 attempts. Re-check
the first three settings in the GUI before changing them, because the backup predates the 11-03 to 11-07 Suricata tuning.
Take a config backup first (System > Configuration > Backups); the nightly config push to the agent box keeps a copy as
well.

**Flows (Reporting > NetFlow).** Listening interfaces: DMZ only. WAN interfaces (egress-only): leave empty. Version: v9
(it carries IPv6; v5 doesn't). Destination: 192.168.99.11 port 2055. Active timeout 60 (from the default 1800), inactive
timeout 15. Leave local capture (Insight) off unless you want its graphs, since it writes to fw-edge's own disk. Capturing
on the DMZ interface alone records every connection a DMZ host has, inbound or outbound, internet or internal, once, with
the DMZ host's real address on one side. For inbound traffic to the 12 Cloudflare-proxied hosts the remote side is a
Cloudflare edge (NPM's access logs in Wazuh hold the real client), but anything hitting the bare public IP or a
non-proxied port shows its true source. Suricata runs inline on vtnet2, the DMZ VLAN's parent, so after enabling NetFlow
confirm both that DMZ flows arrive (section 5) and that Suricata is still inspecting and alerting. If the two don't
coexist, fall back to pass logging on every DMZ rule, not just the ones below.

**Suricata metadata (Services > Intrusion Detection > Administration).** Enable eve HTTP logging (extended) and TLS logging
(extended), and turn on eve syslog output so the records reach the remote target below. Leave "dump all headers" off: the
NPM-to-Nextcloud path uses basic auth over HTTP, and Suricata sees that path on the trunk, so full header dumps would
write credentials to disk. Suricata watches the whole vtnet2 trunk (DMZ and public handoff). Its TLS records give the
server name (SNI) for every TLS session a DMZ host opens and every TLS session into NPM, which is the domain name that
flow records lack. HTTP records give host, URL, method, status and user agent for plaintext traffic. DMZ hosts resolve
through buauth, which forwards upstream over DoT, so their DNS lookups aren't visible on the wire. Buauth's Technitium
query log is the source for those and is the natural next feed. The OPNsense Wazuh agent already ships `eve.json`, so the
new record types will reach the manager too. Wazuh's built-in Suricata rules should match non-alert eve types at level 0,
which costs processing but stores nothing. Confirm with `wazuh-logtest` on a sample TLS record and watch the manager for a
day.

**Remote syslog (System > Settings > Logging > Remote).** Add a destination: transport UDP(4), hostname 192.168.99.11,
port 514, level info and above, applications `filterlog`, `suricata` and `audit`. The audit log carries GUI logins and
config changes on the edge firewall itself, which is the fw-edge half of P4 (T1562, T1098). fw-edge picks its source
address by route, so the packets leave from its TRANSIT address 172.16.255.1.

**Pass logging on DMZ-to-internal rules (Firewall > Rules > DMZ).** Turn on Log for every pass rule that lets the DMZ
reach internal hosts:

| Rules | From | To |
|---|---|---|
| 1030-1036 | NPM | Nextcloud 192.168.20.2:11000, Homepage 192.168.99.8:3000, digest viewer .8:8090, sup 192.168.99.3:8099, primenodetls Technitium 192.168.15.9:53443, Wazuh dashboard 192.168.5.12:443, search 192.168.20.14:4444 |
| 1040-1045 | caddy | primenodetls UI 192.168.15.9:5380, secnodetls and tertnodetls :9090, pve 192.168.99.2:8006, pibox 192.168.5.5:8080, RB5009 WebFig 192.168.5.1:80 |
| 1050 | DMZ resolvers | Wazuh manager (agent ports) |
| 1055 | buauth | domain controllers, DNS |

Volume is low, and each line names the rule that allowed the connection, which flows can't do. Every DMZ-to-internal
connection is a potential lateral-movement path (T1021), so these are the lines worth having verbatim. They also reach
Wazuh through the agent's filterlog collection. The built-in pfSense/OPNsense rules treat pass events at a low level, but
confirm that, the same as the eve records.

**Logging on the IPv6 blocks.** Turn on Log for 1061 (DMZ v6 to internal), 1066 (DMZ v6 to the firewall), 2041 and 2042
(transit v6 into the DMZ) and 2051 (management over v6), to match their IPv4 counterparts. As things stand, a DMZ host
probing internal addresses over IPv6, or an inbound IPv6 attempt into the DMZ, is blocked without a trace. Attackers try
IPv6 precisely because it is often less watched.

**RB5009: let fw-edge reach the collector.** fw-edge's syslog and flows arrive over the public handoff, so they cross the
RB5009's forward chain from the WAN side. Nothing in the current ruleset accepts them, so they would fall through to
`forward: drop all else` (DROP4). Put the new rule beside the existing "forward: fw-edge (OPNsense) wazuh agent to wazuh
manager" rule, which sits directly above "forward: isolate vlans":

```
/ip firewall filter add chain=forward action=accept src-address=172.16.255.1 dst-address=192.168.99.11 \
  protocol=udp dst-port=514,2055 comment="syslog: fw-edge to collector" \
  place-before=[find comment="forward: isolate vlans"]
```

This rule is inbound to the collector, so it doesn't interact with the collector's `syslog: drop all other egress` rule.
Traffic fw-edge originates itself is allowed out by OPNsense's default, and its static route for 192.168.0.0/16 via
172.16.255.2 already covers VLAN 99, so nothing else is needed on fw-edge.

## 5. Verification

On each MikroTik device, run `:log info "collector test <device>"`. On the collector,
`tail -n 3 /var/log/remote/<device>/<device>.log` should show the line with the right source IP and `user.info`-style
severity text, and `/var/log/remote/_unknown/` should not exist. On the siem, `wazuh-remoted` should still report the four
MikroTik sources as allowed with an unchanged discarded count, which proves the original feed is unaffected.

For fw-edge, `/var/log/remote/fw-edge/fw-edge.log` should fill with filterlog block lines within minutes. Load any site from
a phone on Wi-Fi through NPM and the log should gain a Suricata TLS record with the site's name and a filterlog pass line
for the NPM-to-backend connection. On fw-edge, Services > Intrusion Detection > Alerts should still be updating.

For flows, wait one five-minute interval, then on the collector:
- **RB5009:** `nfdump -R /var/log/remote/flows/rb5009 -c 20` should show internal source addresses (192.168.x, the home
  IPv6 prefix) and not the public handoff address. A browsing session from the desktop should appear as 192.168.5.9 flows
  to port 443.
- **fw-edge:** `nfdump -R /var/log/remote/flows/fw-edge -c 20` should show 10.20.0.x on one side of every flow. That
  includes NPM's outbound connections to its backends and inbound connections from Cloudflare addresses on 443.

From the agent box, `sudo -u agent tail -n 1 /srv/syslog/fw-edge/fw-edge.log` should return the newest line, and
`touch /srv/syslog/x` should fail with a read-only error. The next morning, confirm logrotate ran
(`ls /var/log/remote/rb5009/` shows a dated file) and that rsyslog reopened the new file.

For ongoing health, create a Push monitor in Uptime Kuma (192.168.99.7, same subnet, so no router rule is needed) and run
this from cron every 5 minutes on the collector as `/usr/local/bin/syslog-freshness`:

```
#!/bin/sh
KUMA="<push URL from the Kuma monitor>"
stale=""
for d in rb5009 ag01 ag02 ag03 fw-edge; do
  [ -n "$(find /var/log/remote/$d/$d.log -mmin -20 2>/dev/null)" ] || stale="$stale $d"
done
for f in rb5009 fw-edge; do
  [ -n "$(find /var/log/remote/flows/$f -type f -name 'nfcapd.2*' -mmin -11 2>/dev/null | head -n 1)" ] || stale="$stale flows-$f"
done
if [ -z "$stale" ]; then curl -fsS -m 10 "$KUMA?status=up&msg=OK" >/dev/null
else curl -fsS -m 10 "$KUMA?status=down&msg=stale:$(echo $stale | tr ' ' ',')" >/dev/null; fi
```

With the 10-minute heartbeat, a 20-minute threshold means any MikroTik device that stops logging pages Discord within
half an hour. fw-edge needs no heartbeat because internet background noise keeps filterlog busy around the clock. nfcapd
closes a file every five minutes even when traffic is light, so no new flow file for 11 minutes means the export or the
collector has stopped. A device that stops logging is also a detection in its own right: disabling logging is ATT&CK
T1562 (impair defenses), which is P4's territory.

## 6. What the anomaly engine gets, and the gaps to know about now

Once this is running, P7 reads one syslog file per device in a stable format
(`timestamp source-ip facility.severity message`) and one flow directory per exporter, read with
`nfdump -R /srv/syslog/flows/<exporter>/YYYY/MM/DD -o csv`.

### 6.1 DMZ

The DMZ is where this approach works best, because servers are predictable. Over the two-week burn-in (P10), each DMZ host's
set of peers settles into a short list. NPM talks to its backends, Let's Encrypt and Cloudflare, buauth to its DoT
upstreams, and caddy to its six backends. Against that baseline the detectors are high-fidelity:
- **First-seen outbound destination or port from a DMZ host:** a server that starts talking to somewhere new is rarely
  benign. It's the shape of command and control (T1071) or tool download (T1105). The TLS records supply the name.
- **New DMZ-to-internal connection** outside the allowed backend list, or any hit on "DMZ: block everything else to private
  ranges": lateral movement (T1021), or scanning (T1046) when one source fans out to many destinations.
- **Exploit then call-back:** an accepted inbound connection to a DMZ host followed within seconds by that host opening an
  outbound connection, to the same remote address or on an unusual port. That's the pattern of a reverse shell after a
  public-facing exploit (T1190 leading to T1059). Only flows from both directions in one place make this visible.
- **Bytes out per DMZ host** against its own baseline: exfiltration (T1041, T1048).
- **Beaconing** from DMZ hosts: regular intervals and consistent sizes, named via the TLS records.
- **First-seen inbound service:** inbound flows accepted to a DMZ port that has never accepted traffic before mean
  something new is exposed.

The 2026-11-21 RB5009 export points to the DMZ paths that deserve the highest severity, because they are where a
compromised DMZ host would go next:
- **Reverse proxies with broad internal reach.** NPM (10.20.0.2) and caddy (10.20.0.7) each have a "to all vlans" accept
  on the RB5009. This is deliberate: narrower rules were in place before and were widened because they kept breaking
  things on the network. That makes detection the compensating control for these two hosts, with fw-edge's DMZ rules
  (NPM to its seven backends, caddy to its six) as the remaining enforcement point. Any flow from either proxy to an
  internal destination outside its baseline should be a top-severity finding, and the fw-edge pass logs and block lines
  on those rules are the direct evidence. The burn-in also produces something useful in its own right: two weeks of
  flows show every internal destination and port each proxy actually uses. If narrowing is ever revisited, that list
  can be built from observed traffic rather than from what the rules were expected to need, which avoids the breakage
  last time.
- **caddy can reach the router.** On the RB5009, "Local proxy input" accepts every input-chain connection from
  10.20.0.7, and the `www` and `www-ssl` services list 10.20.0.7 as allowed. fw-edge narrows that to WebFig on
  192.168.5.1:80 (rule 1045, "caddy -> RB5009 webfig (map)"); anything else from caddy to RB5009 addresses, including
  `www-ssl` on 8443, hits block rule 1060. A compromised caddy could still reach the WebFig login. Any caddy flow to an
  RB5009 address other than 192.168.5.1:80, and any 1060 block line with caddy as the source, should alert.
- **pibox isolation: fixed 2026-11-21.** The gap described in the next item was closed the same day by
  `pibox-isolation.service`. Copies of the script and unit are in `MikroTik & Service Configs/pibox-isolation.sh` and
  `.service`, and the pre-change state is backed up in `/root/pre-isolation-20261121` on pibox. Its own nftables table
  (`inet pibox_isolation`) drops all forwarding to and from eth1 and drops NPM's ports 80/81/443 arriving on eth1. Two
  policy rules (139, 140) send new container connections out br1 via table 110, with DMZ peers kept on-link. NPM's
  VLAN 5 and VLAN 15 backends (the Wazuh dashboard, primenodetls) now go through fw-edge rules 1034 and 1035, as
  designed. Proxy-host status codes before and after matched, except primenodetls, which went from a timeout (dropped
  by the RB5009 on the old VLAN 5 path) to connection refused (Technitium isn't listening on 53443). Every drop is logged
  to the kernel log with a `pibox-iso` prefix, rate-limited, and pibox's Wazuh agent already ships journald, so a
  Wazuh rule on that prefix turns any isolation hit into an alert. The detector below stays, as a check that the host
  rules are still in force. The two dead RB5009 entries were removed the same day in winbox: the "npm: Homepage +
  digest viewer" filter rule and 192.168.5.5 in `supervisor-clients`. No RB5009 filter rule references 192.168.5.5
  now; its only address-list entry left is `agent-targets` (the agent box's NAS-health check), which is legitimate.
  Tonight's mikrotik-audit diff will show both removals.
- **pibox's VLAN 5 leg was open to its containers (verified live 2026-11-21, before the fix).** pibox has 10.20.0.2 on br1 (DMZ) and
  192.168.5.5 on eth1 (VLAN 5). The intent is that the two are isolated in iptables, but the live host doesn't enforce it:
  - **FORWARD policy:** ACCEPT, with `DOCKER-USER` empty and `ip_forward=1`.
  - **INPUT rules:** the only ones are OMV's five, all for the DMZ addresses (10.20.0.2 and 10.20.0.9); the IPv6 rule
    list is empty.
  - **Docker NAT:** masquerades each container network out any interface but its own bridge.
  - **Routing:** the main table sends 192.168.5.0/28, 192.168.15.9 and the two DCs (192.168.20.6 and .7) out eth1.
  - **The result:** a TCP connect from the NPM container to 192.168.5.12:443 succeeded over eth1, sourced as
    192.168.5.5. So for those destinations NPM's traffic never crosses fw-edge, and fw-edge rules 1034 (primenodetls) and
    1035 (Wazuh dashboard) don't govern it.
  - **What's reachable that way:** the whole VLAN 5 /28, including the admin desktop, the siem and the RB5009's own
    192.168.5.1, where "input: mgmt from vlan5" accepts winbox and SSH from any bridge5 source. On the RB5009, VLAN 5 is
    also covered by "forward: infra vlan20 in", which accepts any LAN source into VLAN 20.
  - **Published ports:** NPM publishes 80, 81 (its admin UI) and 443 on 0.0.0.0 and ::, so they answer on 192.168.5.5
    as well.

  The mangle rules and policy routes (connmark 0x110 on new br1 connections to table 110, and `from 192.168.5.0/28` to
  table 200) only keep replies symmetric; they don't isolate anything. Because pibox has no route to VLAN 99 over eth1,
  the two RB5009 entries that name 192.168.5.5 as an NPM source ("npm: Homepage + digest viewer" and the
  `supervisor-clients` entry "pibox NPM -> sup.example.com") are leftovers: that traffic goes out br1 through fw-edge
  rules 1031-1033. Until the host enforces the separation, the engine treats any flow from 192.168.5.5 to a destination
  outside pibox's storage role (SMB, NFS, iSCSI clients, the DCs for Kerberos) as DMZ traffic leaving by the side door.
  RB5009 traffic-flow on bridge5 records it. Traffic to the siem and the admin desktop stays on the VLAN 5 segment, never
  reaches the RB5009, and so needs the host fix rather than detection.
- **Open web egress from every DMZ host.** Rule 1080 lets any DMZ host reach any internet address on the web ports, so an
  implant on any DMZ server has a ready channel out over 443. The first-seen-destination detector, with names from the
  Suricata TLS records, is the control for this rule.

The explicit backend lists in fw-edge rules 1030-1055 can seed the engine's DMZ allow-list on day one, before the burn-in
finishes. Anything from a DMZ host outside those lists and the expected internet destinations is worth looking at from the
start.
- **The Wi-Fi AP's management is in the DMZ segment.** CAPsMAN runs on bridge10, and the cAP's ether4 port is untagged
  VLAN 10. So the cAP and the RB5009's CAPsMAN are layer-2 neighbors of every DMZ host. The neighbor discovery and
  MAC-server lists already exclude the DMZ, but CAPsMAN traffic from anything other than the cAP's MAC is worth a detector.

One DMZ blind spot remains. Traffic between DMZ hosts never crosses a firewall: it either stays inside pibox (pibox and
its bunode LXCs) or is bridged at layer 2 by bridge10 on the RB5009, for example caddy on pve to pibox off ether3. Bridged
traffic bypasses the RB5009's IP firewall and traffic-flow. Capturing it would need the bridge `use-ip-firewall`
setting, which is global across every bridge and not worth the risk to the fabric. Host-side data has to cover it. The
export has Wazuh agent rules for pibox, buauth, bunode1 and bunode2, but none for caddy, so confirm whether caddy runs an
agent at all. If intra-DMZ movement becomes a concern, the next step is connection auditing on pibox, which hosts most of
the DMZ's services.

### 6.2 Internal VLANs and the fabric

First-seen events are well covered. DHCP lease assignments, CAPsMAN associations and RouterOS logins all arrive at info
level, so a new MAC on any VLAN, a new client on VLAN 25, or a login from a never-seen address are straightforward. Unusual
counts work per device and per log-prefix (ISO25, ISO4, the agent-box drops), and the count z-score detector gets far more
signal here than from Wazuh because nothing is filtered. Time of day works for logins and config changes. Config and user
changes (P4) show up as `system,info` lines naming the user ("... changed by admin"), so the collector already has the raw
material for P4. The Wazuh side of P4 still needs a `system` topic added to each device's `remote` action plus a rule,
because today's Wazuh feed carries only account, critical, error, warning, firewall and (switches) interface.

Beaconing from internal hosts comes from the RB5009 flows: grouped by source, destination and port, a timer-driven implant
shows low jitter in the gaps between connections and consistent sizes, unlike a person's browsing. Internal flows give
addresses, not names, because Suricata only sees the fw-edge trunk. Joining them against the Technitium query logs on
primenodetls would supply the domain, and is worth adding when P8 is written, together with buauth's log for the DMZ.

## 7. Rollback

| System | Change | Rollback |
|---|---|---|
| RB5009, AG01-03 | `collector` action, four logging rules, heartbeat scheduler | `/system logging remove [find action=collector]`; `/system logging action remove [find name=collector]`; `/system scheduler remove [find name=syslog-heartbeat]` |
| RB5009 | traffic-flow export | `/ip traffic-flow target remove [find dst-address=192.168.99.11]`; `/ip traffic-flow set enabled=no` |
| RB5009 | `syslog:` filter rules (collector egress and fw-edge inbound), `syslog-collector` address list, DHCP lease | `/ip firewall filter remove [find comment~"^syslog:"]`; `/ip firewall address-list remove [find list=syslog-collector]`; `/ip dhcp-server lease remove [find comment="syslog collector CT"]` |
| fw-edge | NetFlow, eve HTTP/TLS and eve syslog, remote syslog destination, Log on DMZ pass rules | restore the pre-change config backup, or reverse each setting: NetFlow interfaces cleared, eve HTTP/TLS and eve syslog off, remote destination deleted, Log unticked |
| collector | nfcapd service, nfexpire cron | `systemctl disable --now nfcapd-collector`; remove `/etc/cron.d/nfexpire` |
| CT 107 | read-only `mpN`, agent in `adm` | `pct set 107 --delete mp<N>`; `gpasswd -d agent adm` |
| pve | collector CT, `/srv/syslog` | `pct destroy <id>`; remove `/srv/syslog` once the logs are no longer wanted |
| Uptime Kuma | push monitor | delete the monitor |

None of this touches the Wazuh manager, its rules or the existing `remote` actions. The fw-edge changes add record types and
pass lines to what the OPNsense agent already ships, which is why 4.2 asks for a `wazuh-logtest` check. Beyond that,
rolling back the collector can't affect alerting.

## 8. Where this leaves the board

With P2 and P3 done, plus flows and DMZ metadata, the "Now" column is down to P1 (check `_cat/plugins` on the indexer to see
whether its built-in anomaly detection is installed, which decides whether P7 is a custom engine or a thin layer over the
plugin) and P4 (Wazuh alerts on RouterOS and fw-edge config and user changes, T1562/T1098). Neither blocks the collector,
and the collector should start accumulating baseline as early as possible: P10's two-week learn-only burn-in can't start
until there are two weeks of raw history to learn from. When P8 is scoped, the DMZ detectors in 6.1 are the ones to build
first.

### 8.1 P1 result (2026-11-23): plugin present, used only for what's already indexed

`opensearch-plugin list` on the siem (CT 100) shows `opensearch-anomaly-detection` and `opensearch-job-scheduler` installed (alongside alerting, ml, knn and the rest of the standard Wazuh indexer set). By this section's original test that means "thin layer over the plugin". The plan is a split instead, because of where the plugin runs and what it can see:
- **Why not the plugin for everything:** it runs on the indexer and can only model indexed data, which is `wazuh-alerts-*` (rule matches only, `logall` off). The raw store P7 needs exists only on the collector: RB5009 and fw-edge flows, the Technitium query logs, Suricata eve HTTP/TLS records and unmatched RouterOS lines. Indexing it would mean about 300 MB/day for the query logs alone, plus flows and eve. That's the SIEM load the eve.json forwarder was built to avoid, and the plugin's random cut forest detectors would run on the same constrained indexer.
- **Plugin (on the indexer), for cheap detectors over existing alerts, with no new ingest:** alert counts per agent, per rule group and per hour, such as a jump in fw-edge Suricata alerts, a DMZ agent going quiet or spiking, or a burst of RouterOS login failures. Detectors can be created through `_plugins/_anomaly_detection/detectors` if the Wazuh dashboard doesn't show the Anomaly Detection pages. Check that before building UI-dependent steps.
- **Custom engine (P7, on the agent box), for everything on the raw store:** it reads `/srv/syslog` through the read-only mount (`nfdump` for flows, line-oriented reads for the logs) and runs the section 6 detectors: first-seen destination, exploit-then-callback, beaconing, bytes-out, the NPM/caddy reach checks, and the flow-to-DNS join against `queries.log`. It sends findings to Wazuh only as low-volume alerts, so the indexer stores results, not raw data.

P1 is closed. The "Now" column is down to P4. P10's two-week burn-in clock started on 2026-11-23, when the collector began receiving from all sources, so the earliest end of burn-in is 2026-12-07.

### 8.2 P7/P8/P9 built (2026-11-23): anomaly engine running, learn-only until 2026-12-07

The engine, its detectors and the Wazuh plumbing were all built and started on 2026-11-23. They didn't wait for P4, because only the baseline-dependent detectors need the burn-in. Everything runs learn-only until **2026-12-07 00:00 CST** and then switches to alerting by itself.
- **Engine:** `/home/agent/agents/anomaly-engine/` on the agent box (CT 107), Python stdlib, cron every 5 minutes (`3-58/5`).
- **Docs:** README and code copies in `Scripts - Monitoring & Audit/anomaly-engine/`. Detector, rule, level and ATT&CK table in the README.
- **Flows:** on the collector, `/usr/local/bin/flow-csv-export` (cron `1-59/5`) converts each closed nfcapd file to `/var/log/remote/flows-csv/<exporter>/YYYY/MM/DD/flows-*.csv.gz`. The agent box's nfdump 1.7.1 can't decode the IPFIX extensions written by the collector's 1.7.5, so the engine reads CSV only.
- **Wazuh (P9):** rules 100600-100619 in `/var/ossec/etc/rules/anomaly_engine_rules.xml` on the siem. Central `agent.conf` block for agent `claude_agents` tails `findings.jsonl`. The pipeline was tested end to end (rule 100619, level 7, 15:55:51Z).
- **What's live now:**
  - All detectors learn.
  - Rule-based ones write would-be findings to `learn.jsonl` on the agent box.
  - Nothing reaches Wazuh until the switch.
- **At the switch:** the engine writes `reports/burn-in-report-<date>.md` and raises one level-7 `engine_status` alert pointing at it. That is the "output after two weeks". From then on, findings alert through Wazuh, so they show up in wazuh-triage and the daily digest.
- **Already found on day one:** pibox's IPv6 DMZ addresses send CLDAP (UDP 389, AD DC locator) to IPv6 addresses on VLAN 20. fw-edge blocks it (IPv6 block, tracker 124; visible since its logging was enabled 2026-11-23). It's the same IPv6-first DC discovery as the earlier pibox SMB/Kerberos incidents, now leaving by the DMZ leg. Isolation holds, but winbind/Kerberos on pibox should be pinned to IPv4 for discovery too, or IPv6 turned off on br1 for those lookups.
- **Unrelated rule-order note from the export:** fw-edge rule 1062 (pibox host web out to private ranges on 80/443) sits after block 1060 for the same destinations, so it never matches.


### 8.3 DNS round robin and the resolver-share detector (2026-11-23)

VLANs 20/25/30 now split DNS per query between primenodetls and buauth on the RB5009. VLAN 5 stays on primenodetls, and devices in `dns-rr-pin` (currently G9) are pinned there too. `dns-rr-check` (every 30 s) handles failover. The engine learns primenodetls's share per hour of day during the burn-in. From 2026-12-07, a statistically unusual skew raises Wazuh rule 100620 and starts an automatic triage report in `reports/investigations/` on the agent box. Details, the two defects found while checking it (the v6 fallback gate and G9's internet block), and the rollback are in the build record and `MikroTik & Service Configs/syslog-collector-dns-round-robin.rsc`.

**Board now:** P1, P2, P3, P7, P8 and P9 are done, and P10 (burn-in) is running. Left: P4 (Wazuh alerts on config/user changes), P5/P6 (ATT&CK IDs on the older custom rules, Sigma), P11/P12 (Gemma triage plus Claude audit over findings after the switch), and P13 (dashboard).
