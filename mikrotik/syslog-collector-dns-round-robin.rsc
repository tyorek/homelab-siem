# RB5009 (RTR-HOMELAB-CN-1) - per-query DNS round robin, applied 2026-11-23 ~10:24 CST via winbox terminal
# RouterOS 7.23.5. Record of what was applied (not a blind re-run script; the add/place-before lines assume the
# existing "LAN DNS redirect primary" rules from the dns-fallback-check setup are present).
#
# Intent: VLAN 5 (192.168.5.0/28) keeps the existing primary/fallback redirect to primenodetls.
#         VLANs 20/25/30 (bridge20/25/30) split per query 50/50: nth=2,1 -> primenodetls, the rest -> buauth.
#         dns-rr-check (30s) probes both; buauth down -> all RR traffic to primenodetls; primenodetls down -> all to buauth.
#         Logs only when it changes a rule (or when both resolvers fail).
# Clients that already target a resolver directly (src/dst in address-list dns / dns6) are untouched.

# 1. Narrow the fallback-block filter gates to VLAN 5 only (they previously matched the whole LAN list)
/ip firewall filter set [find comment~"^DNS fallback block LAN v4"] !src-address-list src-address=192.168.5.0/28

# 2. Interface list for the round-robin scope (VLAN 99 mgmt deliberately excluded so probes/infra keep fixed resolvers)
/interface list add name=DNS-RR comment="DNS round-robin scope VLAN 20/25/30"
/interface list member add list=DNS-RR interface=bridge20
/interface list member add list=DNS-RR interface=bridge25
/interface list member add list=DNS-RR interface=bridge30

# 3. IPv4 dst-nat (placed before "LAN DNS redirect primary (udp)")
/ip firewall nat
add chain=dstnat action=dst-nat protocol=udp dst-port=53 in-interface-list=DNS-RR src-address-list=!dns nth=2,1 to-addresses=192.168.15.9 comment="RR DNS split primary v4 (udp)" place-before=[find comment="LAN DNS redirect primary (udp)"]
add chain=dstnat action=dst-nat protocol=tcp dst-port=53 in-interface-list=DNS-RR src-address-list=!dns nth=2,1 to-addresses=192.168.15.9 comment="RR DNS split primary v4 (tcp)" place-before=[find comment="LAN DNS redirect primary (udp)"]
add chain=dstnat action=dst-nat protocol=udp dst-port=53 in-interface-list=DNS-RR src-address-list=!dns to-addresses=10.20.0.9 comment="RR DNS split dmz v4 (udp)" place-before=[find comment="LAN DNS redirect primary (udp)"]
add chain=dstnat action=dst-nat protocol=tcp dst-port=53 in-interface-list=DNS-RR src-address-list=!dns to-addresses=10.20.0.9 comment="RR DNS split dmz v4 (tcp)" place-before=[find comment="LAN DNS redirect primary (udp)"]
add chain=dstnat action=dst-nat protocol=udp dst-port=53 in-interface-list=DNS-RR src-address-list=!dns to-addresses=192.168.15.9 disabled=yes comment="RR DNS failover primary v4 (udp)" place-before=[find comment="LAN DNS redirect primary (udp)"]
add chain=dstnat action=dst-nat protocol=tcp dst-port=53 in-interface-list=DNS-RR src-address-list=!dns to-addresses=192.168.15.9 disabled=yes comment="RR DNS failover primary v4 (tcp)" place-before=[find comment="LAN DNS redirect primary (udp)"]

# 4. IPv6 dst-nat (placed before "LAN DNS redirect primary v6 (udp)"); buauth ULA already in dns-auth6
/ipv6 firewall nat
add chain=dstnat action=dst-nat protocol=udp dst-port=53 in-interface-list=DNS-RR src-address-list=!dns6 nth=2,1 to-address=fd12:3456:789a:15:be24:11ff:fe6a:93b0/128 comment="RR DNS split primary v6 (udp)" place-before=[find comment="LAN DNS redirect primary v6 (udp)"]
add chain=dstnat action=dst-nat protocol=tcp dst-port=53 in-interface-list=DNS-RR src-address-list=!dns6 nth=2,1 to-address=fd12:3456:789a:15:be24:11ff:fe6a:93b0/128 comment="RR DNS split primary v6 (tcp)" place-before=[find comment="LAN DNS redirect primary v6 (udp)"]
add chain=dstnat action=dst-nat protocol=udp dst-port=53 in-interface-list=DNS-RR src-address-list=!dns6 to-address=fd12:3456:789a:10:216:3eff:fe0e:c59/128 comment="RR DNS split dmz v6 (udp)" place-before=[find comment="LAN DNS redirect primary v6 (udp)"]
add chain=dstnat action=dst-nat protocol=tcp dst-port=53 in-interface-list=DNS-RR src-address-list=!dns6 to-address=fd12:3456:789a:10:216:3eff:fe0e:c59/128 comment="RR DNS split dmz v6 (tcp)" place-before=[find comment="LAN DNS redirect primary v6 (udp)"]
add chain=dstnat action=dst-nat protocol=udp dst-port=53 in-interface-list=DNS-RR src-address-list=!dns6 to-address=fd12:3456:789a:15:be24:11ff:fe6a:93b0/128 disabled=yes comment="RR DNS failover primary v6 (udp)" place-before=[find comment="LAN DNS redirect primary v6 (udp)"]
add chain=dstnat action=dst-nat protocol=tcp dst-port=53 in-interface-list=DNS-RR src-address-list=!dns6 to-address=fd12:3456:789a:15:be24:11ff:fe6a:93b0/128 disabled=yes comment="RR DNS failover primary v6 (tcp)" place-before=[find comment="LAN DNS redirect primary v6 (udp)"]

# 5. Health/failover script + scheduler (v2 10:28: change-flag logging; v1 used a :global that the scheduler
#    context never matched, so it logged every 30s)
/system script add name=dns-rr-check policy=read,write,test comment="DNS round-robin failover for VLAN 20/25/30 (2026-11-23)" source=":local p false; :local d false; :do {:resolve \"example.com\" server=192.168.15.9; :set p true} on-error={}; :do {:resolve \"example.com\" server=10.20.0.9; :set d true} on-error={}; :local wPri true; :local wDmz true; :local wFb false; :if (\$p && !\$d) do={:set wDmz false; :set wFb true}; :if (!\$p && \$d) do={:set wPri false}; :local ch false; :foreach i in=[/ip firewall nat find where comment~\"^RR DNS split primary\"] do={:if ([/ip firewall nat get \$i disabled] = \$wPri) do={/ip firewall nat set \$i disabled=(!\$wPri); :set ch true}}; :foreach i in=[/ip firewall nat find where comment~\"^RR DNS split dmz\"] do={:if ([/ip firewall nat get \$i disabled] = \$wDmz) do={/ip firewall nat set \$i disabled=(!\$wDmz); :set ch true}}; :foreach i in=[/ip firewall nat find where comment~\"^RR DNS failover primary\"] do={:if ([/ip firewall nat get \$i disabled] = \$wFb) do={/ip firewall nat set \$i disabled=(!\$wFb); :set ch true}}; :foreach i in=[/ipv6 firewall nat find where comment~\"^RR DNS split primary\"] do={:if ([/ipv6 firewall nat get \$i disabled] = \$wPri) do={/ipv6 firewall nat set \$i disabled=(!\$wPri); :set ch true}}; :foreach i in=[/ipv6 firewall nat find where comment~\"^RR DNS split dmz\"] do={:if ([/ipv6 firewall nat get \$i disabled] = \$wDmz) do={/ipv6 firewall nat set \$i disabled=(!\$wDmz); :set ch true}}; :foreach i in=[/ipv6 firewall nat find where comment~\"^RR DNS failover primary\"] do={:if ([/ipv6 firewall nat get \$i disabled] = \$wFb) do={/ipv6 firewall nat set \$i disabled=(!\$wFb); :set ch true}}; :if (\$ch || (!\$p && !\$d)) do={:log warning (\"dns-rr-check: primenodetls ok=\" . \$p . \" buauth ok=\" . \$d . \" changed=\" . \$ch)}"
/system scheduler add name=dns-rr-check interval=30s start-time=startup on-event=dns-rr-check policy=read,write,test comment="DNS round-robin failover (2026-11-23)"

# 5b. Fixes applied 10:44 after checking per-resolver query logs (the NAT counters were 50/50 but buauth only got ~5%):
#   a) The IPv6 fallback gates were never narrowed in step 1, so every v6 query the split sent to buauth was dropped in
#      forward by "DNS fallback block LAN v6 udp/tcp" (822 drops); clients then retried and landed on primenodetls.
/ipv6 firewall filter set [find comment~"^DNS fallback block LAN v6"] !in-interface-list in-interface=bridge5
#      (was in-interface-list=!DMZ, i.e. every non-DMZ interface)
#   b) G9 (192.168.25.5) has "G9 block internet" (forward drop, out-interface-list=WAN). fw-edge's handoff
#      vlan100-public-handoff is in the WAN list, so its half of the split to buauth was dropped. Pinned to primenodetls:
/ip firewall address-list add list=dns-rr-pin address=192.168.25.5 comment="G9 (internet-blocked, cannot reach buauth via fw-edge) pinned to primenodetls"
/ip firewall nat add chain=dstnat action=dst-nat protocol=udp dst-port=53 src-address-list=dns-rr-pin to-addresses=192.168.15.9 comment="RR DNS pin primary v4 (udp)" place-before=[find comment="RR DNS split primary v4 (udp)"]
/ip firewall nat add chain=dstnat action=dst-nat protocol=tcp dst-port=53 src-address-list=dns-rr-pin to-addresses=192.168.15.9 comment="RR DNS pin primary v4 (tcp)" place-before=[find comment="RR DNS split primary v4 (udp)"]
#      Any other device that gets an internet-block rule later needs the same entry in dns-rr-pin.

# 6. Flushed existing :53 conntrack entries so clients picked up the new mapping (0 present at the time)
# /ip firewall connection remove [find where dst-address~":53\$"]

# Verification 10:26: v4 split primary 56 pkts / dmz 54; v6 primary 30 / dmz 28. Self-heal test 10:28:43 (disabled
# dmz v4 udp by hand, script re-enabled it, logged changed=true).

# ---------------- ROLLBACK ----------------
# /system scheduler remove [find name=dns-rr-check]
# /system script remove [find name=dns-rr-check]
# /ip firewall nat remove [find comment~"^RR DNS "]   (also removes the two pin rules)
# /ip firewall address-list remove [find list=dns-rr-pin]
# /ipv6 firewall filter set [find comment~"^DNS fallback block LAN v6"] !in-interface in-interface-list=!DMZ
# /ipv6 firewall nat remove [find comment~"^RR DNS "]
# /interface list member remove [find list=DNS-RR]
# /interface list remove [find name=DNS-RR]
# Restore the pre-change gates (LAN-wide fallback block) if you want the old single-resolver behaviour back:
# /ip firewall filter set [find comment~"^DNS fallback block LAN v4"] src-address="" src-address-list=LAN
#   (check the saved mikrotik-audit export from before 2026-11-23 10:24 for the exact original matcher)

# ---------------- 2026-11-23 11:01: read-only agent SSH from the anomaly-engine box (CT 107, 192.168.99.14) ----------------
# investigate_dns_share.py pulls NAT/scheduler state over the agent-ro login; .14 was outside both the user restriction
# and the input allow (which only covered .3). Group agent-ro (no write/policy/sensitive) is unchanged.
/user set [find name=agent] address=192.168.99.3/32,192.168.99.14/32
/ip firewall filter add chain=input action=accept protocol=tcp src-address=192.168.99.14 dst-address=192.168.99.1 dst-port=22 comment="agent: input RouterOS SSH from anomaly-engine box CT107 (read-only, 2026-11-23)" place-before=<rule after "agent: input RouterOS mgmt (read-only audit)">
# REVERTED 2026-11-24 04:25: CT 107 is back on its original fixed address 192.168.99.3 (it had come up on .14 via
# DHCP), so the two lines above were undone:
#   /user set [find name=agent] address=192.168.99.3/32
#   /ip firewall filter remove [rule with src-address=192.168.99.14, comment "agent: input RouterOS SSH from anomaly-engine box CT107"]
# Plus a static dhcp7 reservation for CT 107's MAC at 192.168.99.3 (comment "agents CT 107 ... static .3 since 2026-11-24").
# Verified 11:02: router_state() from CT 107 returned the NAT prints.
# Rollback:
# /ip firewall filter remove [find comment~"^agent: input RouterOS SSH from anomaly-engine box"]
# /user set [find name=agent] address=192.168.99.3/32
