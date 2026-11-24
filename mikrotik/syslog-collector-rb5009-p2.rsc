# RB5009 - syslog collector CT 112 (P2 router pieces). APPLIED 2026-11-23 08:31 CST in winbox (rules landed at positions 21-24, above mgmt rule 25).
# Source: Runbooks & Setup Guides/rsyslog-collector-standup-runbook.md sections 3.1 and 3.8
# Built 2026-11-23. CT 112 "syslog", 192.168.99.11/28, net0 MAC 02:00:5E:6F:8E:6E
#
# Pre-check (server name dhcp7 and rule comments come from the 2026-11-21 export, confirm they still match):
#   /ip dhcp-server print where interface=mgmtbridge99
#   /ip dhcp-server lease print where address=192.168.99.11      (should be empty)
#   /ip firewall filter print where comment="forward: mgmt vlan99 to all vlans (excl. agent LXC)"

# 3.1 - pin .11 to the CT so DHCP can never hand it out (CT is static, address sits inside the .2-.14 pool)
/ip dhcp-server lease add address=192.168.99.11 mac-address=02:00:5E:6F:8E:6E server=dhcp7 comment="syslog collector CT"

# 3.8 - collector egress lockdown: DNS + Wazuh agent ports only, everything else dropped and logged
/ip firewall address-list add list=syslog-collector address=192.168.99.11 comment="rsyslog collector CT"
/ip firewall filter
add chain=forward action=accept src-address-list=syslog-collector dst-address-list=dns-auth protocol=udp dst-port=53 comment="syslog: DNS udp" place-before=[find comment="forward: mgmt vlan99 to all vlans (excl. agent LXC)"]
add chain=forward action=accept src-address-list=syslog-collector dst-address-list=dns-auth protocol=tcp dst-port=53 comment="syslog: DNS tcp" place-before=[find comment="forward: mgmt vlan99 to all vlans (excl. agent LXC)"]
add chain=forward action=accept src-address-list=syslog-collector dst-address=192.168.5.12 protocol=tcp dst-port=1514,1515 comment="syslog: Wazuh agent" place-before=[find comment="forward: mgmt vlan99 to all vlans (excl. agent LXC)"]
add chain=forward action=drop src-address-list=syslog-collector log=yes log-prefix=SYSLOG-DROP comment="syslog: drop all other egress" place-before=[find comment="forward: mgmt vlan99 to all vlans (excl. agent LXC)"]

# Verify: the four "syslog:" rules sit directly above the mgmt vlan99 rule
#   /ip firewall filter print
# IPv6: not needed - IPv6 is disabled inside CT 112 (sysctl), so it has no v6 egress to lock down.
#
# Rollback:
#   /ip firewall filter remove [find comment~"^syslog:"]
#   /ip firewall address-list remove [find list=syslog-collector]
#   /ip dhcp-server lease remove [find comment="syslog collector CT"]
