# Syslog collector: DNS server sources. APPLIED 2026-11-23 ~09:17 CST in winbox on RB5009 (rules landed at 64-65, above "forward: isolate vlans" at 66).
/ip firewall address-list add list=syslog-dns-vlan15 address=192.168.15.9 comment="primenodetls"
/ip firewall address-list add list=syslog-dns-vlan15 address=192.168.15.10 comment="secnodetls"
/ip firewall address-list add list=syslog-dns-vlan15 address=192.168.15.11 comment="tertnodetls"
/ip firewall address-list add list=syslog-dns-dmz address=10.20.0.9 comment="buauth"
/ip firewall address-list add list=syslog-dns-dmz address=10.20.0.13 comment="bunode1"
/ip firewall address-list add list=syslog-dns-dmz address=10.20.0.14 comment="bunode2"
/ip firewall filter add chain=forward action=accept protocol=udp dst-port=514 src-address-list=syslog-dns-vlan15 in-interface=bridge15 dst-address=192.168.99.11 comment="syslog: DNS servers (vlan15) to collector" place-before=[find comment="forward: isolate vlans"]
/ip firewall filter add chain=forward action=accept protocol=udp dst-port=514 src-address-list=syslog-dns-dmz in-interface=vlan100-public-handoff dst-address=192.168.99.11 comment="syslog: DMZ resolvers (via fw-edge) to collector" place-before=[find comment="forward: isolate vlans"]
# fw-edge (OPNsense) counterpart, added via API: rule 1051 on DMZ (opt2) in, pass UDP DMZ_RESOLVERS -> 192.168.99.11:514, log on,
# "DMZ resolvers -> syslog collector (CT 112)".
# Rollback: /ip firewall filter remove [find comment~"^syslog: (DNS servers|DMZ resolvers)"]; /ip firewall address-list remove [find list~"^syslog-dns-"]
