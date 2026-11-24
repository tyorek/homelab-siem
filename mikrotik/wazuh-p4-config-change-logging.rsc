# P4 (2026-11-23): send RouterOS config/user change lines ("X added/changed/removed by user") to Wazuh.
# The existing Wazuh action is `remote` (192.168.5.12:514). system,info carries the change lines; account is excluded
# because the existing account rule already sends logins.
# Applied: RB5009 2026-11-23 23:17 CST (rule 14). AG02 00:40, AG03 00:41, AG01 00:41 CST 2026-11-24 (rule 10 on each,
# comment dated 2026-11-24; each switch's Wazuh action is also `remote` -> 192.168.5.12, src-address its mgmt99 IP).
# Verified: each add fired Wazuh 100536 (logging rule changed) from 192.168.99.5, .6 and .4 as user admin.
/system logging add topics=system,info,!account action=remote comment="P4: config and user changes to Wazuh (2026-11-23)"
# Test on the RB5009: add + remove a disabled address-list entry (list p4-test, 192.0.2.1) -> Wazuh 100532 then 100533.
# Rollback: /system logging remove [find comment~"^P4: config and user changes"]
