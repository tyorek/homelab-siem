# Wazuh Indexer read-only user for the Claude agent

Greenfield -- no indexer-side API access exists yet. Run these from the Wazuh
indexer host itself (so `localhost:9200` just works regardless of what TLS
cert it's using), as a user who has the indexer's admin password.

## 1. Create a read-only role scoped to alert indices only

```bash
curl -k -u admin:<ADMIN_PASSWORD> -X PUT "https://localhost:9200/_plugins/_security/api/roles/wazuh_claude_readonly" \
  -H 'Content-Type: application/json' -d '{
    "cluster_permissions": ["cluster_composite_ops_ro"],
    "index_permissions": [{
      "index_patterns": ["wazuh-alerts-*"],
      "allowed_actions": ["read", "indices:admin/mappings/get"]
    }]
  }'
```

## 2. Create the internal user

Pick a strong password yourself -- don't hand it to me, just drop it straight
into `/home/agent/.config/agent.env` on the agent LXC in step 4.

```bash
curl -k -u admin:<ADMIN_PASSWORD> -X PUT "https://localhost:9200/_plugins/_security/api/internalusers/claude-agent" \
  -H 'Content-Type: application/json' -d '{
    "password": "<CHOOSE_A_STRONG_PASSWORD>",
    "backend_roles": [],
    "description": "Read-only agent for Claude wazuh-triage"
  }'
```

(OpenSearch enforces a password-strength policy by default -- if this is
rejected, it'll say why; typically needs 8+ chars with upper/lower/digit/symbol.)

## 3. Map the user to the role

```bash
curl -k -u admin:<ADMIN_PASSWORD> -X PUT "https://localhost:9200/_plugins/_security/api/rolesmapping/wazuh_claude_readonly" \
  -H 'Content-Type: application/json' -d '{
    "users": ["claude-agent"]
  }'
```

## 4. Test as the new user (still from the indexer host)

```bash
curl -k -u claude-agent:<PASSWORD> "https://localhost:9200/wazuh-alerts-*/_search?size=1"
```

Should return a hit, not a 403. Then test it reaches from the agent LXC too
(this exercises the firewall rule added for port 9200):

```bash
curl -k -u claude-agent:<PASSWORD> "https://192.168.5.12:9200/wazuh-alerts-*/_search?size=1"
```

## 5. Store the credentials on the agent LXC

As root on the agent LXC, append to `/home/agent/.config/agent.env` (chmod
600, owned by agent -- already set up that way):

```
WAZUH_INDEXER_URL=https://192.168.5.12:9200
WAZUH_INDEXER_USER=claude-agent
WAZUH_INDEXER_PASS=<the password you chose>
```

Once that's in place, `wazuh-triage/run.sh` (see claude-noc-agent-setup.md)
can authenticate.
