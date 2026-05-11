# Configuring the `auth` Section of `runtime-policy.yaml`

The `auth` block in `config/runtime-policy.yaml` controls how the MCP server authenticates incoming requests and authorizes tool access. It supports three modes: disabled (open access), API key, and Azure AD OAuth2 with optional group-based authorization.

---

## Full Reference

```yaml
auth:
  auth_mode: disabled               # disabled | api_key | azure
  azure_auth_enabled: false         # enable Azure AD token validation
  azure_group_authorization_enabled: false  # enable group-based read/write access control
  azure_tenant_id: ""               # Azure AD tenant ID (GUID)
  azure_client_id: ""               # App registration client ID (GUID)
  azure_client_secret_ref: ""       # env var name holding the client secret
  azure_required_scopes: []         # list of required OAuth2 scopes
  azure_base_url: ""                # override Azure AD base URL (optional)
  azure_identifier_uri: ""          # app identifier URI for token audience validation
  azure_group_claim_name: groups    # JWT claim name that carries group membership
  azure_read_groups: []             # groups allowed to call read-only tools
  azure_write_groups: []            # groups allowed to call write tools
  pool_max_connections: 10          # max total connections in the HTTP client pool
  pool_max_keepalive_connections: 10 # max idle keep-alive connections
  pool_timeout_seconds: 10          # connection pool timeout in seconds
```

---

## `auth_mode`

Controls the top-level authentication strategy.

| Value | Behavior |
|---|---|
| `disabled` | No authentication. All requests are accepted. Use only in isolated dev/test environments. |
| `api_key` | Requires a static API key passed in the `Authorization` header. |
| `azure` | Validates Azure AD Bearer tokens on every request. Requires `azure_auth_enabled: true` and the Azure fields below. |

**Example — disable auth (dev only):**
```yaml
auth:
  auth_mode: disabled
```

**Example — Azure AD:**
```yaml
auth:
  auth_mode: azure
  azure_auth_enabled: true
```

---

## Azure AD Authentication Fields

These fields are only evaluated when `auth_mode: azure` and `azure_auth_enabled: true`.

### `azure_tenant_id`
Your Azure AD tenant ID. Found in Azure Portal → Azure Active Directory → Overview.

```yaml
azure_tenant_id: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

### `azure_client_id`
The client ID of the app registration that represents this MCP server.

```yaml
azure_client_id: "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy"
```

### `azure_client_secret_ref`
The **name of an environment variable** that holds the client secret — not the secret value itself. This keeps secrets out of the config file.

```yaml
azure_client_secret_ref: "MCP_AZURE_CLIENT_SECRET"
```

Then set the environment variable before starting the server:
```bash
export MCP_AZURE_CLIENT_SECRET="your-secret-value"
```

### `azure_identifier_uri`
The application ID URI used to validate the `aud` (audience) claim in incoming tokens. Set this to the URI configured on your app registration.

```yaml
azure_identifier_uri: "api://yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy"
```

### `azure_required_scopes`
List of OAuth2 scopes that must be present in the token. Leave empty to skip scope validation.

```yaml
azure_required_scopes:
  - "api://yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy/mcp.read"
  - "api://yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy/mcp.write"
```

### `azure_base_url`
Optional override for the Azure AD base URL. Leave empty to use the default (`https://login.microsoftonline.com`). Useful for sovereign clouds (e.g., Azure Government).

```yaml
azure_base_url: "https://login.microsoftonline.us"  # Azure Government
```

---

## Group-Based Authorization

When `azure_group_authorization_enabled: true`, the server inspects the group membership claim in the token and enforces read/write access per group.

### `azure_group_authorization_enabled`
Enables group-based access control. Requires `azure_auth_enabled: true`.

```yaml
azure_group_authorization_enabled: true
```

### `azure_group_claim_name`
The JWT claim that carries the user's group memberships. Defaults to `groups`. Change this if your Azure AD app is configured to emit groups under a different claim name (e.g., `roles`).

```yaml
azure_group_claim_name: groups
```

### `azure_read_groups`
List of Azure AD group object IDs (GUIDs) whose members are allowed to call read-only tools. Members of none of these groups are denied access entirely.

```yaml
azure_read_groups:
  - "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"  # mcp-readers
  - "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"  # mcp-analysts
```

### `azure_write_groups`
List of Azure AD group object IDs whose members are additionally allowed to call write tools (those listed in `allowed_write_tools`). Members of read groups but not write groups can still call read tools.

```yaml
azure_write_groups:
  - "cccccccc-cccc-cccc-cccc-cccccccccccc"  # mcp-admins
```

> **Note:** Group object IDs are found in Azure Portal → Azure Active Directory → Groups → select group → Overview → Object ID.

---

## Connection Pool Settings

These control the HTTP client pool used for outbound Azure AD token validation requests. Tune these if you see connection timeouts under high concurrency.

| Field | Default | Description |
|---|---|---|
| `pool_max_connections` | `10` | Maximum total connections in the pool |
| `pool_max_keepalive_connections` | `10` | Maximum idle keep-alive connections |
| `pool_timeout_seconds` | `10` | Timeout in seconds waiting for a pool connection |

```yaml
pool_max_connections: 20
pool_max_keepalive_connections: 10
pool_timeout_seconds: 15
```

---

## Complete Examples

### Development — no auth

```yaml
auth:
  auth_mode: disabled
  azure_auth_enabled: false
  azure_group_authorization_enabled: false
  pool_max_connections: 10
  pool_max_keepalive_connections: 10
  pool_timeout_seconds: 10
```

### Production — Azure AD with group authorization

```yaml
auth:
  auth_mode: azure
  azure_auth_enabled: true
  azure_group_authorization_enabled: true
  azure_tenant_id: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
  azure_client_id: "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy"
  azure_client_secret_ref: "MCP_AZURE_CLIENT_SECRET"
  azure_identifier_uri: "api://yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy"
  azure_required_scopes:
    - "api://yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy/mcp.access"
  azure_group_claim_name: groups
  azure_read_groups:
    - "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
  azure_write_groups:
    - "cccccccc-cccc-cccc-cccc-cccccccccccc"
  pool_max_connections: 20
  pool_max_keepalive_connections: 10
  pool_timeout_seconds: 15
```

---

## Security Notes

- Never put the client secret value directly in `runtime-policy.yaml`. Always use `azure_client_secret_ref` to reference an environment variable.
- Keep `auth_mode: disabled` only in isolated environments. Any HTTP/SSE transport exposed on a network should use `azure` or `api_key`.
- Group object IDs in `azure_read_groups` and `azure_write_groups` are GUIDs, not display names. Display names can change; GUIDs are stable.
- If `azure_group_authorization_enabled: false`, all authenticated users (valid token) can call all tools regardless of group membership.
