# cm-api-rs

## Project Structure

This is a **monorepo** containing:

- `backend/` - Rust API server built with Rocket
- `frontend/` - React/TypeScript web interface

## Backend Configuration

The backend is configured via two TOML files: `Api.toml` and `Rocket.toml`.

### Api.toml

#### Host Configuration

```toml
[host]
base_url = "/api" # base path for API routes (default: "/api")
```

#### Topic Configuration

```toml
[topic]
host = "play.cm-ss13.com:1400" # game server address for status pings
auth = "your-comms-key"        # comms key to contact the game server
```

#### Logging Configuration

```toml
[logging]
webhook = "https://discord.com/api/webhooks/..."       # Discord webhook for database actions
user_manager_webhook = "https://discord.com/api/..."   # (optional) separate webhook for user management
```

#### API Authentication

```toml
[api_auth]
token = "your-bearer-token" # bearer token for API authorization (alternative to session-based auth)
```

#### CORS Configuration

```toml
[cors]
allowed_origin = "https://yourdomain.com" # allowed origin for CORS (required in production, defaults to "*" in debug)
```

#### OIDC Configuration

```toml
[oidc]
issuer_url = "https://auth.example.com/application/o/app/"
client_id = "your-client-id"
client_secret = "your-client-secret"
redirect_uri = "https://yourdomain.com/api/auth/callback"
scopes = ["openid", "profile", "email", "groups"]       # (optional) defaults to these values
staff_groups = ["staff", "admins"]                       # groups allowed to access the API
management_groups = ["management"]                       # groups with elevated permissions
session_secret = "your-secure-session-secret"            # secret for signing session JWTs
session_duration_hours = 24                              # (optional) session duration in hours (default: 24)
post_login_redirect = "/"                                # (optional) redirect after login (default: "/")
post_logout_redirect = "/"                               # (optional) redirect after logout (default: "/")
userinfo_endpoint = "https://auth.example.com/userinfo/" # (optional) override userinfo endpoint
```

#### Authentik Integration

```toml
[authentik]
token = "your-authentik-api-token"
base_url = "https://auth.example.com"
allowed_admin_ranks = ["R_ADMIN", "R_MOD", "R_EVENT"]    # allowed admin rank values for groups
allowed_instances = ["cm13-live", "cm13-rp"]             # allowed instance names for admin_ranks config
webhook_secret = "secret-for-webhook-auth"               # (optional) secret for authenticating webhooks

[authentik.group_permissions]
staff_management = ["admins", "moderators"]              # maps permission roles to manageable groups
mentor_overseer = ["mentors"]

[authentik.discourse]                                    # (optional) Discourse integration
base_url = "https://forum.example.com"
api_key = "your-discourse-api-key"
api_username = "system"
provider_name = "oidc"                                   # identity provider name in Discourse
webhook_secret = "discourse-webhook-secret"              # (optional) webhook authentication
```

#### Space Station 14 Authentication Broker

Lets SS14 game servers (CMU-14) accept CM accounts as real logins alongside Space Wizards
accounts, whether the player signed into the launcher with a password or through Steam.
CMU-14's auth server is [MultiAuthProxy](https://github.com/AU-14/MultiAuthProxy), which asks
several auth servers for every login; add this broker to its `AuthServers` list and restart it.
Nothing changes on the game server itself:

```json
"AuthServers": [
  "https://auth.spacestation14.com/",
  "https://auth.playss14.com/",
  "https://db.cm-ss13.com/api/ss14auth/"
]
```

```toml
[ss14auth]
allowed_server_ips = ["203.0.113.10"]   # hosts allowed to call hasJoined (the proxy); empty = any
# wizden_url = "https://auth.spacestation14.com/"  # only when used WITHOUT a multi-auth proxy:
#                                                   # unknown logins are then forwarded to Space Wizards
# userinfo_url = "https://auth.example.com/application/o/userinfo/"  # defaults to <authentik.base_url>/application/o/userinfo/
# trust = 1.0
```

Which SS14 identity a CM account gets is decided on its first join and kept in `ss14_identities`:

- A CM account with a Space Wizards account linked in the CM portal plays as that account, so
  the player is the same person on the server whichever login they use.
- Any other CM account gets its own id (a UUID v5 of the ckey) with the ckey as username. No
  setup is needed; Steam players in particular can join straight away.
- Linking a Wizden account later does not change an identity that has already joined. To merge
  a player's history, change their `ss14_identities` row by hand.

Endpoints, all under `/api/ss14auth/`:

- `GET api/identity` (launcher, `Authorization: SS14Auth <CM access token>`): the identity the
  account will play as, which the launcher passes to the game before it starts.
- `POST api/session/join` (game client, `Authorization: SS14Auth <CM access token>`): validates
  the token against Authentik `userinfo`, resolves the identity, records the connection hash.
- `GET api/session/hasJoined` (game server via the proxy): answers recorded CM logins; anything
  else is "not valid" so the proxy's other auth servers answer for Space Wizards players. With
  `wizden_url` set, unknown logins are forwarded instead.
- `GET api/query/name?name=` and `GET api/query/userid?userid=`: identity lookups in Space
  Wizards' format, used by the proxy and by in-game admin commands. CM accounts only.
- `GET user-by-ss14-id/<id>` (API bearer token): the CM ckey behind an SS14 user id, for
  applying CM bans and whitelists in game.

Requires the `ss14_identities` and `ss14_sessions` tables from `backend/schema/cmapi.sql`.
Session rows live for about 90 seconds and are single use.

#### Discord Bot Integration

```toml
[discord_bot]
token = "your-discord-bot-token"

[discord_bot.link_role_changes.123456789012345678]       # server (guild) ID
roles_to_add = ["987654321098765432"]                    # role IDs to add on link
roles_to_remove = ["111222333444555666"]                 # role IDs to remove on link
minimum_playtime_minutes = 60                            # (optional) minimum playtime required

[discord_bot.link_role_changes.123456789012345678.whitelist_roles]
WHITELIST_SYNTHETIC = ["synth-role-id"]                  # maps whitelist status to role IDs
WHITELIST_COMMANDER = ["co-role-id"]
```

### Rocket.toml

```toml
[default]
address = "0.0.0.0" # address to bind the web server (e.g., "0.0.0.0" for containers)
port = 8080         # port to listen on

[default.databases.cmdb]
url = "mysql://root:password@127.0.0.1:3306/cmdb" # MySQL connection string
```
