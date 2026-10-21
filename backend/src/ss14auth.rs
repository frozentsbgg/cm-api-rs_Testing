//! Space Station 14 authentication broker.
//!
//! Lets a Robust Toolbox (SS14) game server such as CMU-14 accept CM accounts as real logins
//! while still accepting Space Wizards accounts. The game server's `auth.server` CVar is pointed
//! at this module (`https://db.cm-ss13.com/api/ss14auth/`), which implements the two endpoints
//! the engine calls:
//!
//! * `POST api/session/join` — called by the game *client* right before it connects, with the
//!   player's CM access token in an `Authorization: SS14Auth <token>` header. The token is
//!   checked against Authentik's `userinfo` endpoint (the same check the CM-SS13 game server does
//!   for BYOND logins) and the connection hash is recorded for a short time.
//! * `GET api/session/hasJoined?hash=…&userId=…` — called by the game *server* to confirm a
//!   connecting player. A recorded hash is answered from our own records. Anything else is
//!   answered "not valid", or, when `wizden_url` is configured, forwarded unchanged to Space
//!   Wizards so the broker can also run on its own as a game server's only auth server.
//!
//! CMU-14 runs MultiAuthProxy (github.com/AU-14/MultiAuthProxy) as its auth server, which asks
//! several auth servers at once. There this broker is simply one more entry in its list and
//! forwarding stays off.
//!
//! Which SS14 identity a CM account gets is decided the first time it joins and then kept in
//! `ss14_identities` for good:
//!
//! * a CM account with a Space Wizards account linked in the CM portal (the `ss14_user_id`
//!   claim Authentik returns for the launcher) is that Wizden account, so the player is the
//!   same person on the server whichever login they use;
//! * any other CM account gets its own id, a UUID v5 derived from the ckey, and the ckey as its
//!   username. No setup is needed on the player's side.
//!
//! Linking a Wizden account later does not change an identity that has already joined; an admin
//! can change the row by hand if a player wants their history merged.
//!
//! `GET api/identity` (same `SS14Auth` header) tells the launcher which identity an account will
//! play as, since the engine needs the user id before the game starts.
//!
//! Also implemented, for admins and for MultiAuthProxy's lookups: `GET api/query/name` and
//! `GET api/query/userid` (same shape as Space Wizards'), and `GET user-by-ss14-id/<id>`, which
//! returns the CM ckey behind an SS14 user id and requires the API bearer token.

use std::net::IpAddr;

use rocket::{
    Request, State,
    http::Status,
    request::{FromRequest, Outcome},
    serde::json::Json,
};
use rocket_db_pools::Connection;
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use sqlx::Row;
use utoipa::ToSchema;

use crate::{Cmapi, Config, player::validate_auth_header};

/// How long a recorded `join` stays valid. The game server calls `hasJoined` within seconds.
const SESSION_LIFETIME_SECONDS: i64 = 90;
/// SS14 usernames: 3 to 32 characters of letters, digits and underscores.
const MAX_USERNAME_LENGTH: usize = 32;
const MIN_USERNAME_LENGTH: usize = 3;
/// Namespace for CM-minted SS14 user ids: `uuid5(DNS, "cm-ss13.com")`. Never change it, or every
/// CM-only player becomes a different person on the server.
const CM_IDENTITY_NAMESPACE: [u8; 16] = [
    0xbb, 0x1d, 0x29, 0x49, 0x28, 0x69, 0x53, 0x37, 0xa7, 0x9b, 0xdf, 0x39, 0x47, 0x5e, 0x70, 0x2e,
];

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Ss14AuthConfig {
    /// Space Wizards auth server that unknown logins are forwarded to. Leave unset when the
    /// broker sits behind a multi-auth proxy that already asks Space Wizards itself.
    #[serde(default)]
    pub wizden_url: Option<String>,
    /// Authentik userinfo endpoint used to validate CM access tokens. Defaults to
    /// `<authentik.base_url>/application/o/userinfo/`.
    pub userinfo_url: Option<String>,
    /// Game server addresses allowed to call `hasJoined`. Empty allows any address.
    #[serde(default)]
    pub allowed_server_ips: Vec<IpAddr>,
    /// Trust value reported for CM logins (the engine exposes it to content; 1.0 is "trusted").
    #[serde(default = "default_trust")]
    pub trust: f32,
}

fn default_trust() -> f32 {
    1.0
}

impl Ss14AuthConfig {
    fn wizden_base(&self) -> Option<String> {
        self.wizden_url
            .as_deref()
            .map(str::trim)
            .filter(|u| !u.is_empty())
            .map(|u| format!("{}/", u.trim_end_matches('/')))
    }
}

/// `Authorization: SS14Auth <token>` as sent by the game client.
pub struct Ss14AuthToken(pub String);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for Ss14AuthToken {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let Some(value) = request.headers().get_one("Authorization") else {
            return Outcome::Error((Status::Unauthorized, ()));
        };
        let Some(token) = value.strip_prefix("SS14Auth ") else {
            return Outcome::Error((Status::Unauthorized, ()));
        };
        let token = token.trim();
        if token.is_empty() {
            return Outcome::Error((Status::Unauthorized, ()));
        }
        Outcome::Success(Ss14AuthToken(token.to_string()))
    }
}

/// Address of the caller, for restricting `hasJoined` to the game server.
pub struct ClientAddress(pub Option<IpAddr>);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for ClientAddress {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        Outcome::Success(ClientAddress(request.client_ip()))
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct Ss14AuthError {
    pub error: String,
    pub message: String,
}

fn error(status: Status, code: &str, message: impl Into<String>) -> (Status, Json<Ss14AuthError>) {
    (
        status,
        Json(Ss14AuthError {
            error: code.to_string(),
            message: message.into(),
        }),
    )
}

/// Body of `POST api/session/join`, as sent by Robust.Client.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct JoinRequest {
    /// Base64 SHA-256 of the client's shared secret and the server's public key.
    pub hash: String,
    /// Modern hardware id, base64. Optional: the client omits it when the server did not ask.
    #[serde(default)]
    pub hwid: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct JoinResponse {
    pub user_id: String,
    pub user_name: String,
}

/// What Authentik's `userinfo` returns for a launcher access token.
#[derive(Debug, Deserialize)]
struct AuthentikUserInfo {
    sub: String,
    #[serde(default)]
    ckey: Option<String>,
    #[serde(default)]
    preferred_username: Option<String>,
    #[serde(default)]
    ss14_user_id: Option<String>,
}

/// Shape of `hasJoined` responses, matching Space Wizards' auth server so the engine can parse
/// either our answer or a forwarded one.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct HasJoinedResponse {
    pub is_valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_data: Option<HasJoinedUserData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_data: Option<HasJoinedConnectionData>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct HasJoinedUserData {
    pub user_name: String,
    pub user_id: String,
    pub patron_tier: Option<String>,
    pub created_time: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct HasJoinedConnectionData {
    pub hwids: Vec<String>,
    pub trust: f32,
}

impl HasJoinedResponse {
    fn invalid() -> Self {
        Self {
            is_valid: false,
            user_data: None,
            connection_data: None,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UserBySs14IdResponse {
    pub ss14_user_id: String,
    pub ckey: String,
    pub user_name: String,
    /// `wizden` for a linked Space Wizards account, `cm` for an id minted from the ckey.
    pub source: String,
}

/// Body of `GET api/identity`: what the launcher starts the game with.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct IdentityResponse {
    pub user_id: String,
    pub user_name: String,
    pub ckey: String,
    /// `wizden` for a linked Space Wizards account, `cm` for an id minted from the ckey.
    pub source: String,
}

/// Shape of Space Wizards' `api/query/name` and `api/query/userid` answers.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct QueryResponse {
    pub user_name: String,
    pub user_id: String,
    pub patron_tier: Option<String>,
    pub created_time: String,
}

/// An SS14 identity for a CM account, as stored in `ss14_identities`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub ckey: String,
    pub ss14_user_id: String,
    pub source: String,
    pub created_time: String,
}

/// UUID v5 (RFC 4122) of `name` in `namespace`, lower-case hyphenated.
pub fn uuid_v5(namespace: &[u8; 16], name: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(namespace);
    hasher.update(name.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = hex::encode(bytes);
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

/// The SS14 user id minted for a CM account without a linked Space Wizards account.
pub fn cm_identity_id(ckey: &str) -> String {
    uuid_v5(&CM_IDENTITY_NAMESPACE, &ckey.trim().to_ascii_lowercase())
}

/// Lower-case hyphenated UUID, or `None` if the value is not one.
fn normalise_user_id(value: &str) -> Option<String> {
    let value = value.trim().to_ascii_lowercase();
    let parts: Vec<&str> = value.split('-').collect();
    let lengths = [8, 4, 4, 4, 12];
    if parts.len() != 5
        || parts
            .iter()
            .zip(lengths)
            .any(|(p, len)| p.len() != len || !p.chars().all(|c| c.is_ascii_hexdigit()))
    {
        return None;
    }
    Some(value)
}

/// Derive an SS14-compatible username from a CM ckey or username.
pub fn ss14_username(ckey: Option<&str>, preferred_username: Option<&str>, sub: &str) -> String {
    let source = ckey
        .filter(|s| !s.trim().is_empty())
        .or(preferred_username.filter(|s| !s.trim().is_empty()))
        .unwrap_or(sub);

    let mut name: String = source
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
        .take(MAX_USERNAME_LENGTH)
        .collect();

    if name.len() < MIN_USERNAME_LENGTH {
        name = format!(
            "cm_{}",
            sub.chars()
                .filter(char::is_ascii_alphanumeric)
                .take(8)
                .collect::<String>()
        );
    }
    name
}

/// Validate a hash parameter: base64url without padding, as the engine sends it.
pub fn is_valid_hash(hash: &str) -> bool {
    !hash.is_empty()
        && hash.len() <= 64
        && hash
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '=')
}

fn ss14auth_config(config: &Config) -> Result<&Ss14AuthConfig, (Status, Json<Ss14AuthError>)> {
    config.ss14auth.as_ref().ok_or_else(|| {
        error(
            Status::InternalServerError,
            "not_configured",
            "SS14 authentication is not configured",
        )
    })
}

fn userinfo_url(
    config: &Config,
    ss14: &Ss14AuthConfig,
) -> Result<String, (Status, Json<Ss14AuthError>)> {
    if let Some(url) = &ss14.userinfo_url {
        return Ok(url.clone());
    }
    let authentik = config.authentik.as_ref().ok_or_else(|| {
        error(
            Status::InternalServerError,
            "not_configured",
            "Authentik is not configured",
        )
    })?;
    Ok(format!(
        "{}/application/o/userinfo/",
        authentik.base_url.trim_end_matches('/')
    ))
}

async fn fetch_userinfo(
    url: &str,
    token: &str,
) -> Result<AuthentikUserInfo, (Status, Json<Ss14AuthError>)> {
    let response = reqwest::Client::new()
        .get(url)
        .bearer_auth(token)
        .send()
        .await
        .map_err(|e| {
            error(
                Status::BadGateway,
                "authentik_unreachable",
                format!("Could not reach Authentik: {e}"),
            )
        })?;

    if response.status() == reqwest::StatusCode::UNAUTHORIZED
        || response.status() == reqwest::StatusCode::FORBIDDEN
    {
        return Err(error(
            Status::Unauthorized,
            "invalid_token",
            "The CM login token is invalid or expired; log in to the launcher again",
        ));
    }
    if !response.status().is_success() {
        return Err(error(
            Status::BadGateway,
            "authentik_error",
            format!("Authentik returned HTTP {}", response.status()),
        ));
    }

    response.json::<AuthentikUserInfo>().await.map_err(|e| {
        error(
            Status::BadGateway,
            "authentik_error",
            format!("Could not parse Authentik userinfo: {e}"),
        )
    })
}

/// The CM account behind a launcher token, with its SS14 identity resolved.
async fn account_for_token(
    config: &Config,
    ss14: &Ss14AuthConfig,
    db: &mut Connection<Cmapi>,
    token: &str,
) -> Result<(Identity, String), (Status, Json<Ss14AuthError>)> {
    let info = fetch_userinfo(&userinfo_url(config, ss14)?, token).await?;

    let ckey = info
        .ckey
        .as_deref()
        .map(str::trim)
        .filter(|c| !c.is_empty())
        .map(str::to_ascii_lowercase)
        .unwrap_or_else(|| info.sub.clone());
    let user_name = ss14_username(
        info.ckey.as_deref(),
        info.preferred_username.as_deref(),
        &info.sub,
    );
    let identity = resolve_identity(db, &ckey, info.ss14_user_id.as_deref()).await?;
    Ok((identity, user_name))
}

/// GET /ss14auth/api/identity - the identity a CM account plays as (launcher, before launch)
#[utoipa::path(
    get,
    path = "/api/ss14auth/api/identity",
    tag = "SS14 Auth",
    responses(
        (status = 200, description = "Identity", body = IdentityResponse),
        (status = 401, description = "Missing or invalid CM token", body = Ss14AuthError),
        (status = 409, description = "Linked SS14 account already belongs to another CM account", body = Ss14AuthError),
    ),
    security(("ss14_auth_token" = []))
)]
#[get("/api/identity")]
pub async fn identity(
    token: Ss14AuthToken,
    config: &State<Config>,
    mut db: Connection<Cmapi>,
) -> Result<Json<IdentityResponse>, (Status, Json<Ss14AuthError>)> {
    let ss14 = ss14auth_config(config)?;
    let (identity, user_name) = account_for_token(config, ss14, &mut db, &token.0).await?;
    Ok(Json(IdentityResponse {
        user_id: identity.ss14_user_id,
        user_name,
        ckey: identity.ckey,
        source: identity.source,
    }))
}

/// POST /ss14auth/api/session/join - the game client registers an upcoming connection
#[utoipa::path(
    post,
    path = "/api/ss14auth/api/session/join",
    tag = "SS14 Auth",
    request_body = JoinRequest,
    responses(
        (status = 200, description = "Login recorded", body = JoinResponse),
        (status = 401, description = "Missing or invalid CM token", body = Ss14AuthError),
        (status = 409, description = "Linked SS14 account already belongs to another CM account", body = Ss14AuthError),
    ),
    security(("ss14_auth_token" = []))
)]
#[post("/api/session/join", format = "json", data = "<request>")]
pub async fn session_join(
    token: Ss14AuthToken,
    config: &State<Config>,
    mut db: Connection<Cmapi>,
    request: Json<JoinRequest>,
) -> Result<Json<JoinResponse>, (Status, Json<Ss14AuthError>)> {
    let ss14 = ss14auth_config(config)?;

    if !is_valid_hash(&request.hash) {
        return Err(error(Status::BadRequest, "invalid_hash", "Malformed hash"));
    }

    let (identity, user_name) = account_for_token(config, ss14, &mut db, &token.0).await?;
    let user_id = identity.ss14_user_id.as_str();
    let ckey = identity.ckey.as_str();

    purge_expired(&mut db).await;

    sqlx::query(
        r#"
        INSERT INTO ss14_sessions (hash, ss14_user_id, user_name, ckey, hwid, created_at)
        VALUES (?, ?, ?, ?, ?, NOW())
        ON DUPLICATE KEY UPDATE
            ss14_user_id = VALUES(ss14_user_id),
            user_name = VALUES(user_name),
            ckey = VALUES(ckey),
            hwid = VALUES(hwid),
            created_at = NOW()
        "#,
    )
    .bind(&request.hash)
    .bind(user_id)
    .bind(&user_name)
    .bind(ckey)
    .bind(request.hwid.as_deref())
    .execute(&mut **db)
    .await
    .map_err(|e| {
        error(
            Status::InternalServerError,
            "database_error",
            format!("Failed to record session: {e}"),
        )
    })?;

    Ok(Json(JoinResponse {
        user_id: user_id.to_string(),
        user_name,
    }))
}

fn identity_from_row(row: &sqlx::mysql::MySqlRow) -> Identity {
    let created: chrono::NaiveDateTime = row.get("created_at");
    Identity {
        ckey: row.get("ckey"),
        ss14_user_id: row.get("ss14_user_id"),
        source: row.get("source"),
        created_time: created.and_utc().to_rfc3339(),
    }
}

async fn find_identity(
    db: &mut Connection<Cmapi>,
    column: &str,
    value: &str,
) -> Result<Option<Identity>, (Status, Json<Ss14AuthError>)> {
    let sql = format!(
        "SELECT ckey, ss14_user_id, source, created_at FROM ss14_identities WHERE {column} = ?"
    );
    sqlx::query(&sql)
        .bind(value)
        .fetch_optional(&mut ***db)
        .await
        .map(|row| row.as_ref().map(identity_from_row))
        .map_err(|e| {
            error(
                Status::InternalServerError,
                "database_error",
                format!("Failed to look up identity: {e}"),
            )
        })
}

/// The SS14 identity for a CM account, created on first join and fixed from then on.
async fn resolve_identity(
    db: &mut Connection<Cmapi>,
    ckey: &str,
    linked_ss14_user_id: Option<&str>,
) -> Result<Identity, (Status, Json<Ss14AuthError>)> {
    if let Some(existing) = find_identity(db, "ckey", ckey).await? {
        return Ok(existing);
    }

    let (ss14_user_id, source) = match linked_ss14_user_id.and_then(normalise_user_id) {
        Some(linked) => (linked, "wizden"),
        None => (cm_identity_id(ckey), "cm"),
    };

    // INSERT IGNORE so two simultaneous first joins (or a Wizden account already claimed by
    // another ckey) do not fail; whatever is in the table afterwards is the answer.
    sqlx::query(
        "INSERT IGNORE INTO ss14_identities (ckey, ss14_user_id, source, created_at) VALUES (?, ?, ?, NOW())",
    )
    .bind(ckey)
    .bind(&ss14_user_id)
    .bind(source)
    .execute(&mut ***db)
    .await
    .map_err(|e| {
        error(
            Status::InternalServerError,
            "database_error",
            format!("Failed to record identity: {e}"),
        )
    })?;

    find_identity(db, "ckey", ckey).await?.ok_or_else(|| {
        error(
            Status::Conflict,
            "identity_conflict",
            "The linked Space Station 14 account is already used by another CM account",
        )
    })
}

async fn purge_expired(db: &mut Connection<Cmapi>) {
    let _ = sqlx::query("DELETE FROM ss14_sessions WHERE created_at < NOW() - INTERVAL ? SECOND")
        .bind(SESSION_LIFETIME_SECONDS * 10)
        .execute(&mut ***db)
        .await;
}

/// GET /ss14auth/api/session/hasJoined - the game server confirms a connecting player
#[utoipa::path(
    get,
    path = "/api/ss14auth/api/session/hasJoined",
    tag = "SS14 Auth",
    params(
        ("hash" = String, Query, description = "Connection hash from the client handshake"),
        ("userId" = String, Query, description = "User id the client claims"),
    ),
    responses(
        (status = 200, description = "Validation result (ours, or forwarded from Space Wizards)", body = HasJoinedResponse),
        (status = 403, description = "Caller is not an allowed game server", body = Ss14AuthError),
    )
)]
#[get("/api/session/hasJoined?<hash>&<userId>&<serverUrl>")]
#[allow(non_snake_case)]
pub async fn session_has_joined(
    caller: ClientAddress,
    config: &State<Config>,
    mut db: Connection<Cmapi>,
    hash: String,
    userId: String,
    serverUrl: Option<String>,
) -> Result<Json<HasJoinedResponse>, (Status, Json<Ss14AuthError>)> {
    let ss14 = ss14auth_config(config)?;

    if !ss14.allowed_server_ips.is_empty() {
        let allowed = caller
            .0
            .is_some_and(|ip| ss14.allowed_server_ips.contains(&ip));
        if !allowed {
            return Err(error(
                Status::Forbidden,
                "forbidden",
                "This address may not validate SS14 logins",
            ));
        }
    }

    if !is_valid_hash(&hash) {
        return Ok(Json(HasJoinedResponse::invalid()));
    }

    // A CM login we recorded ourselves. Single use: the row is deleted once answered.
    let row = sqlx::query(
        r#"
        SELECT ss14_user_id, user_name, hwid
        FROM ss14_sessions
        WHERE hash = ? AND created_at > NOW() - INTERVAL ? SECOND
        "#,
    )
    .bind(&hash)
    .bind(SESSION_LIFETIME_SECONDS)
    .fetch_optional(&mut **db)
    .await
    .map_err(|e| {
        error(
            Status::InternalServerError,
            "database_error",
            format!("Failed to look up session: {e}"),
        )
    })?;

    if let Some(row) = row {
        let ss14_user_id: String = row.get("ss14_user_id");
        let user_name: String = row.get("user_name");
        let hwid: Option<String> = row.get("hwid");

        let _ = sqlx::query("DELETE FROM ss14_sessions WHERE hash = ?")
            .bind(&hash)
            .execute(&mut **db)
            .await;

        // The id the client claimed has to be the one its token belongs to.
        if !ss14_user_id.eq_ignore_ascii_case(userId.trim()) {
            return Ok(Json(HasJoinedResponse::invalid()));
        }

        return Ok(Json(HasJoinedResponse {
            is_valid: true,
            user_data: Some(HasJoinedUserData {
                user_name,
                user_id: ss14_user_id,
                patron_tier: None,
                created_time: chrono::Utc::now().to_rfc3339(),
            }),
            connection_data: Some(HasJoinedConnectionData {
                hwids: hwid.into_iter().collect(),
                trust: ss14.trust,
            }),
        }));
    }

    // Not ours. Behind a multi-auth proxy that is the end of it; standalone, ask Space Wizards.
    match ss14.wizden_base() {
        Some(wizden) => forward_has_joined(&wizden, &hash, &userId, serverUrl.as_deref()).await,
        None => Ok(Json(HasJoinedResponse::invalid())),
    }
}

async fn forward_has_joined(
    wizden_base: &str,
    hash: &str,
    user_id: &str,
    server_url: Option<&str>,
) -> Result<Json<HasJoinedResponse>, (Status, Json<Ss14AuthError>)> {
    let mut query = vec![("hash", hash.to_string()), ("userId", user_id.to_string())];
    if let Some(server_url) = server_url {
        query.push(("serverUrl", server_url.to_string()));
    }

    let response = reqwest::Client::new()
        .get(format!("{wizden_base}api/session/hasJoined"))
        .query(&query)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| {
            error(
                Status::BadGateway,
                "wizden_unreachable",
                format!("Could not reach the Space Wizards auth server: {e}"),
            )
        })?;

    if !response.status().is_success() {
        return Err(error(
            Status::BadGateway,
            "wizden_error",
            format!(
                "Space Wizards auth server returned HTTP {}",
                response.status()
            ),
        ));
    }

    let body = response.json::<HasJoinedResponse>().await.map_err(|e| {
        error(
            Status::BadGateway,
            "wizden_error",
            format!("Could not parse the Space Wizards response: {e}"),
        )
    })?;
    Ok(Json(body))
}

/// GET /ss14auth/user-by-ss14-id/<id> - CM ckey behind an SS14 user id (API token required)
#[utoipa::path(
    get,
    path = "/api/ss14auth/user-by-ss14-id/{ss14_user_id}",
    tag = "SS14 Auth",
    params(("ss14_user_id" = String, Path, description = "SS14 user id")),
    responses(
        (status = 200, description = "Linked CM account", body = UserBySs14IdResponse),
        (status = 401, description = "Missing or invalid API token", body = Ss14AuthError),
        (status = 404, description = "No CM account is linked to that id", body = Ss14AuthError),
    ),
    security(("bearer_token" = []))
)]
#[get("/user-by-ss14-id/<ss14_user_id>")]
pub async fn user_by_ss14_id(
    auth: Option<crate::player::AuthorizationHeader>,
    config: &State<Config>,
    mut db: Connection<Cmapi>,
    ss14_user_id: String,
) -> Result<Json<UserBySs14IdResponse>, (Status, Json<Ss14AuthError>)> {
    if !validate_auth_header(auth.as_ref().map(|a| a.0.as_str()), config) {
        return Err(error(
            Status::Unauthorized,
            "unauthorized",
            "Invalid API token",
        ));
    }

    // Anyone who has joined through the broker is in our own table.
    let known = match normalise_user_id(&ss14_user_id) {
        Some(id) => find_identity(&mut db, "ss14_user_id", &id).await?,
        None => None,
    };
    if let Some(identity) = known {
        return Ok(Json(UserBySs14IdResponse {
            ss14_user_id: identity.ss14_user_id,
            user_name: ss14_username(Some(&identity.ckey), None, &identity.ckey),
            ckey: identity.ckey,
            source: identity.source,
        }));
    }

    // Otherwise a Space Wizards account linked in the portal that has not joined yet.
    let authentik = config.authentik.as_ref().ok_or_else(|| {
        error(
            Status::InternalServerError,
            "not_configured",
            "Authentik is not configured",
        )
    })?;

    // Linked accounts live in Authentik as OAuth source connections on the "ss14" source.
    let url = format!(
        "{}/api/v3/sources/user_connections/oauth/?source__slug=ss14&identifier={}",
        authentik.base_url.trim_end_matches('/'),
        urlencoding::encode(&ss14_user_id)
    );
    let response = reqwest::Client::new()
        .get(&url)
        .header("Authorization", format!("Bearer {}", authentik.token))
        .send()
        .await
        .map_err(|e| {
            error(
                Status::BadGateway,
                "authentik_unreachable",
                format!("Could not reach Authentik: {e}"),
            )
        })?;
    if !response.status().is_success() {
        return Err(error(
            Status::BadGateway,
            "authentik_error",
            format!("Authentik returned HTTP {}", response.status()),
        ));
    }
    let body: serde_json::Value = response.json().await.map_err(|e| {
        error(
            Status::BadGateway,
            "authentik_error",
            format!("Could not parse Authentik response: {e}"),
        )
    })?;

    let Some(connection) = body["results"].as_array().and_then(|results| {
        results
            .iter()
            .find(|c| c["identifier"].as_str() == Some(ss14_user_id.as_str()))
    }) else {
        return Err(error(
            Status::NotFound,
            "not_found",
            "No CM account is linked to that SS14 account",
        ));
    };
    let Some(user_pk) = connection["user"].as_i64() else {
        return Err(error(
            Status::NotFound,
            "not_found",
            "Linked account has no user",
        ));
    };

    let user_url = format!(
        "{}/api/v3/core/users/{}/",
        authentik.base_url.trim_end_matches('/'),
        user_pk
    );
    let user: serde_json::Value = reqwest::Client::new()
        .get(&user_url)
        .header("Authorization", format!("Bearer {}", authentik.token))
        .send()
        .await
        .map_err(|e| {
            error(
                Status::BadGateway,
                "authentik_unreachable",
                format!("Could not reach Authentik: {e}"),
            )
        })?
        .json()
        .await
        .map_err(|e| {
            error(
                Status::BadGateway,
                "authentik_error",
                format!("Could not parse Authentik user: {e}"),
            )
        })?;

    let ckey = user["attributes"]["ckey"]
        .as_str()
        .or(user["username"].as_str())
        .unwrap_or_default()
        .to_string();
    let user_name = ss14_username(Some(&ckey), user["username"].as_str(), &user_pk.to_string());

    Ok(Json(UserBySs14IdResponse {
        ss14_user_id,
        ckey,
        user_name,
        source: "wizden".to_string(),
    }))
}

fn query_response(identity: Identity) -> QueryResponse {
    QueryResponse {
        user_name: ss14_username(Some(&identity.ckey), None, &identity.ckey),
        user_id: identity.ss14_user_id,
        patron_tier: None,
        created_time: identity.created_time,
    }
}

/// GET /ss14auth/api/query/name - SS14 identity behind a username (CM accounts only)
#[utoipa::path(
    get,
    path = "/api/ss14auth/api/query/name",
    tag = "SS14 Auth",
    params(("name" = String, Query, description = "SS14 username (the CM ckey)")),
    responses(
        (status = 200, description = "Identity", body = QueryResponse),
        (status = 404, description = "No CM account has joined under that name"),
    )
)]
#[get("/api/query/name?<name>")]
pub async fn query_name(
    mut db: Connection<Cmapi>,
    name: String,
) -> Result<Json<QueryResponse>, Status> {
    let ckey = name.trim().to_ascii_lowercase();
    if ckey.is_empty() || ckey.len() > MAX_USERNAME_LENGTH {
        return Err(Status::NotFound);
    }
    match find_identity(&mut db, "ckey", &ckey).await {
        Ok(Some(identity)) => Ok(Json(query_response(identity))),
        Ok(None) => Err(Status::NotFound),
        Err((status, _)) => Err(status),
    }
}

/// GET /ss14auth/api/query/userid - SS14 identity behind a user id (CM accounts only)
#[utoipa::path(
    get,
    path = "/api/ss14auth/api/query/userid",
    tag = "SS14 Auth",
    params(("userid" = String, Query, description = "SS14 user id")),
    responses(
        (status = 200, description = "Identity", body = QueryResponse),
        (status = 404, description = "No CM account has joined under that id"),
    )
)]
#[get("/api/query/userid?<userid>")]
pub async fn query_userid(
    mut db: Connection<Cmapi>,
    userid: String,
) -> Result<Json<QueryResponse>, Status> {
    let Some(id) = normalise_user_id(&userid) else {
        return Err(Status::NotFound);
    };
    match find_identity(&mut db, "ss14_user_id", &id).await {
        Ok(Some(identity)) => Ok(Json(query_response(identity))),
        Ok(None) => Err(Status::NotFound),
        Err((status, _)) => Err(status),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usernames_follow_ss14_rules() {
        assert_eq!(
            ss14_username(Some("frozentsbgg"), None, "sub"),
            "frozentsbgg"
        );
        assert_eq!(ss14_username(Some("tim millar!"), None, "sub"), "timmillar");
        assert_eq!(ss14_username(None, Some("Frozen"), "sub"), "Frozen");
        assert_eq!(
            ss14_username(Some("ab"), None, "0c1b0f6e-2b4a"),
            "cm_0c1b0f6e"
        );
        assert_eq!(ss14_username(Some(&"x".repeat(50)), None, "sub").len(), 32);
    }

    #[test]
    fn uuid_v5_matches_rfc_4122() {
        // RFC 4122 DNS namespace, "python.org": the standard library's well-known vector.
        let dns: [u8; 16] = [
            0x6b, 0xa7, 0xb8, 0x10, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4,
            0x30, 0xc8,
        ];
        assert_eq!(
            uuid_v5(&dns, "python.org"),
            "886313e1-3b8a-5372-9b90-0c9aee199e5d"
        );
        assert_eq!(
            uuid_v5(&dns, "cm-ss13.com"),
            "bb1d2949-2869-5337-a79b-df39475e702e"
        );
    }

    #[test]
    fn cm_identities_are_stable_and_case_insensitive() {
        assert_eq!(
            cm_identity_id("frozentsbgg"),
            "a1ff36cd-b942-5ef6-9d23-b1561592fe30"
        );
        assert_eq!(
            cm_identity_id(" FrozenTSBGG "),
            cm_identity_id("frozentsbgg")
        );
        assert_ne!(
            cm_identity_id("frozentsbgg"),
            cm_identity_id("frozentsbgg2")
        );
    }

    #[test]
    fn user_ids_are_normalised() {
        assert_eq!(
            normalise_user_id(" 74A82703-832A-4BD9-9BF7-B0281740A885 ").as_deref(),
            Some("74a82703-832a-4bd9-9bf7-b0281740a885")
        );
        assert_eq!(normalise_user_id(""), None);
        assert_eq!(normalise_user_id("not-a-uuid"), None);
        assert_eq!(normalise_user_id("74a82703832a4bd99bf7b0281740a885"), None);
    }

    #[test]
    fn hashes_are_validated() {
        assert!(is_valid_hash("abcDEF123-_="));
        assert!(!is_valid_hash(""));
        assert!(!is_valid_hash("has space"));
        assert!(!is_valid_hash(&"a".repeat(65)));
    }

    #[test]
    fn has_joined_matches_wizden_shape() {
        let wizden = r#"{"isValid":true,"userData":{"userName":"Frozen","userId":"74a82703-832a-4bd9-9bf7-b0281740a885","patronTier":null,"createdTime":"2024-01-01T00:00:00+00:00"},"connectionData":{"hwids":["AAAA"],"trust":1}}"#;
        let parsed: HasJoinedResponse = serde_json::from_str(wizden).unwrap();
        assert!(parsed.is_valid);
        let back = serde_json::to_value(&parsed).unwrap();
        assert_eq!(back["userData"]["userName"], "Frozen");
        assert_eq!(back["connectionData"]["hwids"][0], "AAAA");

        let invalid = serde_json::to_value(HasJoinedResponse::invalid()).unwrap();
        assert_eq!(invalid, serde_json::json!({"isValid": false}));
    }

    /// Forwarding to Space Wizards with an unknown hash must come back as a well-formed
    /// "not valid" answer, which is what a Wizden-login player's server will see mid-handshake.
    #[tokio::test]
    #[ignore = "network"]
    async fn live_forward_unknown_hash_to_wizden() {
        let result = forward_has_joined(
            "https://auth.spacestation14.com/",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "00000000-0000-0000-0000-000000000000",
            None,
        )
        .await;
        let body = result
            .map_err(|(s, e)| format!("{s}: {}", e.message))
            .unwrap();
        assert!(!body.is_valid);
    }

    #[test]
    fn wizden_base_always_has_trailing_slash() {
        let mut cfg = Ss14AuthConfig {
            wizden_url: Some("https://auth.spacestation14.com".into()),
            userinfo_url: None,
            allowed_server_ips: vec![],
            trust: 1.0,
        };
        assert_eq!(
            cfg.wizden_base().as_deref(),
            Some("https://auth.spacestation14.com/")
        );
        cfg.wizden_url = None;
        assert_eq!(cfg.wizden_base(), None);
        cfg.wizden_url = Some("  ".into());
        assert_eq!(cfg.wizden_base(), None);
    }
}
