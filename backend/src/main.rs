#![forbid(unsafe_code)]

use auth::{CorsConfig, OidcConfig};
use rocket::fairing::{Fairing, Info, Kind};
use rocket::figment::value::Value;
use rocket::fs::FileServer;
use rocket::http::Header;
use rocket::{Request, Response};
use rocket::{
    fairing::AdHoc,
    figment::{
        Figment,
        providers::{Format, Serialized, Toml},
    },
};
use rocket_db_pools::{Database, sqlx::MySqlPool};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::auth::OidcClient;
use crate::authentik::AuthentikConfig;
use crate::openapi::ApiDoc;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

#[macro_use]
extern crate rocket;

/// Check for --openapi flag (sync, no runtime needed)
fn check_openapi_json_flag() -> bool {
    let args: Vec<String> = std::env::args().collect();

    if args.contains(&"--openapi".to_string()) {
        let doc = ApiDoc::openapi();
        println!("{}", doc.to_pretty_json().unwrap());
        return true;
    }

    false
}

fn should_serve_docs_only() -> bool {
    std::env::args().any(|arg| arg == "--serve-docs")
}

fn build_docs_server() -> rocket::Rocket<rocket::Build> {
    eprintln!("Starting OpenAPI documentation server...");
    eprintln!("Swagger UI: http://localhost:8000/swagger-ui/");
    eprintln!("OpenAPI JSON: http://localhost:8000/api-docs/openapi.json");

    rocket::build()
        .configure(rocket::Config {
            port: 8000,
            address: std::net::Ipv4Addr::new(127, 0, 0, 1).into(),
            ..rocket::Config::default()
        })
        .mount(
            "/",
            SwaggerUi::new("/swagger-ui/<_..>").url("/api-docs/openapi.json", ApiDoc::openapi()),
        )
}

mod achievements;
mod admin;
mod appeal;
mod auth;
mod authentik;
mod byond;
mod connections;
mod discord;
mod logging;
mod new_players;
mod openapi;
mod player;
mod spa;
mod ss14auth;
mod steam;
mod stickyban;
mod ticket;
mod token;
mod twitch;
mod twofactor;
mod user_settings;
mod utils;
mod whitelist;

/// CORS fairing with configurable allowed origin
pub struct Cors {
    allowed_origin: String,
}

impl Cors {
    pub fn new(allowed_origin: String) -> Self {
        Self { allowed_origin }
    }
}

#[rocket::async_trait]
impl Fairing for Cors {
    fn info(&self) -> Info {
        Info {
            name: "Add CORS headers to responses",
            kind: Kind::Response,
        }
    }

    async fn on_response<'r>(&self, _request: &'r Request<'_>, response: &mut Response<'r>) {
        response.set_header(Header::new(
            "Access-Control-Allow-Origin",
            self.allowed_origin.clone(),
        ));
        response.set_header(Header::new(
            "Access-Control-Allow-Methods",
            "POST, GET, PATCH, DELETE, OPTIONS",
        ));
        response.set_header(Header::new("Access-Control-Allow-Headers", "*"));
        response.set_header(Header::new("Access-Control-Allow-Credentials", "true"));
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ServerConfig {
    pub name: String,
    pub host: String,
    pub auth: String,
    #[serde(default)]
    pub refresh_admins: bool,
    pub recommended_byond_version: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct TopicConfig {
    servers: Vec<ServerConfig>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct LoggingConfig {
    webhook: String,
    user_manager_webhook: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct ApiAuthConfig {
    /// Bearer token for API authorization (alternative to session-based auth)
    token: String,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct ServerRoleConfig {
    #[serde(default)]
    pub roles_to_add: Vec<String>,
    #[serde(default)]
    pub roles_to_remove: Vec<String>,
    /// minimum playtime in minutes required to be eligible for role changes.
    /// if the user has a database discord link, this requirement is bypassed.
    #[serde(default)]
    pub minimum_playtime_minutes: Option<i32>,
    /// mapping of whitelist status strings (e.g., "WHITELIST_SYNTHETIC") to role IDs.
    /// when a player has a whitelist_status containing one of these strings (separated by |),
    /// the corresponding roles will be added on link and removed on unlink.
    #[serde(default)]
    pub whitelist_roles: std::collections::HashMap<String, Vec<String>>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct DiscordBotConfig {
    pub token: String,
    /// mapping of server (guild) IDs to role configuration for link events
    /// on unlink events, the inverse is applied (roles_to_add are removed, roles_to_remove are added)
    #[serde(default)]
    pub link_role_changes: std::collections::HashMap<String, ServerRoleConfig>,
    /// primary guild ID for checking Discord bans in the appeal system
    pub primary_guild_id: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(crate = "rocket::serde")]
#[derive(Default)]
struct Config {
    topic: Option<TopicConfig>,
    logging: Option<LoggingConfig>,
    oidc: Option<OidcConfig>,
    cors: Option<CorsConfig>,
    authentik: Option<AuthentikConfig>,
    api_auth: Option<ApiAuthConfig>,
    discord_bot: Option<DiscordBotConfig>,
    steam: Option<steam::SteamConfig>,
    ss14auth: Option<ss14auth::Ss14AuthConfig>,
    byond_hashes: Option<std::collections::HashMap<String, String>>,
}

#[derive(Database)]
#[database("cmdb")]
pub struct Cmdb(MySqlPool);

#[derive(Database)]
#[database("cmapi")]
pub struct Cmapi(MySqlPool);

fn main() {
    if check_openapi_json_flag() {
        return;
    }

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        if should_serve_docs_only() {
            let _ = build_docs_server().launch().await;
        } else {
            let _ = build_rocket().await.launch().await;
        }
    });
}

async fn build_rocket() -> rocket::Rocket<rocket::Build> {
    let figment = Figment::from(rocket::Config::default())
        .merge(Serialized::defaults(Config::default()))
        .merge(Toml::file("Rocket.toml").nested())
        .merge(Toml::file("Api.toml"));

    let base_url: String = match figment.find_value("host.base_url") {
        Ok(value) => match value {
            Value::String(_, val) => val,
            _ => panic!("base_url must be a string."),
        },
        Err(_) => "/api".to_string(),
    };

    let config: Config = figment.extract().expect("Failed to extract configuration");

    let allowed_origin = config
        .cors
        .as_ref()
        .map(|c| c.allowed_origin.clone())
        .unwrap_or_else(|| {
            if cfg!(debug_assertions) {
                "*".to_string()
            } else {
                panic!("CORS allowed_origin must be configured in Api.toml for production")
            }
        });

    // Initialize OIDC client if configured (not required in debug mode)
    let oidc_client = if let Some(oidc_config) = config.oidc.clone() {
        match auth::init_oidc_client(oidc_config).await {
            Ok(client) => Some(Arc::new(client)),
            Err(e) => {
                if cfg!(debug_assertions) {
                    eprintln!("Warning: Failed to initialize OIDC client: {}", e);
                    eprintln!("Continuing in debug mode without OIDC...");
                    None
                } else {
                    panic!("Failed to initialize OIDC client: {}", e);
                }
            }
        }
    } else if cfg!(debug_assertions) {
        eprintln!("Warning: OIDC not configured, running in debug mode");
        None
    } else {
        panic!("OIDC configuration required in Api.toml for production");
    };

    let mut rocket_builder = rocket::custom(figment)
        .manage(byond::ByondTopic::default())
        .manage(connections::TraceCache::default())
        .attach(Cmdb::init())
        .attach(Cmapi::init())
        .attach(AdHoc::config::<Config>())
        .attach(Cors::new(allowed_origin));

    if let Some(client) = oidc_client {
        rocket_builder = rocket_builder.manage(client);
    } else {
        rocket_builder = rocket_builder.manage(Arc::new(OidcClient::default()))
    }

    rocket_builder
        .mount(
            format!("{base_url}/auth"),
            routes![
                auth::login,
                auth::callback,
                auth::logout,
                auth::refresh,
                auth::userinfo,
            ],
        )
        .mount(
            format!("{}/User", base_url),
            routes![
                player::index,
                player::id,
                player::new_note,
                player::applied_notes,
                player::get_playtime,
                player::get_recent_playtime,
                player::get_total_playtime,
                player::get_vpn_whitelist,
                player::add_vpn_whitelist,
                player::remove_vpn_whitelist,
                player::get_banned_players,
                player::get_ban_history,
                player::get_known_alts,
                player::add_known_alt,
                player::remove_known_alt,
            ],
        )
        .mount(
            format!("{}/Round", base_url),
            routes![byond::round, byond::recent],
        )
        .mount(
            format!("{}/Connections", base_url),
            routes![
                connections::ip,
                connections::cid,
                connections::ckey,
                connections::connection_history_by_cid,
                connections::connection_history_by_ip,
                connections::hwid,
                connections::hwid_by_ckey,
                connections::full_by_all_hwid,
                connections::trace
            ],
        )
        .mount(
            format!("{}/Stickyban", base_url),
            routes![
                stickyban::all_stickybans,
                stickyban::whitelist,
                stickyban::get_matched_cids,
                stickyban::get_matched_ckey,
                stickyban::get_matched_ip,
                stickyban::get_all_cid,
                stickyban::get_all_ckey,
                stickyban::get_all_ip
            ],
        )
        .mount(
            format!("{}/Ticket", base_url),
            routes![ticket::get_tickets_by_round_id, ticket::get_tickets_by_user],
        )
        .mount(
            format!("{base_url}/Whitelist"),
            routes![whitelist::get_all_whitelistees],
        )
        .mount(
            format! {"{}/NewPlayers", base_url},
            routes![new_players::get_new_players],
        )
        .mount(
            format!("{}/TwoFactor", base_url),
            routes![twofactor::twofactor_validate],
        )
        .mount(
            format!("{}/Authentik", base_url),
            routes![
                authentik::add_user_to_group,
                authentik::remove_user_from_group,
                authentik::get_group_members,
                authentik::get_allowed_groups,
                authentik::get_allowed_instances,
                authentik::get_group_admin_ranks,
                authentik::update_group_admin_ranks,
                authentik::get_group_display_name,
                authentik::update_group_display_name,
                authentik::get_user_additional_titles,
                authentik::update_user_additional_titles,
                authentik::get_admin_ranks_export,
                authentik::get_discourse_user_id,
                authentik::webhook_user_unlinked,
                authentik::webhook_user_linked,
                authentik::user_by_uuid_endpoint,
                authentik::user_by_ckey_endpoint,
                authentik::get_user_by_discord_id,
                authentik::search_users,
                authentik::get_my_profile,
                authentik::update_my_profile,
                authentik::unlink_my_source,
                authentik::get_my_player_info,
                authentik::set_chat_banned,
                user_settings::get_my_settings,
                user_settings::delete_my_session,
                user_settings::revoke_my_consent,
                user_settings::delete_my_mfa_device,
                token::get_token_user_info,
            ],
        )
        .mount(
            format!("{}/Discord", base_url),
            routes![
                discord::get_user_by_discord,
                discord::check_verified,
                discord::get_my_profile
            ],
        )
        .mount(
            format!("{}/Appeal", base_url),
            routes![appeal::get_my_bans, appeal::submit_appeal],
        )
        .mount(
            format!("{}/Steam", base_url),
            routes![steam::authenticate, steam::get_my_persona],
        )
        .mount(
            format!("{}/ss14auth", base_url),
            routes![
                ss14auth::identity,
                ss14auth::session_join,
                ss14auth::session_has_joined,
                ss14auth::user_by_ss14_id,
                ss14auth::query_name,
                ss14auth::query_userid
            ],
        )
        .mount(
            format!("{}/ByondHash", base_url),
            routes![byond::byond_hash],
        )
        .mount(
            format!("{}/Achievements", base_url),
            routes![
                achievements::get_achievements,
                achievements::set_achievement
            ],
        )
        .mount(
            format!("{}/Twitch", base_url),
            routes![twitch::get_twitch_id_by_ckey],
        )
        .mount(
            "/",
            if std::path::Path::new("/var/www/static/assets").exists() {
                FileServer::from("/var/www/static/assets").into()
            } else {
                rocket::routes![]
            },
        )
        .mount("/", routes![spa::index, spa::fallback])
        .mount(
            "/swagger-ui",
            SwaggerUi::new("/swagger-ui/<_..>").url("/api-docs/openapi.json", ApiDoc::openapi()),
        )
}
