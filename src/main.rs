//#![allow(unused)]

use std::{collections::HashMap, fs::File, io::Read, net::{IpAddr, SocketAddr}, sync::Arc, time::Duration};
use axum::{body::Body, extract::{ConnectInfo, Path, State}, http::{header, StatusCode}, response::{IntoResponse, Response}, routing::{get, post}, Router};
use anyhow::{anyhow, Result};
use serde::Deserialize;
use tokio::{process::Command, sync::Mutex, time::Instant};

#[derive(Debug, Deserialize)]
struct AppConfig {
    listen_port: u16,
    lease_time: u64,                            /* Number of seconds a lease is valid for */
    grant_action: Vec<String>,
    revoke_action: Vec<String>,
    secret: String,
    redirect_url: String,
}

struct AppState {
    leases: Mutex<HashMap<IpAddr, Instant>>,    /* Value: timestamp when the lease started */
    cfg: AppConfig,
}

async fn execute_action(action: &Vec<String>, ip: &IpAddr) -> Result<()> {
    let status = Command::new(&action[0])
        .args(action.iter().skip(1).collect::<Vec<&String>>())
        .arg(ip.to_string())
        .status()
        .await?;
    if !status.success() {
        Err(anyhow!("Process exited with code {}", status.code().unwrap_or(-1)))
    } else {
        Ok(())
    }
}

async fn get_lease(state: Arc<AppState>, ip: &IpAddr) -> Result<Option<Duration>> {
    let state2 = Arc::clone(&state);
    let leases = state2.leases.lock().await;
    if let Some(lease) = leases.get(ip) {
        let expiry = lease
            .checked_add(Duration::from_secs(state.cfg.lease_time))
            .ok_or_else(|| anyhow!("Invalid lease"))?;
        if let Some(remaining) = expiry.checked_duration_since(Instant::now()) {
            return Ok(Some(remaining));
        } else {
            remove_lease(state, ip).await?;
        }
    }
    Ok(None)
}

async fn add_lease(state: Arc<AppState>, ip: &IpAddr) -> Result<()> {
    let mut leases = state.leases.lock().await;
    match leases.get_mut(ip) {
        Some(lease) => { *lease = Instant::now(); }
        None => {
            leases.insert(ip.clone(), Instant::now());
            execute_action(&state.cfg.grant_action, &ip).await?;
        }
    }
    Ok(())
}

async fn remove_lease(state: Arc<AppState>, ip: &IpAddr) -> Result<()> {
    let mut leases = state.leases.lock().await;
    leases.remove(ip);

    execute_action(&state.cfg.revoke_action, ip).await?;
    Ok(())
}

fn format_duration(d: Duration) -> String {
    if d.as_secs() < 60 {
        return format!("{}s", d.as_secs());
    }

    let m = d.as_secs() / 60;
    if m < 60 {
        format!("{}m", m)
    } else if m < 60 * 24 {
        format!("{}h{}m", m / 60, m % 60)
    } else {
        format!("{}d{}h{}m", m / (60*24), (m % (60*24)) / 60, m % 60)
    }
}

fn internal_server_error(e: impl std::fmt::Display) -> (StatusCode, String) {
    eprintln!("Internal server error: {e}");
    (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error\n".to_string())
}

fn redirect(target: &str) -> Response {
    Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(header::LOCATION, target)
        .body(
            Body::from(format!("Redirecting to {target}...\n"))
        )
        .expect("Failed to create response")
}

fn rickroll(state: Arc<AppState>) -> Response {
    redirect(&state.cfg.redirect_url)
}

async fn index(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>
) -> Result<Response, (StatusCode, String)> {
    /*
     * If access granted, show:
     *  - remaining time
     *  - a button to revoke access
     *  - a button to extend access
     * Else: rickroll the user
     */
    let lease = get_lease(Arc::clone(&state), &addr.ip())
        .await
        .map_err(|e| internal_server_error(e))?;
    if let Some(lease) = lease {
        let body = include_bytes!("../res/index.html");
        let body = String::from_utf8(body.to_vec())
            .map_err(|e| internal_server_error(e))?
            .replace("{{address}}", &addr.ip().to_string())
            .replace("{{remaining}}", &format_duration(lease));
        Ok(Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/html; charset=utf8")
            .body(Body::from(body))
            .map_err(|e| internal_server_error(e))?)
    } else {
        Ok(rickroll(state))
    }
}

async fn lease(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>
) -> Result<Response, (StatusCode, String)> {
    let lease = get_lease(Arc::clone(&state), &addr.ip())
        .await
        .map_err(|e| internal_server_error(e))?;
    if let Some(lease) = lease {
        let body = format!("{{\"lease\": {}}}", lease.as_secs());
        Ok(Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::CACHE_CONTROL, "no-store")
            .body(Body::from(body))
            .map_err(|e| internal_server_error(e))?)
    } else {
        Ok(rickroll(state))
    }
}

async fn knock(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(path): Path<String>,
) -> Result<Response, (StatusCode, String)> {
    if path != state.cfg.secret && path != format!("{}/", state.cfg.secret) {
        return Ok(rickroll(state));
    }

    add_lease(state, &addr.ip())
        .await
        .map_err(|e| internal_server_error(e))?;
    Ok((StatusCode::SEE_OTHER, [(header::LOCATION, "/")]).into_response())
}

async fn revoke(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    remove_lease(state, &addr.ip())
        .await
        .map_err(|e| internal_server_error(e))?;

    Ok(( StatusCode::SEE_OTHER, [(header::LOCATION, "/")] ))
}

fn get_default_cfg_file() -> String {
    /*
     * Config file search path:
     *  $PWD/config.cfg
     *  ${XDG_CONFIG_HOME:$HOME/.config}/portknock/config.cfg
     *  /etc/portknock/config.cfg
     *  /etc/portknock.cfg
     */
    fn exists(p: impl AsRef<std::path::Path>) -> bool {
        if let Ok(ret) = std::fs::exists(p) {
            ret
        } else {
            false
        }
    }

    if let Ok(cwd) = std::env::current_dir() {
        if exists(&cwd.join("config.cfg")) {
            if let Some(s) = cwd.join("config.cfg").to_str() {
                return s.to_string();
            }
        }
    }

    let xdg_config_home = std::env::var("XDG_CONFIG_HOME")
        .unwrap_or_else(|_| {
            if let Ok(home) = std::env::var("HOME") {
                format!("{home}/.config")
            } else {
                "/etc".to_string()
            }
        });
    if exists(&format!("{xdg_config_home}/portknock/config.cfg")) {
        return format!("{xdg_config_home}/portknock/config.cfg");
    }

    if exists("/etc/portknock/config.cfg") {
        return "/etc/portknock/config.cfg".to_string();
    }

    return "/etc/portknock.cfg".to_string();
}

fn read_config<T>(p: impl AsRef<std::path::Path>) -> Result<T>
where
    T: serde::de::DeserializeOwned,
{
    let mut f = File::open(p)?;
    let mut buf = String::new();
    f.read_to_string(&mut buf)?;
    drop(f);

    Ok(toml::from_str::<T>(&buf)?)
}

#[tokio::main]
async fn main() {
    use clap::{command, arg};

    let default_cfg_file = get_default_cfg_file();
    let args = command!()
        .arg(arg!(-c --"config-file" <FILENAME> "Configuration file").default_value(&default_cfg_file))
        .get_matches();

    let cfg_file = args.get_one::<String>("config-file").expect("Unexpected None");
    let cfg: AppConfig = read_config(cfg_file)
        .expect("Failed to read configuration file");

    println!("Configuration: {cfg:?}");
    let state = Arc::new(AppState {
        leases: Mutex::new(HashMap::new()),
        cfg,
    });
    let app = Router::new()
        .route("/:secret", get(knock))
        .route("/revoke", get(revoke))
        .route("/revoke", post(revoke))
        .route("/lease", get(lease))
        .fallback(get(index))
        .with_state(Arc::clone(&state));
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", state.cfg.listen_port))
        .await
        .expect("Listener creation failed");
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .expect("Server creation failed");
}

#[cfg(test)]
mod tests {
    use std::time::Duration;
    use super::format_duration;

    #[test]
    fn test_format_duration() {
        let _s = 1;
        let m = 60;
        let h = m * 60;
        let _d = h * 24;

        let data = [
            58,
            59,
            60,
            61,
            (2*h)+(30*m)+30,
            24*h,
            (24*h)+(6*h)+(30*m),
        ];
        for t in data {
            println!("{t}s --> {}", format_duration(Duration::from_secs(t)));
        }
    }
}

