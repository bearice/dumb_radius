use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{io, process};

use async_trait::async_trait;
use clap::{App, Arg, ArgMatches};
use hmac::*;
use log::info;
use radius::client::Client;
use radius::core::packet::Packet;
use sha2::Sha256;
use tokio::net::UdpSocket;
use tokio::signal;

use radius::core::code::Code;
use radius::core::request::Request;
use radius::core::rfc2865;
use radius::server::{RequestHandler, SecretProvider, SecretProviderError, Server};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
type HmacSha256 = Hmac<Sha256>;

#[tokio::main]
async fn main() {
    let args = App::new(env!("CARGO_BIN_NAME"))
        .version(VERSION)
        .arg(
            Arg::with_name("bind")
                .short("b")
                .long("bind")
                .help("radius bind address")
                .default_value("0.0.0.0")
                .validator(|s| {
                    if s.parse::<IpAddr>().is_ok() {
                        Ok(())
                    } else {
                        Err("invalid bind address".to_string())
                    }
                })
                .env("DUMB_RADIUS_BIND")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("port")
                .short("p")
                .long("port")
                .validator(|s| {
                    if s.parse::<u16>().is_ok() {
                        Ok(())
                    } else {
                        Err("port must be a number".to_string())
                    }
                })
                .help("radius port")
                .default_value("1812")
                .env("DUMB_RADIUS_PORT")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("secret")
                .short("s")
                .long("secret")
                .help("radius secret")
                .default_value("12345678")
                .env("DUMB_RADIUS_SECRET")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("pwd_key")
                .short("k")
                .long("key")
                .help("password key")
                .default_value("whosyourdaddy")
                .env("DUMB_RADIUS_KEY")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("pwd_len")
                .short("l")
                .long("len")
                .help("password length")
                .default_value("32")
                .validator(|s| {
                    if s.parse::<usize>().ok().filter(|x| *x > 8).is_some() {
                        Ok(())
                    } else {
                        Err("password length must be a number greater than 8".to_string())
                    }
                })
                .env("DUMB_RADIUS_PWD_LEN")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("acct_port")
                .short("a")
                .long("acct-port")
                .help("radius accounting port")
                .default_value("1813")
                .env("DUMB_RADIUS_ACCT_PORT")
                .validator(|s| {
                    if s.parse::<u16>().is_ok() {
                        Ok(())
                    } else {
                        Err("port must be a number".to_string())
                    }
                })
                .takes_value(true),
        )
        .subcommand(
            App::new("genpwd")
                .about("generate passwords for testing")
                .arg(
                    Arg::with_name("expires")
                        .short("e")
                        .help("password expires time")
                        .default_value("30d")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("user")
                        .short("u")
                        .help("user name")
                        .default_value("test")
                        .takes_value(true),
                ),
        )
        .subcommand(
            App::new("test")
                .about("test remote server")
                .arg(
                    Arg::with_name("user")
                        .short("u")
                        .help("user name")
                        .default_value("test")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("pass")
                        .short("P")
                        .help("password (default: auto generate)")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("remote")
                        .short("r")
                        .help("remote server")
                        .default_value("127.0.0.1:1812")
                        .takes_value(true),
                ),
        )
        .subcommand(
            App::new("verify")
                .about("verify username and password")
                .arg(
                    Arg::with_name("user")
                        .short("u")
                        .help("user name")
                        .required(true)
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("pass")
                        .short("P")
                        .help("password")
                        .required(true)
                        .takes_value(true),
                ),
        )
        .get_matches();

    let log_level = args.value_of("log-level").unwrap_or("info");
    env_logger::init_from_env(env_logger::Env::default().default_filter_or(log_level));

    let pwd_len = args.value_of("pwd_len").unwrap().parse::<usize>().unwrap();
    let pwd_key = args.value_of("pwd_key").unwrap();
    let hmac = HmacSha256::new_from_slice(pwd_key.as_bytes()).expect("HMAC init");
    let bind = args.value_of("bind").unwrap();
    let port = args.value_of("port").unwrap().parse().unwrap();
    let acct_port = args.value_of("acct_port").unwrap().parse().unwrap();
    let secret = args.value_of("secret").unwrap().to_string();

    if let Some(m) = args.subcommand_matches("genpwd") {
        return cmd_genpwd(m, hmac, pwd_len);
    }

    if let Some(m) = args.subcommand_matches("test") {
        return cmd_test(m, hmac, pwd_len, secret).await;
    }

    if let Some(m) = args.subcommand_matches("verify") {
        return cmd_verify(m, hmac, pwd_len);
    }

    let handler = MyRequestHandler { hmac, len: pwd_len };
    let secret = MySecretProvider { secret };

    if acct_port > 0 {
        let secret = secret.clone();
        let bind = bind.to_string();
        tokio::spawn(async move {
            let acct_handler = AcctRequestHandler;
            let mut server = Server::listen(&bind, acct_port, acct_handler, secret)
                .await
                .unwrap();
            info!(
                "acct_server ready: {}",
                server.get_listen_address().unwrap()
            );
            let result = server.run(signal::ctrl_c()).await;
            info!("acct_server finished: {:?}", result);
        });
    }

    // start UDP listening
    let mut server = Server::listen(bind, port, handler, secret).await.unwrap();
    info!("server ready: {}", server.get_listen_address().unwrap());
    let result = server.run(signal::ctrl_c()).await;
    info!("server finished: {:?}", result);
    if result.is_err() {
        process::exit(1);
    }
}

fn cmd_verify(m: &ArgMatches<'_>, hmac: HmacSha256, pwd_len: usize) {
    let user = m.value_of("user").expect("user not defined");
    let password = m.value_of("pass").expect("password not defined");
    if verify_pwd(hmac, pwd_len, user, password) {
        process::exit(0);
    } else {
        process::exit(1);
    }
}

async fn cmd_test(m: &ArgMatches<'_>, hmac: HmacSha256, pwd_len: usize, secret: String) {
    let user = m.value_of("user").expect("user not defined");
    let password = m
        .value_of("pass")
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| genpwd(hmac, pwd_len, user, get_ts(Some(Duration::from_secs(3600)))));
    println!("User: {}\r\nPassword: {}", user, password);
    let remote_addr: SocketAddr = m.value_of("remote").unwrap().parse().unwrap();
    let mut req_packet = Packet::new(Code::AccessRequest, secret.as_bytes());
    rfc2865::add_user_name(&mut req_packet, user);
    rfc2865::add_user_password(&mut req_packet, password.as_bytes()).unwrap();
    let client = Client::new(Some(Duration::from_secs(3)), Some(Duration::from_secs(5)));
    let res = client.send_packet(&remote_addr, &req_packet).await;
    info!("response: {:?}", res);
}

fn cmd_genpwd(m: &ArgMatches, hmac: HmacSha256, pwd_len: usize) {
    let user = m.value_of("user").expect("user not defined");
    let expires = m.value_of("expires").and_then(parse_duration);
    let ts = get_ts(expires);
    let pwd = genpwd(hmac, pwd_len, user, ts);
    println!("User: {}\r\nPassword: {}", user, pwd);
}

struct AcctRequestHandler;

#[async_trait]
impl RequestHandler<(), io::Error> for AcctRequestHandler {
    async fn handle_radius_request(
        &self,
        conn: &UdpSocket,
        req: &Request,
    ) -> Result<(), io::Error> {
        let req_packet = req.get_packet();
        let code = Code::AccountingResponse;
        info!("Accounting-Request received: {:?}", req_packet);
        info!("response => {:?} to {}", code, req.get_remote_addr());
        conn.send_to(
            &req_packet.make_response_packet(code).encode().unwrap(),
            req.get_remote_addr(),
        )
        .await?;
        Ok(())
    }
}

struct MyRequestHandler {
    hmac: HmacSha256,
    len: usize,
}

#[async_trait]
impl RequestHandler<(), io::Error> for MyRequestHandler {
    async fn handle_radius_request(
        &self,
        conn: &UdpSocket,
        req: &Request,
    ) -> Result<(), io::Error> {
        let req_packet = req.get_packet();

        fn check(hmac: HmacSha256, len: usize, req: &Packet) -> Option<bool> {
            let user = rfc2865::lookup_user_name(req)?.ok()?;
            let password = String::from_utf8(rfc2865::lookup_user_password(req)?.ok()?).ok()?;

            Some(verify_pwd(hmac, len, &user, &password))
        }

        let code = if Some(true) == check(self.hmac.clone(), self.len, req_packet) {
            Code::AccessAccept
        } else {
            Code::AccessReject
        };

        info!("response => {:?} to {}", code, req.get_remote_addr());

        conn.send_to(
            &req_packet.make_response_packet(code).encode().unwrap(),
            req.get_remote_addr(),
        )
        .await?;
        Ok(())
    }
}

#[derive(Clone)]
struct MySecretProvider {
    secret: String,
}

impl SecretProvider for MySecretProvider {
    fn fetch_secret(&self, _remote_addr: SocketAddr) -> Result<Vec<u8>, SecretProviderError> {
        Ok(self.secret.as_bytes().to_vec())
    }
}

fn get_ts(offset: Option<Duration>) -> u64 {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let offset = offset.unwrap_or_else(|| Duration::from_secs(0));
    let ts = now + offset;
    ts.as_secs()
}

fn parse_duration(s: &str) -> Option<Duration> {
    let s = s.to_ascii_lowercase();
    let unit = s.chars().last()?;
    let (val, unit) = if unit.is_numeric() {
        (s.as_str().parse().ok()?, 's')
    } else {
        (s[0..s.len() - 1].parse().ok()?, unit)
    };
    let val = match unit {
        's' => val,
        'h' => val * 3600,
        'd' => val * 3600 * 24,
        _ => return None,
    };
    Some(Duration::from_secs(val))
}

fn genpwd(mut hmac: HmacSha256, len: usize, user: &str, ts: u64) -> String {
    let rawpwd = format!("{:08x}{}", ts, user);
    hmac.update(rawpwd.as_bytes());
    let hash = hmac.finalize().into_bytes();
    let mut pwd = format!("{:08x}{}", ts, base64::encode(hash));
    pwd.truncate(len);
    pwd
}

fn verify_pwd(hmac: HmacSha256, len: usize, user: &str, pwd: &str) -> bool {
    let raw = if pwd.len() == len { Some(pwd) } else { None };
    let ts = raw.and_then(|pwd| u64::from_str_radix(&pwd[0..8], 16).ok());
    let ts = ts.filter(|ts| *ts > get_ts(None));
    let chk = ts
        .map(move |ts| genpwd(hmac, len, user, ts))
        .filter(|chk| pwd == chk);
    chk.is_some()
}

#[cfg(test)]
mod test {
    use std::time::Duration;

    #[test]
    fn test_parse_duration() {
        assert_eq!(super::parse_duration("1s"), Some(Duration::from_secs(1)));
        assert_eq!(super::parse_duration("2h"), Some(Duration::from_secs(7200)));
        assert_eq!(
            super::parse_duration("3d"),
            Some(Duration::from_secs(3 * 3600 * 24))
        );
        assert_eq!(super::parse_duration("100"), Some(Duration::from_secs(100)));
        assert_eq!(super::parse_duration("1s1"), None);
    }
}
