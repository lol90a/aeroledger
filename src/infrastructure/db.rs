use deadpool_postgres::{Config, Pool, PoolError, Runtime};
use tokio_postgres::NoTls;

pub type DbPool = Pool;
pub type DbError = PoolError;

pub fn init_pool(database_url: &str) -> DbPool {
    if database_url.trim().is_empty() {
        log::error!("DATABASE_URL is empty");
        std::process::exit(1);
    }

    let mut cfg = Config::new();

    if database_url.starts_with("postgres://") || database_url.starts_with("postgresql://") {
        cfg.url = Some(database_url.to_string());
    } else {
        for part in database_url.split_whitespace() {
            if let Some((key, val)) = part.split_once('=') {
                match key {
                    "host" => cfg.host = Some(val.to_string()),
                    "port" => cfg.port = val.parse().ok(),
                    "dbname" => cfg.dbname = Some(val.to_string()),
                    "user" => cfg.user = Some(val.to_string()),
                    "password" => cfg.password = Some(val.to_string()),
                    _ => {}
                }
            }
        }
    }

    cfg.create_pool(Some(Runtime::Tokio1), NoTls)
        .unwrap_or_else(|e| {
            log::error!("Failed to create connection pool: {}", e);
            std::process::exit(1);
        })
}

pub async fn run_migrations(pool: &DbPool) -> Result<(), Box<dyn std::error::Error>> {
    let conn = pool.get().await?;
    conn.batch_execute(include_str!("../../migrations/complete_schema.sql"))
        .await?;
    log::info!("Database migrations applied successfully.");
    Ok(())
}

/// Host and port a Postgres URL points at, for diagnostics.
///
/// **Credentials are dropped, deliberately.** A connection failure is precisely
/// the moment someone copies a log into a chat window or an issue, and a
/// `DATABASE_URL` carries a password in the middle of it. The host and port are
/// the only parts that help, and they are the only parts that come back.
///
/// Returns `None` for a form it does not recognise rather than guessing: a
/// half-parsed address in an error message sends the reader somewhere that was
/// never tried.
pub fn connection_target(database_url: &str) -> Option<String> {
    let url = database_url.trim();

    if let Some(rest) = url
        .strip_prefix("postgresql://")
        .or_else(|| url.strip_prefix("postgres://"))
    {
        // Everything before the last '@' is credentials. Last, not first: a
        // password may legitimately contain one.
        let after_credentials = rest.rsplit_once('@').map_or(rest, |(_, after)| after);
        let host_port = after_credentials
            .split(['/', '?'])
            .next()
            .filter(|s| !s.is_empty())?;
        return Some(host_port.to_string());
    }

    // The key=value form `init_pool` also accepts.
    let mut host = None;
    let mut port = None;
    for part in url.split_whitespace() {
        match part.split_once('=') {
            Some(("host", value)) => host = Some(value),
            Some(("port", value)) => port = Some(value),
            _ => {}
        }
    }
    let host = host?;
    Some(match port {
        Some(port) => format!("{}:{}", host, port),
        None => host.to_string(),
    })
}

/// True when an error chain bottoms out in "nothing is listening there".
///
/// The distinction matters because the remedy is different. A refused
/// connection means the server is not running; a rejected password means it is,
/// and the credentials are wrong. Telling someone to start a database that is
/// already up wastes their time and teaches them to ignore the message.
pub fn looks_like_connection_refused(error: &(dyn std::error::Error + 'static)) -> bool {
    let mut current = Some(error);
    while let Some(err) = current {
        if let Some(io) = err.downcast_ref::<std::io::Error>() {
            if matches!(
                io.kind(),
                std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::TimedOut
            ) {
                return true;
            }
        }
        current = err.source();
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The security-relevant one. A connection failure is when logs get pasted
    /// into chat windows, so the password must not be in the message.
    #[test]
    fn the_target_never_carries_credentials() {
        let target = connection_target("postgresql://aeroledger:hunter2@localhost:5435/aeroledger")
            .expect("parsed");
        assert_eq!(target, "localhost:5435");
        assert!(!target.contains("hunter2"));
        assert!(!target.contains("aeroledger:"));
    }

    #[test]
    fn a_password_containing_an_at_sign_does_not_truncate_the_host() {
        // Splitting on the FIRST '@' would report the host as part of the
        // password and send the reader to an address nobody tried.
        let target = connection_target("postgres://user:p@ss@db.internal:6543/app").unwrap();
        assert_eq!(target, "db.internal:6543");
    }

    #[test]
    fn handles_both_url_schemes_and_a_missing_database() {
        assert_eq!(
            connection_target("postgres://u:p@127.0.0.1:5432/db"),
            Some("127.0.0.1:5432".to_string())
        );
        assert_eq!(
            connection_target("postgresql://u:p@127.0.0.1:5432"),
            Some("127.0.0.1:5432".to_string())
        );
    }

    #[test]
    fn strips_query_parameters() {
        assert_eq!(
            connection_target("postgres://u:p@host:5432/db?sslmode=require"),
            Some("host:5432".to_string())
        );
    }

    #[test]
    fn reads_the_key_value_form_init_pool_also_accepts() {
        assert_eq!(
            connection_target("host=localhost port=5435 dbname=aeroledger password=secret"),
            Some("localhost:5435".to_string())
        );
        assert_eq!(
            connection_target("host=localhost dbname=aeroledger"),
            Some("localhost".to_string())
        );
    }

    #[test]
    fn returns_nothing_for_a_form_it_does_not_understand() {
        // Better silent than wrong: a half-parsed address in an error message
        // sends the reader to somewhere that was never tried.
        assert_eq!(connection_target(""), None);
        assert_eq!(connection_target("not a url"), None);
        assert_eq!(connection_target("postgres://"), None);
    }

    #[test]
    fn recognises_a_refused_connection_through_a_wrapper() {
        // The real error arrives wrapped by deadpool and tokio-postgres, so the
        // check has to walk the chain rather than inspect the top.
        #[derive(Debug)]
        struct Wrapper(std::io::Error);
        impl std::fmt::Display for Wrapper {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "error connecting to server")
            }
        }
        impl std::error::Error for Wrapper {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                Some(&self.0)
            }
        }

        let refused = Wrapper(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "target machine actively refused it",
        ));
        assert!(looks_like_connection_refused(&refused));
    }

    #[test]
    fn does_not_mistake_a_rejected_password_for_a_stopped_server() {
        // Telling someone to start a database that is already running wastes
        // their time and teaches them to ignore the message.
        #[derive(Debug)]
        struct AuthFailed;
        impl std::fmt::Display for AuthFailed {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "password authentication failed")
            }
        }
        impl std::error::Error for AuthFailed {}

        assert!(!looks_like_connection_refused(&AuthFailed));
    }
}
