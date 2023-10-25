use std::borrow::Cow;
use std::env;
use std::time::{SystemTime, UNIX_EPOCH};

use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use base64ct::{Base64, Encoding};
use log;
use schema::auth::{
    AuthenticateRequest, LoginRequest, LoginResponse, LogoutRequest, RefreshRequest,
    RefreshResponse, RegisterRequest, RegisterResponse,
};
use schema::proto::auth::auth_server::{Auth, AuthServer};
use schema::ToFromProto;
use sha2::Digest;
use sqlx::postgres::PgPoolOptions;
use tonic::transport::Server;
use tonic::{Request, Response, Status};
use ulid::Ulid;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv::dotenv().ok();
    env_logger::init();

    let manager = bb8_memcached::MemcacheConnectionManager::new(env::var("CACHE_URI")?)?;
    let cache = bb8::Pool::builder().max_size(15).build(manager).await?;
    log::info!("connected to cache");

    let db = PgPoolOptions::new()
        .max_connections(5)
        .connect(&env::var("DATABASE_URL")?)
        .await?;
    log::info!("connected to database");

    let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter
        .set_serving::<AuthServer<AuthService>>()
        .await;
    log::info!("started health reporter");

    let addr = env::var("AUTH_SOCKET")
        .unwrap_or_else(|_| "0.0.0.0:50051".to_string())
        .parse()?;
    let auth = AuthServer::new(AuthService {
        db,
        cache,
        session_expiry_ms: env::var("SESSION_EXPIRY_MS")?.parse()?,
        refresh_expiry_ms: env::var("REFRESH_EXPIRY_MS")?.parse()?,
        pepper: env::var("PEPPER")?,
    });

    Server::builder()
        .add_service(health_service)
        .add_service(auth)
        .serve(addr)
        .await?;

    Ok(())
}

struct AuthService {
    db: sqlx::Pool<sqlx::Postgres>,
    cache: bb8::Pool<bb8_memcached::MemcacheConnectionManager>,
    session_expiry_ms: u128,
    refresh_expiry_ms: u128,
    pepper: String,
}

trait Hashable {
    fn as_bytes<'a>(&'a self) -> Cow<'a, [u8]>;
}

impl Hashable for String {
    fn as_bytes<'a>(&'a self) -> Cow<'a, [u8]> {
        Cow::Borrowed(self.as_bytes())
    }
}

impl Hashable for Ulid {
    fn as_bytes<'a>(&'a self) -> Cow<'a, [u8]> {
        Cow::Owned(self.to_bytes().to_vec())
    }
}

impl AuthService {
    /// Returns hash of the input including environment supplied pepper
    async fn pepper_hash<T: Hashable + Send + 'static>(&self, input: T) -> Result<String, Status> {
        let pepper = SaltString::from_b64(&self.pepper).map_err(|_| Status::internal("pepper"))?; // yum yum

        tokio::task::spawn_blocking(move || {
            Ok::<String, Status>(
                Argon2::default()
                    .hash_password(input.as_bytes().as_ref(), &pepper)
                    .map_err(|_| Status::internal("hash"))?
                    .to_string(),
            )
        })
        .await
        .map_err(|_| Status::unauthenticated("invalid"))?
    }

    /// Returns the password hash to be persisted from a given password
    async fn password_hash(&self, password: String) -> Result<String, Status> {
        let peppered = self.pepper_hash(password).await?;
        tokio::task::spawn_blocking(move || {
            let salt = SaltString::generate(&mut rand::thread_rng());
            let password_hash = Argon2::default()
                .hash_password(peppered.as_bytes(), &salt)
                .map_err(|_| Status::internal("hash"))?
                .to_string();

            Ok::<String, Status>(password_hash)
        })
        .await
        .map_err(|_| Status::internal("hash"))?
    }

    /// Verifies the supplied password against the expected (persisted) hash
    async fn verify_password(&self, password: String, expected: String) -> Result<(), Status> {
        let peppered = self.pepper_hash(password).await?;
        tokio::task::spawn_blocking(move || {
            let expected = PasswordHash::new(&expected).map_err(|_| Status::internal("hash"))?;

            Argon2::default()
                .verify_password(peppered.as_bytes(), &expected)
                .map_err(|_| Status::unauthenticated("invalid"))?;
            Ok::<(), Status>(())
        })
        .await
        .map_err(|_| Status::internal("hash"))?
    }
}

#[tonic::async_trait]
impl Auth for AuthService {
    /// Verifies that this session is valid for the specified user.
    async fn authenticate(
        &self,
        req: Request<schema::proto::auth::AuthenticateRequest>,
    ) -> Result<Response<()>, Status> {
        log::info!("authenticating");
        let req = req.into_inner();
        let AuthenticateRequest {
            user_id,
            session_token,
        } = AuthenticateRequest::try_from_proto(req).ok_or(Status::internal("decode"))?;

        if SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Status::internal("time"))?
            .as_millis()
            - session_token.timestamp_ms() as u128
            > self.session_expiry_ms
        {
            return Err(Status::unauthenticated("token expired"));
        }

        // Fast hash for memcache read/write
        let sha = Base64::encode_string(
            &sha2::Sha256::new()
                .chain_update(user_id.as_bytes())
                .chain_update(session_token.as_bytes())
                .chain_update(self.pepper.as_bytes())
                .finalize(),
        );
        let mut cache = self.cache.get().await;
        if let Err(e) = cache.as_ref() {
            log::warn!("cache connection failure: {}", e);
        }

        if let Ok(fut) = cache.as_mut().map(|cache| cache.get(&sha)) {
            if fut.await.is_ok() {
                log::trace!("auth cache hit");
                return Ok(Response::new(()));
            }
        }

        // Slow hash persisted to database
        let session_token_hash = self.pepper_hash(session_token).await?;
        let _ = sqlx::query!(
            r#"
            SELECT user_id
            FROM user_sessions
            WHERE user_id = $1
            AND session_token_hash = $2;
            "#,
            user_id.to_string(),
            session_token_hash
        )
        .fetch_one(&self.db)
        .await
        .map_err(|_| Status::unauthenticated("invalid credentials"))?;

        // Write auth SHA to cache
        if let Ok(cache) = cache.as_mut() {
            let _ = cache.set(&sha, &[], 0).await;
        }

        Ok(Response::new(()))
    }

    /// Creates a new user with the given username and password.
    async fn register(
        &self,
        req: Request<schema::proto::auth::RegisterRequest>,
    ) -> Result<Response<schema::proto::auth::RegisterResponse>, Status> {
        log::info!("registration");
        let req = req.into_inner();
        let RegisterRequest { username, password } =
            RegisterRequest::try_from_proto(req).ok_or(Status::internal("decode"))?;

        log::info!("processing registration");
        let user_id = Ulid::new();
        let password_hash = self.password_hash(password).await?;

        sqlx::query!(
            r#"
            INSERT INTO users (
                id,
                username,
                password_hash
            ) VALUES ($1, $2, $3)
            "#,
            user_id.to_string(),
            username,
            password_hash
        )
        .execute(&self.db)
        .await
        .map_err(|_| Status::aborted("insert"))?;

        let session_token = Ulid::new();
        let refresh_token = Ulid::new();
        let origin = Ulid::new();

        let session_token_hash = self.pepper_hash(session_token).await?;
        let refresh_token_hash = self.pepper_hash(refresh_token).await?;
        sqlx::query!(
            r#"
            INSERT INTO user_sessions (
                session_token_hash,
                refresh_token_hash,
                user_id,
                origin
            ) VALUES ($1, $2, $3, $4)
            "#,
            session_token_hash,
            refresh_token_hash,
            user_id.to_string(),
            origin.to_string()
        )
        .execute(&self.db)
        .await
        .map_err(|_| Status::aborted("insert"))?;

        log::info!("registration successful");
        Ok(Response::new(
            RegisterResponse {
                user_id,
                session_token,
                refresh_token,
            }
            .into_proto(),
        ))
    }

    /// Creates a new session for user with the given username & password.
    async fn login(
        &self,
        req: Request<schema::proto::auth::LoginRequest>,
    ) -> Result<Response<schema::proto::auth::LoginResponse>, Status> {
        log::info!("login");
        let req = req.into_inner();
        let LoginRequest { username, password } =
            LoginRequest::try_from_proto(req).ok_or(Status::internal("decode"))?;

        log::info!("processing login");
        let row = sqlx::query!(
            r#"
            SELECT id, password_hash
            FROM users
            WHERE username = $1
            "#,
            username.to_string(),
        )
        .fetch_one(&self.db)
        .await
        .map_err(|_| Status::unauthenticated("invalid"))?;

        let user_id = Ulid::from_string(&row.id).map_err(|_| Status::unauthenticated("invalid"))?;
        self.verify_password(password, row.password_hash).await?;

        let session_token = Ulid::new();
        let refresh_token = Ulid::new();
        let session_token_hash = self.pepper_hash(session_token).await?;
        let refresh_token_hash = self.pepper_hash(refresh_token).await?;
        let origin = Ulid::new();
        sqlx::query!(
            r#"
            INSERT INTO user_sessions (
                session_token_hash,
                refresh_token_hash,
                user_id,
                origin
            ) VALUES ($1, $2, $3, $4);
            "#,
            session_token_hash,
            refresh_token_hash,
            user_id.to_string(),
            origin.to_string()
        )
        .execute(&self.db)
        .await
        .map_err(|_| Status::unauthenticated("invalid"))?;
        log::info!("login successful");

        // Prune any user sessions where the refresh token is expired
        let prune_time = chrono::Utc::now().naive_utc()
            - std::time::Duration::from_millis(self.refresh_expiry_ms as u64);
        sqlx::query!(
            r#"
            DELETE FROM user_sessions
            WHERE user_id = $1
            AND created_at < $2;
            "#,
            user_id.to_string(),
            prune_time
        )
        .execute(&self.db)
        .await
        .map_err(|_| Status::unauthenticated("invalid"))?;
        log::info!("pruned sessions");

        Ok(Response::new(
            LoginResponse {
                user_id,
                session_token,
                refresh_token,
            }
            .into_proto(),
        ))
    }

    /// Extends session for the given user if a valid refresh token is supplied.
    /// This service uses rotating refresh tokens, meaning that a new refresh token
    /// is supplied sharing the same origin with every refresh. Only the most recently
    /// provided refresh token for a given login will be able to extend the session.
    /// Attempts to extend the session with outdated refresh tokens are considered suspicious
    /// behavior, and indicate that the user's refresh token has likely been comprimised. Such
    /// attempts are logged and cause all sessions / refresh tokens originating from the same
    /// origin to be invalidated.
    async fn refresh(
        &self,
        req: Request<schema::proto::auth::RefreshRequest>,
    ) -> Result<Response<schema::proto::auth::RefreshResponse>, Status> {
        log::info!("refreshing");
        let req = req.into_inner();
        let RefreshRequest {
            user_id,
            refresh_token,
        } = RefreshRequest::try_from_proto(req).ok_or(Status::internal("decode"))?;

        if SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Status::internal("time"))?
            .as_millis()
            - refresh_token.timestamp_ms() as u128
            > self.refresh_expiry_ms
        {
            return Err(Status::unauthenticated("token expired"));
        }

        // Determine the most recent refresh token with this origin
        let refresh_token_hash = self.pepper_hash(refresh_token).await?;
        let row = sqlx::query!(
            r#"
            SELECT
                refresh_token_hash,
                origin 
            FROM user_sessions
            WHERE origin IN (
                SELECT origin
                FROM user_sessions
                WHERE user_id = $1
                AND refresh_token_hash = $2
            )
            ORDER BY created_at DESC
            LIMIT 1;
            "#,
            user_id.to_string(),
            refresh_token_hash,
        )
        .fetch_one(&self.db)
        .await
        .map_err(|_| Status::unauthenticated("invalid credentials"))?;

        if row.refresh_token_hash != refresh_token_hash {
            log::warn!(
                "suspicious refresh attempt for user id {}, revoking refresh tokens with origin {}",
                user_id,
                row.origin
            );
            sqlx::query!(
                r#"
                DELETE
                FROM user_sessions
                WHERE origin=$1;
                "#,
                row.origin
            )
            .execute(&self.db)
            .await
            .map_err(|_| Status::unauthenticated("invalid credentials"))?;

            return Err(Status::unauthenticated("invalid credentials"))?;
        }

        let session_token = Ulid::new();
        let refresh_token = Ulid::new();
        let session_token_hash = self.pepper_hash(session_token).await?;
        let refresh_token_hash = self.pepper_hash(refresh_token).await?;
        sqlx::query!(
            r#"
            INSERT INTO user_sessions (
                session_token_hash,
                refresh_token_hash,
                user_id,
                origin
            ) VALUES ($1, $2, $3, $4)
            "#,
            session_token_hash,
            refresh_token_hash,
            user_id.to_string(),
            row.origin
        )
        .execute(&self.db)
        .await
        .map_err(|_| Status::aborted("insert"))?;

        Ok(Response::new(
            RefreshResponse {
                session_token,
                refresh_token,
            }
            .into_proto(),
        ))
    }

    /// Terminates the current session, regardless of its expiry time.
    async fn logout(
        &self,
        req: Request<schema::proto::auth::LogoutRequest>,
    ) -> Result<Response<()>, Status> {
        log::info!("logging out");
        let req = req.into_inner();
        let LogoutRequest {
            user_id,
            session_token,
        } = LogoutRequest::try_from_proto(req).ok_or(Status::internal("decode"))?;

        if SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Status::internal("time"))?
            .as_millis()
            - session_token.timestamp_ms() as u128
            > self.session_expiry_ms
        {
            return Err(Status::unauthenticated("token expired"));
        }

        let session_token_hash = self.pepper_hash(session_token).await?;
        sqlx::query!(
            r#"
            DELETE
            FROM user_sessions
            WHERE user_id=$1
            AND session_token_hash = $2;
            "#,
            user_id.to_string(),
            session_token_hash
        )
        .execute(&self.db)
        .await
        .map_err(|_| Status::unauthenticated("invalid credentials"))?;

        Ok(Response::new(()))
    }
}
