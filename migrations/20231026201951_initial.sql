CREATE TABLE
    users (
        id CHAR(26) PRIMARY KEY,
        username VARCHAR(255) NOT NULL UNIQUE,
        password_hash VARCHAR(255) NOT NULL
    );

CREATE TABLE
    user_sessions (
        session_token_hash VARCHAR(255) PRIMARY KEY,
        refresh_token_hash VARCHAR(255) NOT NULL,
        user_id CHAR(26) NOT NULL REFERENCES users (id) ON DELETE CASCADE,
        origin CHAR(26) NOT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CLOCK_TIMESTAMP()
    );

CREATE INDEX idx_user_sessions ON user_sessions (user_id HASH);
