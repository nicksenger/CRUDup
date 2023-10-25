use prost::Message as ProstMessage;

pub mod proto {
    pub mod auth;
    pub mod gateway;
}

pub trait ToFromProto<Proto>: Sized
where
    Proto: ProstMessage,
{
    fn try_from_proto(proto: Proto) -> Option<Self>;
    fn into_proto(self) -> Proto;
}

impl<T, Proto> ToFromProto<Proto> for T
where
    Proto: ProstMessage,
    T: TryFrom<Proto> + Into<Proto>,
{
    fn try_from_proto(proto: Proto) -> Option<Self> {
        proto.try_into().ok()
    }

    fn into_proto(self) -> Proto {
        self.into()
    }
}

pub mod auth {
    use ulid::Ulid;

    pub struct RegisterRequest {
        pub username: String,
        pub password: String,
    }

    pub struct RegisterResponse {
        pub user_id: Ulid,
        pub session_token: Ulid,
        pub refresh_token: Ulid,
    }

    pub struct LoginRequest {
        pub username: String,
        pub password: String,
    }

    pub struct LoginResponse {
        pub user_id: Ulid,
        pub session_token: Ulid,
        pub refresh_token: Ulid,
    }

    pub struct RefreshRequest {
        pub user_id: Ulid,
        pub refresh_token: Ulid,
    }

    pub struct RefreshResponse {
        pub session_token: Ulid,
        pub refresh_token: Ulid,
    }

    pub struct AuthenticateRequest {
        pub user_id: Ulid,
        pub session_token: Ulid,
    }

    pub struct LogoutRequest {
        pub user_id: Ulid,
        pub session_token: Ulid,
    }

    impl super::ToFromProto<super::proto::auth::RegisterRequest> for RegisterRequest {
        fn into_proto(self) -> super::proto::auth::RegisterRequest {
            super::proto::auth::RegisterRequest {
                username: self.username,
                password: self.password,
            }
        }

        fn try_from_proto(proto: super::proto::auth::RegisterRequest) -> Option<Self> {
            Some(RegisterRequest {
                username: proto.username,
                password: proto.password,
            })
        }
    }

    impl super::ToFromProto<super::proto::auth::RegisterResponse> for RegisterResponse {
        fn into_proto(self) -> super::proto::auth::RegisterResponse {
            super::proto::auth::RegisterResponse {
                user_id: self.user_id.to_bytes().to_vec(),
                session_token: self.session_token.to_bytes().to_vec(),
                refresh_token: self.refresh_token.to_bytes().to_vec(),
            }
        }

        fn try_from_proto(proto: super::proto::auth::RegisterResponse) -> Option<Self> {
            Some(RegisterResponse {
                user_id: Ulid::from_bytes(proto.user_id.try_into().ok()?),
                session_token: Ulid::from_bytes(proto.session_token.try_into().ok()?),
                refresh_token: Ulid::from_bytes(proto.refresh_token.try_into().ok()?),
            })
        }
    }

    impl super::ToFromProto<super::proto::auth::LoginRequest> for LoginRequest {
        fn into_proto(self) -> super::proto::auth::LoginRequest {
            super::proto::auth::LoginRequest {
                username: self.username,
                password: self.password,
            }
        }

        fn try_from_proto(proto: super::proto::auth::LoginRequest) -> Option<Self> {
            Some(LoginRequest {
                username: proto.username,
                password: proto.password,
            })
        }
    }

    impl super::ToFromProto<super::proto::auth::LoginResponse> for LoginResponse {
        fn into_proto(self) -> super::proto::auth::LoginResponse {
            super::proto::auth::LoginResponse {
                user_id: self.user_id.to_bytes().to_vec(),
                session_token: self.session_token.to_bytes().to_vec(),
                refresh_token: self.refresh_token.to_bytes().to_vec(),
            }
        }

        fn try_from_proto(proto: super::proto::auth::LoginResponse) -> Option<Self> {
            Some(LoginResponse {
                user_id: Ulid::from_bytes(proto.user_id.try_into().ok()?),
                session_token: Ulid::from_bytes(proto.session_token.try_into().ok()?),
                refresh_token: Ulid::from_bytes(proto.refresh_token.try_into().ok()?),
            })
        }
    }

    impl super::ToFromProto<super::proto::auth::RefreshRequest> for RefreshRequest {
        fn into_proto(self) -> super::proto::auth::RefreshRequest {
            super::proto::auth::RefreshRequest {
                user_id: self.user_id.to_bytes().to_vec(),
                refresh_token: self.refresh_token.to_bytes().to_vec(),
            }
        }

        fn try_from_proto(proto: super::proto::auth::RefreshRequest) -> Option<Self> {
            Some(RefreshRequest {
                user_id: Ulid::from_bytes(proto.user_id.try_into().ok()?),
                refresh_token: Ulid::from_bytes(proto.refresh_token.try_into().ok()?),
            })
        }
    }

    impl super::ToFromProto<super::proto::auth::RefreshResponse> for RefreshResponse {
        fn into_proto(self) -> super::proto::auth::RefreshResponse {
            super::proto::auth::RefreshResponse {
                session_token: self.session_token.to_bytes().to_vec(),
                refresh_token: self.refresh_token.to_bytes().to_vec(),
            }
        }

        fn try_from_proto(proto: super::proto::auth::RefreshResponse) -> Option<Self> {
            Some(RefreshResponse {
                session_token: Ulid::from_bytes(proto.session_token.try_into().ok()?),
                refresh_token: Ulid::from_bytes(proto.refresh_token.try_into().ok()?),
            })
        }
    }

    impl super::ToFromProto<super::proto::auth::AuthenticateRequest> for AuthenticateRequest {
        fn into_proto(self) -> super::proto::auth::AuthenticateRequest {
            super::proto::auth::AuthenticateRequest {
                user_id: self.user_id.to_bytes().to_vec(),
                session_token: self.session_token.to_bytes().to_vec(),
            }
        }

        fn try_from_proto(proto: super::proto::auth::AuthenticateRequest) -> Option<Self> {
            Some(AuthenticateRequest {
                user_id: Ulid::from_bytes(proto.user_id.try_into().ok()?),
                session_token: Ulid::from_bytes(proto.session_token.try_into().ok()?),
            })
        }
    }

    impl super::ToFromProto<super::proto::auth::LogoutRequest> for LogoutRequest {
        fn into_proto(self) -> super::proto::auth::LogoutRequest {
            super::proto::auth::LogoutRequest {
                user_id: self.user_id.to_bytes().to_vec(),
                session_token: self.session_token.to_bytes().to_vec(),
            }
        }

        fn try_from_proto(proto: super::proto::auth::LogoutRequest) -> Option<Self> {
            Some(LogoutRequest {
                user_id: Ulid::from_bytes(proto.user_id.try_into().ok()?),
                session_token: Ulid::from_bytes(proto.session_token.try_into().ok()?),
            })
        }
    }
}

pub mod gateway {
    use ulid::Ulid;

    pub use super::auth::{
        LoginRequest, LoginResponse, LogoutRequest, RefreshRequest, RefreshResponse,
        RegisterRequest, RegisterResponse,
    };

    impl super::ToFromProto<super::proto::gateway::RegisterRequest> for RegisterRequest {
        fn into_proto(self) -> super::proto::gateway::RegisterRequest {
            super::proto::gateway::RegisterRequest {
                username: self.username,
                password: self.password,
            }
        }

        fn try_from_proto(proto: super::proto::gateway::RegisterRequest) -> Option<Self> {
            Some(RegisterRequest {
                username: proto.username,
                password: proto.password,
            })
        }
    }

    impl super::ToFromProto<super::proto::gateway::RegisterResponse> for RegisterResponse {
        fn into_proto(self) -> super::proto::gateway::RegisterResponse {
            super::proto::gateway::RegisterResponse {
                user_id: self.user_id.to_bytes().to_vec(),
                session_token: self.session_token.to_bytes().to_vec(),
                refresh_token: self.refresh_token.to_bytes().to_vec(),
            }
        }

        fn try_from_proto(proto: super::proto::gateway::RegisterResponse) -> Option<Self> {
            Some(RegisterResponse {
                user_id: Ulid::from_bytes(proto.user_id.try_into().ok()?),
                session_token: Ulid::from_bytes(proto.session_token.try_into().ok()?),
                refresh_token: Ulid::from_bytes(proto.refresh_token.try_into().ok()?),
            })
        }
    }

    impl super::ToFromProto<super::proto::gateway::LoginRequest> for LoginRequest {
        fn into_proto(self) -> super::proto::gateway::LoginRequest {
            super::proto::gateway::LoginRequest {
                username: self.username,
                password: self.password,
            }
        }

        fn try_from_proto(proto: super::proto::gateway::LoginRequest) -> Option<Self> {
            Some(LoginRequest {
                username: proto.username,
                password: proto.password,
            })
        }
    }

    impl super::ToFromProto<super::proto::gateway::LoginResponse> for LoginResponse {
        fn into_proto(self) -> super::proto::gateway::LoginResponse {
            super::proto::gateway::LoginResponse {
                user_id: self.user_id.to_bytes().to_vec(),
                session_token: self.session_token.to_bytes().to_vec(),
                refresh_token: self.refresh_token.to_bytes().to_vec(),
            }
        }

        fn try_from_proto(proto: super::proto::gateway::LoginResponse) -> Option<Self> {
            Some(LoginResponse {
                user_id: Ulid::from_bytes(proto.user_id.try_into().ok()?),
                session_token: Ulid::from_bytes(proto.session_token.try_into().ok()?),
                refresh_token: Ulid::from_bytes(proto.refresh_token.try_into().ok()?),
            })
        }
    }

    impl super::ToFromProto<super::proto::gateway::RefreshRequest> for RefreshRequest {
        fn into_proto(self) -> super::proto::gateway::RefreshRequest {
            super::proto::gateway::RefreshRequest {
                user_id: self.user_id.to_bytes().to_vec(),
                refresh_token: self.refresh_token.to_bytes().to_vec(),
            }
        }

        fn try_from_proto(proto: super::proto::gateway::RefreshRequest) -> Option<Self> {
            Some(RefreshRequest {
                user_id: Ulid::from_bytes(proto.user_id.try_into().ok()?),
                refresh_token: Ulid::from_bytes(proto.refresh_token.try_into().ok()?),
            })
        }
    }

    impl super::ToFromProto<super::proto::gateway::RefreshResponse> for RefreshResponse {
        fn into_proto(self) -> super::proto::gateway::RefreshResponse {
            super::proto::gateway::RefreshResponse {
                session_token: self.session_token.to_bytes().to_vec(),
                refresh_token: self.refresh_token.to_bytes().to_vec(),
            }
        }

        fn try_from_proto(proto: super::proto::gateway::RefreshResponse) -> Option<Self> {
            Some(RefreshResponse {
                session_token: Ulid::from_bytes(proto.session_token.try_into().ok()?),
                refresh_token: Ulid::from_bytes(proto.refresh_token.try_into().ok()?),
            })
        }
    }

    impl super::ToFromProto<super::proto::gateway::LogoutRequest> for LogoutRequest {
        fn into_proto(self) -> super::proto::gateway::LogoutRequest {
            super::proto::gateway::LogoutRequest {
                user_id: self.user_id.to_bytes().to_vec(),
                session_token: self.session_token.to_bytes().to_vec(),
            }
        }

        fn try_from_proto(proto: super::proto::gateway::LogoutRequest) -> Option<Self> {
            Some(LogoutRequest {
                user_id: Ulid::from_bytes(proto.user_id.try_into().ok()?),
                session_token: Ulid::from_bytes(proto.session_token.try_into().ok()?),
            })
        }
    }
}
