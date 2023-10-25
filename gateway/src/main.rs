use std::env;

use log;
use schema::gateway::{
    LoginRequest, LoginResponse, LogoutRequest, RefreshRequest, RefreshResponse, RegisterRequest,
    RegisterResponse,
};
use schema::proto::auth::auth_client::AuthClient;
use schema::proto::gateway::gateway_server::{Gateway, GatewayServer};
use schema::ToFromProto;
use tonic::transport::{Channel, Server};
use tonic::{Request, Response, Status};
use tonic_web::GrpcWebLayer;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv::dotenv().ok();
    env_logger::init();

    let auth_client = AuthClient::connect(env::var("AUTH_SERVICE_URI")?).await?;
    log::info!("connected to auth client");

    let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter
        .set_serving::<GatewayServer<GatewayService>>()
        .await;
    log::info!("started health reporter");

    let addr = env::var("GATEWAY_SOCKET")
        .unwrap_or_else(|_| "0.0.0.0:50051".to_string())
        .parse()?;
    let gateway = GatewayServer::new(GatewayService {
        auth_client: auth_client.clone(),
    });

    Server::builder()
        .accept_http1(true)
        .layer(GrpcWebLayer::new())
        .add_service(health_service)
        .add_service(gateway)
        .serve(addr)
        .await?;

    Ok(())
}

struct GatewayService {
    auth_client: AuthClient<Channel>,
}

#[tonic::async_trait]
impl Gateway for GatewayService {
    async fn register(
        &self,
        req: Request<schema::proto::gateway::RegisterRequest>,
    ) -> Result<Response<schema::proto::gateway::RegisterResponse>, Status> {
        log::info!("registration");
        let req =
            RegisterRequest::try_from_proto(req.into_inner()).ok_or(Status::internal("decode"))?;

        let resp = RegisterResponse::try_from_proto(
            self.auth_client
                .clone()
                .register(Request::new(req.into_proto()))
                .await?
                .into_inner(),
        )
        .ok_or(Status::internal("decode"))?;

        log::info!("registration successful");
        Ok(Response::new(resp.into_proto()))
    }

    async fn login(
        &self,
        req: Request<schema::proto::gateway::LoginRequest>,
    ) -> Result<Response<schema::proto::gateway::LoginResponse>, Status> {
        log::info!("login");
        let req =
            LoginRequest::try_from_proto(req.into_inner()).ok_or(Status::internal("decode"))?;

        let resp = LoginResponse::try_from_proto(
            self.auth_client
                .clone()
                .login(Request::new(req.into_proto()))
                .await?
                .into_inner(),
        )
        .ok_or(Status::internal("decode"))?;

        log::info!("login successful");
        Ok(Response::new(resp.into_proto()))
    }

    async fn refresh(
        &self,
        req: Request<schema::proto::gateway::RefreshRequest>,
    ) -> Result<Response<schema::proto::gateway::RefreshResponse>, Status> {
        log::info!("refresh");
        let req =
            RefreshRequest::try_from_proto(req.into_inner()).ok_or(Status::internal("decode"))?;

        let resp = RefreshResponse::try_from_proto(
            self.auth_client
                .clone()
                .refresh(Request::new(req.into_proto()))
                .await?
                .into_inner(),
        )
        .ok_or(Status::internal("decode"))?;

        log::info!("login successful");
        Ok(Response::new(resp.into_proto()))
    }

    async fn logout(
        &self,
        req: Request<schema::proto::gateway::LogoutRequest>,
    ) -> Result<Response<()>, Status> {
        log::info!("refresh");
        let req =
            LogoutRequest::try_from_proto(req.into_inner()).ok_or(Status::internal("decode"))?;

        let resp = self
            .auth_client
            .clone()
            .logout(Request::new(req.into_proto()))
            .await?
            .into_inner();

        log::info!("logout successful");
        Ok(Response::new(resp.into_proto()))
    }
}
