mod pb {
    include!("../proto/output/api.rs");
}

pub use pb::User;

use crate::Error;

use std::{collections::HashMap, net::SocketAddr, pin::Pin, sync::Arc};

use tokio::sync::RwLock;

use pb::{
    user_management_server::UserManagementServer, GetUserRequest, GetUserResponse,
    ListUsersRequest, ListUsersResponse, RemoveUserRequest, SetUserResponse, UpsertUserRequest,
};

use tonic::Response;

use futures::stream;

use tonic::{transport::Server, Status};

use crate::hex_hash;

type ResponseStream =
    Pin<Box<dyn futures::Stream<Item = Result<ListUsersResponse, Status>> + Send + Sync>>;

pub struct UserManagementService {
    users: Arc<RwLock<HashMap<Box<[u8]>, User>>>,
}

impl UserManagementService {
    pub fn new(users: Arc<RwLock<HashMap<Box<[u8]>, User>>>) -> Self {
        Self { users }
    }
}

#[tonic::async_trait]
impl pb::user_management_server::UserManagement for UserManagementService {
    type ListUsersStream = ResponseStream;

    async fn list_users(
        &self,
        _: tonic::Request<ListUsersRequest>,
    ) -> Result<tonic::Response<Self::ListUsersStream>, Status> {
        let user_map = self.users.read().await;
        let mut users = vec![];
        for user in user_map.values() {
            let r: Result<ListUsersResponse, Status> = Ok(ListUsersResponse {
                user: Some(user.clone()),
            });
            users.push(r);
        }
        Ok(Response::new(Box::pin(stream::iter(users))))
    }

    async fn get_user(
        &self,
        request: tonic::Request<GetUserRequest>,
    ) -> Result<tonic::Response<GetUserResponse>, tonic::Status> {
        let guard = self.users.read().await;
        if let Some(user) = guard.get(&hex_hash(&request.get_ref().pswd)) {
            Ok(Response::new(GetUserResponse {
                user: Some(user.clone()),
            }))
        } else {
            Err(tonic::Status::not_found(format!(
                "not found user password: '{}'",
                &request.get_ref().pswd
            )))
        }
    }

    async fn upsert_user(
        &self,
        mut request: tonic::Request<UpsertUserRequest>,
    ) -> Result<tonic::Response<SetUserResponse>, tonic::Status> {
        let mut guard = self.users.write().await;
        let success = if let Some(user) = request.get_mut().user.take() {
            guard.insert(hex_hash(&user.pswd), user);
            true
        } else {
            false
        };
        Ok(Response::new(SetUserResponse { success }))
    }

    async fn remove_user(
        &self,
        request: tonic::Request<RemoveUserRequest>,
    ) -> Result<tonic::Response<SetUserResponse>, tonic::Status> {
        let mut guard = self.users.write().await;
        let success = if let Some(_) = guard.remove(&hex_hash(&request.get_ref().pswd)) {
            true
        } else {
            false
        };
        Ok(Response::new(SetUserResponse { success }))
    }
}

pub async fn run_server(
    addr: SocketAddr,
    users: Arc<RwLock<HashMap<Box<[u8]>, User>>>,
) -> Result<(), Error> {
    let svc = UserManagementService::new(users);
    Server::builder()
        .add_service(UserManagementServer::new(svc))
        .serve(addr)
        .await?;
    Ok(())
}
