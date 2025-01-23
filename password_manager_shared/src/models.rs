use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[derive(Debug, Serialize, Deserialize)]
pub struct Account {
    pub id: i32,
    pub name: String,
    pub username: String,
    pub password: String,
    pub url: Option<String>,
    pub description: Option<String>,
    pub master_id: i32,
}

impl Account {
    pub fn new(name: String, username: String, password: String, url: Option<String>, description: Option<String>, master_id: i32) -> Self {
        Account {
            id: 0, // Placeholder value, ID will be assigned automatically
            name,
            username,
            password,
            url,
            description,
            master_id,
        }
    }
}

impl Drop for Account {
    fn drop(&mut self) {
        self.username.zeroize();
        self.password.zeroize();

        if let Some(ref mut url) = self.url {
            url.zeroize();
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AccountSummary {
    pub id: i32,
    pub name: String,
    pub description: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Master {
    pub id: i32,
    pub username: String,
    pub password: String,
}

impl Drop for Master {
    fn drop(&mut self) {
        self.id.zeroize();
        self.username.zeroize();
        self.password.zeroize();
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}
impl Drop for LoginRequest {
    fn drop(&mut self) {
        self.username.zeroize();
        self.password.zeroize();
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginResponse {
    pub token: String,
}

#[derive(Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
}