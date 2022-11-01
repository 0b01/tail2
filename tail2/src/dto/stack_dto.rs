use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct ModuleDto {
    debug_id: Option<String>,
    file_name: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct FrameDto {
    pub module: ModuleDto,
    pub offset: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct StackDto {
    pub frames: Vec<FrameDto>,
    pub success: bool,
}

#[cfg(feature = "server")]
mod server {
    use super::*;
    use rocket::{data::{FromData, self, ToByteUnit}, Request, Data, http::Status};

    #[rocket::async_trait]
    impl<'r> FromData<'r> for StackDto {
        type Error = ();

        async fn from_data(req: &'r Request<'_>, data: Data<'r>) -> data::Outcome<'r, Self> {
            use rocket::outcome::Outcome::*;

            // Use a configured limit with name 'stack' or fallback to default.
            let limit = req.limits().get("stack").unwrap_or(256.bytes());

            // Read the data into a string.
            let buf = match data.open(limit).into_bytes().await {
                Ok(string) if string.is_complete() => string.into_inner(),
                Ok(_) => return Failure((Status::PayloadTooLarge, ())),
                Err(_) => return Failure((Status::InternalServerError, ())),
            };
            let ret = match bincode::deserialize(&buf) {
                Ok(ret) => ret,
                Err(_) => return Failure((Status::ImATeapot, ())),
            };
    
            Success(ret)
        }
    }
}