use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct Stack {
    pub frames: Vec<u64>,
    pub success: bool,
}

impl From<tail2_common::Stack> for Stack {
    fn from(s: tail2_common::Stack) -> Self {
        let frames = if let Some(len) = s.unwind_success {
            s.user_stack[..len].to_vec()
        } else {
            vec![]
        };

        Self {
            frames,
            success: s.unwind_success.is_some(),
        }
    }
}

#[cfg(feature = "server")]
mod server {
    use super::*;
    use rocket::{data::{FromData, self, ToByteUnit}, Request, Data, http::Status};

    #[rocket::async_trait]
    impl<'r> FromData<'r> for Stack {
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