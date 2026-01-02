use std::error;

pub type MyResult<T> = std::result::Result<T, Box<dyn error::Error>>;

//#[derive(Error, Debug)]
//#[error(transparent)]
//pub struct ConvertBytesToMessageError {
//    #[from]
//    source: anyhow::Error,
//}
//
//#[derive(Error, Debug)]
//#[error(transparent)]
//pub struct ConvertMessageToBytesError {
//    #[from]
//    source: anyhow::Error,
//}
