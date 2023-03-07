
pub type SignatureResult<T> = Result<T,SignatureError>;

#[derive(Debug)]
pub enum SignatureError {
    Invalid,
}  
