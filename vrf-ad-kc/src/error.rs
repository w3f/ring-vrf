
pub type SignatureResult<T> = Result<T,SignatureError>;

pub enum SignatureError {
    Invalid,
}  
