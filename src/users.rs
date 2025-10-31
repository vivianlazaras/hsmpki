use cryptoki::{session::UserType, types::AuthPin};

pub struct User {
    pub(crate) pin: AuthPin,
    pub(crate) ty: UserType,
}
