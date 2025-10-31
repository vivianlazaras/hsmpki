use cryptoki::object::Attribute;
use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::session::UserType;
use cryptoki::types::AuthPin;
use cryptoki::mechanism::Mechanism;
use std::env;

fn main() {
    let ctx = Pkcs11::new("/usr/local/lib/softhsm/libsofthsm2.so")?;
    let slot = ctx.get_slot_list(true).unwrap().first().unwrap().clone();
    let info = ctx.get_token_info(slot).unwrap();
    let user = User::new_user("1234");

    let pool = SessionPool::from_parts(&ctx, slot, &info, &user)?;
}