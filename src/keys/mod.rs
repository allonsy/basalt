mod private;
mod public;
use crate::menu;

pub fn gen_sodium_key() {
    let key_name = menu::prompt("Please enter a name for your key");
}
