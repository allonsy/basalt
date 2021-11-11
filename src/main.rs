mod config;
mod keys;
mod menu;

fn main() {
    let resp = menu::prompt_menu("hello", &vec!["Opt 1", "Opt 2", "Opt 3"], Some(1));
    println!("'{}'", resp);
}
