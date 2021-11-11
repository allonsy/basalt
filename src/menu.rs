use io::Write;
use std::fmt::Display;
use std::io;

pub fn prompt<P: Display>(prompt: P) -> String {
    print!("{} ", prompt);
    let _ = io::stdout().flush();
    read_line()
}

pub fn prompt_yes_no<P: Display>(query_prompt: P, default: Option<bool>) -> bool {
    let yes_opt = match default {
        Some(true) => "Y",
        _ => "y",
    };

    let no_opt = match default {
        Some(false) => "N",
        _ => "n",
    };

    let full_prompt = format!("{} ({}/{}): ", query_prompt, yes_opt, no_opt);

    loop {
        let resp = prompt(&full_prompt);
        if resp.is_empty() && default.is_some() {
            return default.unwrap();
        }

        match resp.as_str() {
            "y" => return true,
            "Y" => return true,
            "yes" => return true,
            "N" => return false,
            "n" => return false,
            "no" => return false,
            _ => {}
        }
    }
}

pub fn prompt_menu<P: Display, Q: Display>(
    query_prompt: P,
    choices: &[Q],
    default: Option<usize>,
) -> usize {
    println!("{}", query_prompt);

    let default_prompt = if default.is_some() {
        "(* designates default): "
    } else {
        ": "
    };
    println!("Please choose an option {}", default_prompt);

    loop {
        for (idx, val) in choices.iter().enumerate() {
            let asterisk = if default.is_some() && default.as_ref().unwrap() == &idx {
                "*"
            } else if default.is_some() {
                " "
            } else {
                ""
            };

            println!("{}){} {}", idx + 1, asterisk, val);
        }
        let user_choice = prompt("Your Choice? ");

        if user_choice.is_empty() && default.is_some() {
            return default.unwrap();
        } else {
            let parsed_choice = str::parse::<usize>(&user_choice);
            if parsed_choice.is_ok() {
                let parsed_choice = parsed_choice.unwrap();
                if parsed_choice > 0 && parsed_choice <= choices.len() {
                    return parsed_choice - 1;
                }
            }
        }
    }
}

fn read_line() -> String {
    let stdin = io::stdin();
    let mut response = String::new();
    let _ = stdin.read_line(&mut response);
    response.trim().to_string()
}
