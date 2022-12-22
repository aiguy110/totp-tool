use std::{io::{Write, Cursor}, process, error::Error, path::PathBuf};
use clap::{Parser, Subcommand, CommandFactory, Command, FromArgMatches, error::{ContextKind, ContextValue}};
use totp_rs::TOTP;
use serde::{Serialize, Deserialize};

mod generic_error;
use generic_error::GenericError;

mod migration;
use migration::proto_message::Payload;
use prost::Message;

use base64;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
#[clap(propagate_version = true)]
#[clap(term_width = 120)]
struct Cli {
    #[clap(subcommand)]
    command: Option<TotpCommand>,
}

#[derive(Subcommand, Debug)]
enum TotpCommand {    
    /// Use the TOTP config specified by label
    Use {
        label: String
    },
    
    /// Add a new TOTP config via a URL. Supported schemes are "otpauth", "otpauth-migration", and "qr-path"
    Add { 
        /// URL specifying TOTP config.  Supported schemes: totpauth, otpauth-migration, and qr-path.
        url: String, 
        /// Label for TOTP config. (Optional if included in URL)
        label: Option<String> 
    },
    
    /// Delete a give TOTP config or all of them if none is specified. (Confirmation needed in second case)
    Del {
        /// Label of TOTP config to delete
        label: Option<String>
    },

    /// Set the default TOTP config to use if no other is specified
    Default {
        /// Label of TOTP config to set as default
        label: String
    },

    /// Change a label to another string
    Rename {
        label: String,
        new_label: String
    },

    /// List available TOTP config labels
    List,

    /// Save configuration changes and exit. (Only useful in interactive mode)
    Exit
}

#[derive(Serialize, Deserialize, Default)]
struct GeneralConfig {
    default_totp: Option<String>,
    available_totps: Vec<TotpConfig>
}

#[derive(Serialize, Deserialize)]
struct TotpConfig {
    label: String,
    totp_details: TOTP
}

fn main() {
    selfstorage::self_storage_init();

    let cli = Cli::parse();
    let mut cfg = load_config();

    match cli.command {
        None => do_command_loop(&mut cfg),
        Some(cmd) => {
            process_command(cmd, &mut cfg, &mut None)
        }
    }
    save_and_exit(&cfg);
}

fn do_command_loop(cfg: &mut GeneralConfig) {
    println!("Type \"?\" for a list of available commands, or \":\" when you are ready to enter a password.");

    let mut current_label = cfg.default_totp.clone();
    let mut input_buf = String::new();
    loop {
        // Show prompt
        match &current_label {
            Some(label) => print!("({})>", label),
            None        => print!("(-)>")
        }
        std::io::stdout().flush().unwrap();

        // Read input
        input_buf.clear();
        std::io::stdin().read_line(&mut input_buf).unwrap();
        match input_buf.trim() {
            "?" => {
                for subcommand in Cli::into_app().get_subcommands() {
                    match subcommand.get_about() {
                        Some(about) => println!("{} - {}", subcommand.get_name(), about),
                        None        => println!("{}", subcommand.get_name())
                    }
                }
            }
            ":" => deliver_code(&mut current_label, cfg),
            "" => {}
            cmd => {
                let cmd_parts: Vec<_> = cmd.split_whitespace().collect();
                match Cli::into_app().get_subcommands().find(|sc| sc.get_name() == cmd_parts[0]) {
                    Some(clap_cmd) => {
                        if cmd_parts.len() > 1 && cmd_parts[1] == "?" {
                            show_help_for_clap_cmd(clap_cmd);
                            continue;
                        }
                        match Cli::command().no_binary_name(true).try_get_matches_from(cmd_parts.iter()) {
                            Ok(arg_matches) => {
                                process_command(TotpCommand::from_arg_matches(&arg_matches).unwrap(), cfg, &mut current_label)
                            },
                            Err(e) => {
                                println!("Got error processing args for \"{}\"", cmd_parts[0]);
                                for err_part in e.context() {
                                    match err_part  {
                                        (ContextKind::Usage, ContextValue::String(usage)) => {println!("{}", usage)},
                                        _ => {}
                                    }
                                }
                            }
                        }
                    },
                    None => {
                        println!("Unrecognized command \"{}\"", cmd_parts[0])
                    }
                }

            }, 
        }
    }
}

fn label_exists(label: &str, cfg: &GeneralConfig) -> bool {
    cfg.available_totps
        .iter()
        .map(|tc| &tc.label)
        .any(|l| l == &label)
}

fn process_command(cmd: TotpCommand, cfg: &mut GeneralConfig, current_label: &mut Option<String>) {
    match cmd {
        TotpCommand::Use { label } => {
            do_use(label, current_label, cfg);
        },
        TotpCommand::Add { url, label } => {
            do_add(url, label, current_label, cfg);
        },
        TotpCommand::Del { label } => {
            do_del(label, current_label, cfg);
        },
        TotpCommand::Default { label } => {
            do_default(label, cfg);
        },
        TotpCommand::Rename { label, new_label } => {
            do_rename(label, new_label, current_label, cfg);
        }
        TotpCommand::List => {
            do_list(cfg);
        },
        TotpCommand::Exit => {
            save_and_exit(cfg);
        }
    }
}

fn do_use(label: String, current_label: &mut Option<String>, cfg: &GeneralConfig) {
    if label_exists(&label, cfg) {
        *current_label = Some(label)
    } else {
        println!("Unknown label \"{}\"", label);
        return;
    }
}

fn do_add(url: String, label: Option<String>, current_label: &mut Option<String>, cfg: &mut GeneralConfig) {
    let url = match urlencoding::decode(&url) {
        Ok(decoded_url) => decoded_url.into_owned(),
        Err(e) => {
            println!("Error decoding URL: {}", e);
            return;
        }
    };
    
    let colon_pos = url.find(':');
    if matches!(colon_pos, None) {
        println!("Invalid URL: \"{}\"", url);
        return;
    }
    let scheme = &url[..colon_pos.unwrap()];
    match scheme {
        "otpauth" => {
            add_otpauth_url(url, label, current_label, cfg);
        }
        "otpauth-migration" => {
            add_otpauth_migration(url, label, current_label, cfg);
        },
        "qr-path" => {
            add_qr_path_url(url, label, current_label, cfg);
        }
        _ => {
            println!("Unrecognized URL scheme \"{}\"", scheme);
        }
    }
}

fn add_otpauth_url(url: String, mut label: Option<String>, current_label: &mut Option<String>, cfg: &mut GeneralConfig) {
    match TOTP::<Vec<u8>>::from_url(url) {
        Err(e) => {
            println!("Error processing URL: {}", e);
            return;
        } 
        Ok(totp) => {
            if matches!(label, None) {
                if totp.account_name.trim() == "" {
                    println!("URL contains no label and no label was provided. Cannot add this URL.");
                    return;
                }
                label = Some(totp.account_name.clone())
            }
            if label_exists(label.as_ref().unwrap(), cfg) {
                println!("Label \"{}\" already exists. Not adding this URL.", label.as_ref().unwrap());
                return;
            }
            cfg.available_totps.push( TotpConfig {
                label: label.clone().unwrap(),
                totp_details: totp
            });
            if cfg.available_totps.len() == 1 {
                cfg.default_totp = label.clone();
                *current_label = label;
            }
        },
    }
}


fn add_otpauth_migration(url: String, mut label: Option<String>, current_label: &mut Option<String>, cfg: &mut GeneralConfig) {
    let prefix = "otpauth-migration://offline?data=";
    if &url[..prefix.len()] != prefix {
        println!("Couldn't base64 payload. Expected fromat is \"otpauth-migration://offline?data=<base64_payload>\"");
        return;
    }
    
    let base64_payload = &url[prefix.len()..];
    match base64::decode(base64_payload) {
        Err(e) => {
            println!("Error decoding base64: {}", e);
            return;
        },
        Ok(data) => {
            match Payload::decode(&data[..]) {
                Err(e) => {
                    println!("Error parsing decoded bytes into TOTP configuration: {}", e);
                    return;
                },
                Ok(payload)=> {
                    let totp: TOTP = match payload.into() {
                        Err(e) =>  {
                            println!("Error parsing TOTP configuration from Google migration payload: {}", e);
                            return;
                        }
                        Ok(totp) => totp,
                    };

                    if matches!(label, None) {
                        if totp.account_name.trim() == "" {
                            println!("URL contains no label and no label was provided. Cannot add this URL.");
                            return;
                        }
                        label = Some(totp.account_name.clone())
                    }
                    if label_exists(label.as_ref().unwrap(), cfg) {
                        println!("Label \"{}\" already exists. Not adding this URL.", label.as_ref().unwrap());
                        return;
                    }
                    cfg.available_totps.push( TotpConfig {
                        label: label.clone().unwrap(),
                        totp_details: totp
                    });
                    if cfg.available_totps.len() == 1 {
                        cfg.default_totp = label.clone();
                        *current_label = label;
                    }
                }
            }
        }
    }
}

fn add_qr_path_url(url: String, label: Option<String>, current_label: &mut Option<String>, cfg: &mut GeneralConfig) {
    let prefix = "qr-path://";
    if &url[..prefix.len()] != prefix {
        println!("Couldn't extract path from qr-path URL. Expected fromat is \"qr-path://<path-to-file>\"");
        return;
    }
    let path = PathBuf::from(&url[10..]);

    let inner_url = match get_url_from_qr_path(&path) {
        Ok(s) => s,
        Err(e) => {
            println!("Got error retrieving inner URL from QR image path: {e}");
            return;
        }
    };
    println!("Got inner URL \"{inner_url}\" from QR code image.");
    do_add(inner_url, label, current_label, cfg);
}

fn get_url_from_qr_path(path: &PathBuf) -> Result<String, Box<dyn Error>> {
    let img = image::open(path)?;

    let mut builder = bardecoder::default_builder();
    builder.prepare(Box::new(bardecoder::prepare::BlockedMean::new(7, 9)));

    let decoder = builder.build();
    let url = decoder.decode(&img)
        .pop()
        .ok_or(GenericError::new("Failed to find QR code in provided image."))??;

    Ok(url)
}

fn do_del(label: Option<String>, current_label: &mut Option<String>, cfg: &mut GeneralConfig) {
    match label {
        Some(label) => { 
            if label_exists(&label, cfg) {
                cfg.available_totps.retain(|x| x.label != label);
                if let Some(current_label_inner) = current_label {
                    if *current_label_inner == label {
                        *current_label = None;
                    }
                }
                if let Some(default_label_inner) = cfg.default_totp.as_ref() {
                    if *default_label_inner == label {
                        cfg.default_totp = None;
                    }
                }
            } else {
                println!("Unknown label \"{}\"", label);
                return;
            }
        },
        None => {
            let totp_count = cfg.available_totps.len();
            print!("Are you sure you want to delete all TOTP configurations? ({} will be deleted) [y|N]>", totp_count);
            std::io::stdout().flush().unwrap();
            let mut yes_no = String::new();
            std::io::stdin().read_line(&mut yes_no).unwrap();
            if yes_no.to_lowercase().trim() != "y" {
                return;
            }
            *cfg = GeneralConfig {
                default_totp: None,
                available_totps: vec![]
            };
            *current_label = None;
            println!("Deleted {} TOTP configurations", totp_count);
        }
    }
}

fn do_default(label: String, cfg: &mut GeneralConfig) {
    if label_exists(&label, cfg) {
        cfg.default_totp = Some(label)
    } else {
        println!("Unknown label \"{}\"", label);
        return;
    }
}

fn do_rename(label: String, new_label: String, current_label: &mut Option<String>, cfg: &mut GeneralConfig) {
    if !label_exists(&label, cfg) {
        println!("Unknown label \"{}\"", label);
        return;
    }

    for totp_config in cfg.available_totps.iter_mut() {
        if totp_config.label == label {
            totp_config.label = new_label.clone();
            break;
        }
    }
    if let Some(current_label_inner) = current_label {
        if *current_label_inner == label {
            *current_label = Some(new_label.clone());
        }
    }
    if let Some(default_label_inner) = cfg.default_totp.as_ref() {
        if *default_label_inner == label {
            cfg.default_totp = Some(new_label);
        }
    }
}

fn do_list(cfg: &GeneralConfig) {
    if cfg.available_totps.len() == 0 {
        println!("No TOTP configuration to show.");
    } else {
        for totp_config in cfg.available_totps.iter() {
            println!("{}", totp_config.label);
        }
    }
}

fn deliver_code(current_label: &mut Option<String>, cfg: &GeneralConfig) {
    if matches!(current_label, None) {
        println!("No TOTP config selected.");
        return;
    }
    let label = current_label.clone().unwrap();
    for totp_config in cfg.available_totps.iter() {
        if totp_config.label == label {
            let code = totp_config.totp_details.generate_current().unwrap();
            println!("{}", code);
            cli_clipboard::set_contents(code).unwrap();
        }
    }
}

fn show_help_for_clap_cmd(cmd: &Command) {
    println!("Showing help for command \"{}\":", cmd.get_name());
    match Cli::command().no_binary_name(true).try_get_matches_from([cmd.get_name()].iter()) {
        Err(e) => {
            for err_part in e.context() {
                match err_part  {
                    (ContextKind::Usage, ContextValue::String(usage)) => {println!("{}", usage)},
                    _ => {}
                }
            }
        },
        Ok(_) => {
            println!("{}", cmd.get_about().unwrap());
        }
    }
}

fn load_config() -> GeneralConfig {
    let self_reader = match selfstorage::get_stored_data() {
        Ok(r)  => r,
        Err(e) => { 
            println!("Error reading data from self-storage: {}", e);
            return GeneralConfig::default() 
        }
    };
    let des = serde_yaml::Deserializer::from_reader(self_reader);
    match GeneralConfig::deserialize(des) {
        Ok(cfg) => cfg,
        Err(e)  => {
            println!("Error deserializing content of self-storage: {}", e);
            GeneralConfig::default()
        }
    }
}

fn save_and_exit(cfg: &GeneralConfig) {
    let mut yaml_output = Cursor::new(Vec::<u8>::new());
    let mut ser = serde_yaml::Serializer::new(&mut yaml_output);
    match cfg.serialize(&mut ser) {
        Ok(_) => { 
            let yaml_output = yaml_output.into_inner();
            selfstorage::set_stored_data_and_exit(&yaml_output[..]);
        },
        Err(e) => {
            println!("Error saving config: {}", e);
            process::exit(-1);
        }
    }
}