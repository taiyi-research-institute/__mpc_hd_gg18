#![allow(non_snake_case)]
#![allow(dead_code)]
mod biz_algo;
mod exception;
mod mp_ecdsa;
mod mp_ecdsa2;
mod util;

use bip32::ChainCode;
use clap::{Arg, ArgMatches, Command};
use curv::elliptic::curves::{secp256_k1::Secp256k1, Point, Scalar};
use paillier::*;
use tokio::fs;

use crate::util::*;
use biz_algo::{hd::get_hd_key, keygen, manager, reshare, sign, Params};
use mp_ecdsa::{feldman_vss::VerifiableSS, party_i::*};

#[tokio::main]
async fn main() {
    let args = argparse();
    init_sampler().await;
    println!("Sampler initialized.");

    match args.subcommand() {
        Some(("manager", _matches)) => {
            manager::run_manager().await.unwrap();
        }
        Some(("keygen", sub_matches)) => {
            let addr = sub_matches
                .get_one::<String>("manager_addr")
                .map(|s| s.as_str())
                .unwrap_or("http://127.0.0.1:8000")
                .to_string();
            let keysfile_path = sub_matches
                .get_one::<String>("keysfile")
                .map(|s| s.as_str())
                .unwrap_or("")
                .to_string();
            let params: Vec<&str> = sub_matches
                .get_one::<String>("params")
                .map(|s| s.as_str())
                .unwrap_or("")
                .split("/")
                .collect();
            keygen::run_keygen(&addr, &keysfile_path, &params)
                .await
                .unwrap();
        }
        Some(("sign", sub_matches)) => {
            let keysfile_path = sub_matches
                .get_one::<String>("keysfile")
                .map(|s| s.as_str())
                .unwrap_or("");

            // Read data from keys file
            let data = fs::read_to_string(keysfile_path).await.expect(
                format!("Unable to load keys file at location: {}", keysfile_path).as_str(),
            );
            let (
                party_keys,
                shared_keys,
                party_id,
                mut vss_scheme_vec,
                paillier_key_vec,
                y_sum,
                chain_code,
            ): (
                Keys,
                SharedKeys,
                u16,
                Vec<VerifiableSS<Secp256k1>>,
                Vec<EncryptionKey>,
                Point<Secp256k1>,
                ChainCode,
            ) = serde_json::from_str(&data).unwrap();

            // Get root pub key or HD non-hardened pub key at specified path
            let path = sub_matches
                .get_one::<String>("path")
                .map(|s| s.as_str())
                .unwrap_or("");
            let (tweak_sk, y_sum) = match path.is_empty() {
                true => (Scalar::<Secp256k1>::zero(), y_sum),
                false => call_hd_key(path, y_sum, chain_code),
            };

            // Parse message to sign
            let message_str = sub_matches
                .get_one::<String>("message")
                .map(|s| s.as_str())
                .unwrap_or("");
            let message = match hex::decode(message_str) {
                Ok(x) => x,
                Err(_e) => message_str.as_bytes().to_vec(),
            };
            let message = &message[..];
            let manager_addr = sub_matches
                .get_one::<String>("manager_addr")
                .map(|s| s.as_str())
                .unwrap_or("http://127.0.0.1:8000")
                .to_string();

            // Parse threshold params
            let params: Vec<&str> = sub_matches
                .get_one::<String>("params")
                .map(|s| s.as_str())
                .unwrap_or("")
                .split("/")
                .collect();
            let params = Params {
                threshold: params[0].to_string(),
                parties: params[1].to_string(),
                share_count: params[2].to_string(),
            };
            sign::sign(
                &manager_addr,
                party_keys,
                shared_keys,
                party_id,
                &mut vss_scheme_vec,
                paillier_key_vec,
                &y_sum,
                &params,
                &message,
                &tweak_sk,
            )
            .await
        }
        Some(("reshare", sub_matches)) => {
            let keysfile_path = sub_matches
                .get_one::<String>("keysfile")
                .map(|s| s.as_str())
                .unwrap_or("")
                .to_string();
            let manager_addr = sub_matches
                .get_one::<String>("manager_addr")
                .map(|s| s.as_str())
                .unwrap_or("http://127.0.0.1:8000")
                .to_string();
            // Parse threshold params
            let params: Vec<&str> = sub_matches
                .get_one::<String>("params")
                .map(|s| s.as_str())
                .unwrap_or("")
                .split("/")
                .collect();
            let params = Params {
                threshold: params[0].to_string(),
                parties: params[1].to_string(),
                share_count: params[2].to_string(),
            };
            let if_give_str = sub_matches
                .get_one::<String>("give")
                .map(|s| s.as_str())
                .unwrap_or("")
                .to_string();
            let if_give: bool = if_give_str == "t" || if_give_str == "T";
            let if_hold_str = sub_matches
                .get_one::<String>("hold")
                .map(|s| s.as_str())
                .unwrap_or("")
                .to_string();
            let if_hold: bool = if_hold_str == "t" || if_hold_str == "T";
            let if_receive_str = sub_matches
                .get_one::<String>("receive")
                .map(|s| s.as_str())
                .unwrap_or("")
                .to_string();
            let if_receive: bool = if_receive_str == "t" || if_receive_str == "T";
            reshare::reshare_all_xi(
                manager_addr,
                &params,
                &keysfile_path,
                if_give,
                if_hold,
                if_receive,
            )
            .await
        }
        _ => {}
    };
}

fn call_hd_key(
    path_str: &str,
    par_pk: Point<Secp256k1>,
    chain_code: ChainCode,
) -> (Scalar<Secp256k1>, Point<Secp256k1>) {
    let (tweak_sk, child_pk) =
        if let Ok((tweak_sk, child_pk)) = get_hd_key(path_str, par_pk, chain_code) {
            (tweak_sk, child_pk)
        } else {
            todo!()
        };
    (tweak_sk, child_pk.clone())
}

fn argparse() -> ArgMatches {
    Command::new("MPC_HD_GG18")
        .version("0.1.0")
        .author("TAIYI TECH")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommands(vec![
            Command::new("manager").about("Run state manager"),
            Command::new("keygen")
                .about("Run keygen")
                .arg(
                    Arg::new("keysfile")
                        .index(1)
                        .required(true)
                        .num_args(1)
                        .help("Target keys file"),
                )
                .arg(
                    Arg::new("params")
                        .index(2)
                        .required(true)
                        .num_args(1)
                        .help("Threshold params: threshold/parties (t/n). E.g. 1/3."),
                )
                .arg(
                    Arg::new("manager_addr")
                        .short('a')
                        .long("addr")
                        .num_args(1)
                        .help("URL to manager. E.g. http://127.0.0.2:8002"),
                ),
            Command::new("sign")
                .about("Run sign")
                .arg(
                    Arg::new("keysfile")
                        .index(1)
                        .required(true)
                        .num_args(1)
                        .help("Keys file"),
                )
                .arg(
                    Arg::new("params").index(2).required(true).num_args(1).help(
                        "Threshold params: threshold/parties/share_count (t/t'/n). E.g. 1/2/3.",
                    ),
                )
                .arg(
                    Arg::new("message")
                        .index(3)
                        .required(true)
                        .num_args(1)
                        .help("Message to sign in hex format"),
                )
                .arg(
                    Arg::new("path")
                        .short('p')
                        .long("path")
                        .num_args(1)
                        .help("Derivation path"),
                )
                .arg(
                    Arg::new("manager_addr")
                        .short('a')
                        .long("addr")
                        .num_args(1)
                        .help("URL to manager"),
                ),
            Command::new("reshare")
                .about("Run reshare")
                .arg(
                    Arg::new("keysfile")
                        .index(1)
                        .required(true)
                        .num_args(1)
                        .help("Keys file"),
                )
                .arg(
                    Arg::new("params").index(2).required(true).num_args(1).help(
                        "Threshold params: threshold/parties/share_count (t/t'/n). E.g. 1/2/3.",
                    ),
                )
                .arg(
                    Arg::new("give")
                        .index(3)
                        .required(true)
                        .num_args(1)
                        .help("Either f/F for false or t/T for true."),
                )
                .arg(
                    Arg::new("hold")
                        .index(4)
                        .required(true)
                        .num_args(1)
                        .help("Either f/F for false or t/T for true."),
                )
                .arg(
                    Arg::new("receive")
                        .index(5)
                        .required(true)
                        .num_args(1)
                        .help("Either f/F for false or t/T for true."),
                )
                .arg(
                    Arg::new("manager_addr")
                        .short('a')
                        .long("addr")
                        .num_args(1)
                        .help("URL to manager"),
                ),
        ])
        .get_matches()
}
