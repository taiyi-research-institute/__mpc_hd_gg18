pub mod hd;
pub mod keygen;
pub mod manager;
pub mod reshare;
pub mod sign;

use std::{iter::repeat, thread, time, time::Duration};

use aes_gcm::{
    aead::{Aead, NewAead, Payload},
    Aes256Gcm, Nonce,
};

use rand::{rngs::OsRng, RngCore};

use curv::{
    elliptic::curves::{secp256_k1::Secp256k1, Point, Scalar},
    BigInt,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};

use thiserror::Error;
#[derive(Error, PartialEq, Eq, Clone, Debug, Deserialize)]
pub enum Error {
    // InvalidKey,
    // InvalidSS,
    // InvalidCom,
    // InvalidSig,
    // Phase5BadSum,
    // Phase6Error,
    #[error("Keygen-Error")]
    KeygenError(String),
    #[error("Sign-Error")]
    SignError(String),
    #[error("Connect-Error")]
    ConnectError(String),
    #[error("Uuid-Error")]
    UuidError(String),
    #[error("Signup-Error")]
    SignupError(String),
    #[error("Param-Error")]
    ParamInvalid(String),
    #[error("Keyshare-Error")]
    KeyshareError(String),
}

pub type Key = String;

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct AEAD {
    pub ciphertext: Vec<u8>,
    pub tag: Vec<u8>,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct PartySignup {
    pub number: u16,
    pub uuid: String,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Index {
    pub key: Key,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Entry {
    pub key: Key,
    pub value: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Params {
    pub threshold: String,
    pub parties: String,
    pub share_count: String,
}

#[allow(dead_code)]
pub fn aes_encrypt(key: &[u8], plaintext: &[u8]) -> AEAD {
    let mut full_length_key: [u8; 32] = [0; 32];
    full_length_key[(32 - key.len())..].copy_from_slice(key); // pad key with zeros

    let aes_key = aes_gcm::Key::from_slice(full_length_key.as_slice());
    let cipher = Aes256Gcm::new(aes_key);

    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let nonce = Nonce::from_slice(&nonce);

    // reserve for later changes when a non-empty aad could be imported
    let aad: Vec<u8> = repeat(0).take(16).collect();
    let payload = Payload {
        msg: plaintext,
        aad: &aad.as_slice(),
    };

    let ciphertext = cipher.encrypt(nonce, payload).expect("encryption failure!"); // NOTE: handle this error to avoid panics!

    AEAD {
        ciphertext: ciphertext,
        tag: nonce.to_vec(),
    }
}

#[allow(dead_code)]
pub fn aes_decrypt(key: &[u8], aead_pack: AEAD) -> Vec<u8> {
    let mut full_length_key: [u8; 32] = [0; 32];
    full_length_key[(32 - key.len())..].copy_from_slice(key); // Pad key with zeros

    let aes_key = aes_gcm::Key::from_slice(full_length_key.as_slice());
    let nonce = Nonce::from_slice(&aead_pack.tag);
    let gcm = Aes256Gcm::new(aes_key);

    // reserve for later changes when a non-empty aad could be imported
    let aad: Vec<u8> = repeat(0).take(16).collect();
    let payload = Payload {
        msg: aead_pack.ciphertext.as_slice(),
        aad: aad.as_slice(),
    };

    // NOTE: no error reported but return a value NONE when decrypt key is wrong
    let out = gcm.decrypt(nonce, payload);
    out.unwrap_or_default()
}

pub async fn signup(addr: &String, client: &Client, path: &str, params: &Params) -> PartySignup {
    let res_body = postb(&addr, &client, path, params).await;
    println!("{}", &res_body);
    let res: Result<PartySignup, ()> = serde_json::from_str(&res_body).unwrap();
    res.unwrap()
}

pub async fn postb<T>(addr: &String, client: &Client, path: &str, body: T) -> String
where
    T: serde::ser::Serialize,
{
    let retries = 3;
    let retry_delay = time::Duration::from_millis(250);
    let addr = format!("{}/{}", addr, path);
    for _i in 1..retries {
        let res = client.post(&addr).json(&body).send().await;
        if let Ok(res) = res {
            return res.text().await.unwrap();
        }
        thread::sleep(retry_delay);
    }
    let res = client.post(&addr).json(&body).send().await.unwrap();
    res.text().await.unwrap()
}

pub async fn broadcast(
    addr: &String,
    client: &Client,
    party_num: u16,
    round: &str,
    data: String,
    sender_uuid: String,
) {
    let key = format!("{}-{}-{}", party_num, round, sender_uuid);
    let entry = Entry {
        key: key.clone(),
        value: data,
    };

    let res_body = postb(&addr, &client, "set", entry).await;
    let res: Result<(), ()> = serde_json::from_str(&res_body).unwrap();
    res.unwrap();
}

pub async fn sendp2p(
    addr: &String,
    client: &Client,
    party_from: u16,
    party_to: u16,
    round: &str,
    data: String,
    sender_uuid: String,
) -> Result<(), ()> {
    let key = format!("{}-{}-{}-{}", party_from, party_to, round, sender_uuid);

    let entry = Entry {
        key: key.clone(),
        value: data,
    };

    let res_body = postb(&addr, &client, "set", entry).await;
    serde_json::from_str(&res_body).unwrap()
}

pub async fn poll_for_broadcasts(
    addr: &String,
    client: &Client,
    party_num: u16,
    n: u16,
    delay: Duration,
    round: &str,
    sender_uuid: String,
) -> Vec<String> {
    let mut ans_vec = Vec::new();
    for i in 1..=n {
        if i != party_num {
            let key = format!("{}-{}-{}", i, round, sender_uuid);
            let index = Index { key };
            loop {
                // tokio sleep
                tokio::time::sleep(delay).await;

                let res_body = postb(&addr, &client, "get", index.clone()).await;
                let answer: Result<Entry, ()> = serde_json::from_str(&res_body).unwrap();
                if let Ok(answer) = answer {
                    ans_vec.push(answer.value);
                    println!("[{:?}] party {:?} => party {:?}", round, i, party_num);
                    break;
                }
            }
        }
    }
    ans_vec
}

pub async fn poll_all_for_p2p(
    addr: &String,
    client: &Client,
    party_num: u16,
    n: u16,
    delay: Duration,
    round: &str,
    sender_uuid: String,
) -> Vec<String> {
    let mut ans_vec = Vec::new();
    for i in 1..=n {
        ans_vec.push(
            single_poll_for_p2p(
                addr,
                client,
                party_num,
                i,
                delay,
                round,
                sender_uuid.clone(),
            )
            .await,
        );
    }
    ans_vec
}

pub async fn poll_for_p2p(
    addr: &String,
    client: &Client,
    party_num: u16,
    n: u16,
    delay: Duration,
    round: &str,
    sender_uuid: String,
) -> Vec<String> {
    let mut ans_vec = Vec::new();
    for i in 1..=n {
        if i != party_num {
            ans_vec.push(
                single_poll_for_p2p(
                    addr,
                    client,
                    party_num,
                    i,
                    delay,
                    round,
                    sender_uuid.clone(),
                )
                .await,
            );
        }
    }
    ans_vec
}

pub async fn single_poll_for_p2p(
    addr: &String,
    client: &Client,
    receiver_index: u16,
    sender_index: u16,
    delay: Duration,
    round: &str,
    sender_uuid: String,
) -> String {
    let ans: String;
    let key = format!(
        "{}-{}-{}-{}",
        sender_index, receiver_index, round, sender_uuid
    );
    let index = Index { key };
    loop {
        // add delay to allow the server to process request:
        tokio::time::sleep(delay).await;
        let res_body = postb(&addr, &client, "get", index.clone()).await;
        let answer: Result<Entry, ()> = serde_json::from_str(&res_body).unwrap();
        if let Ok(answer) = answer {
            ans = answer.value;
            println!(
                "[{:?}] party {:?} => party {:?}",
                round, sender_index, receiver_index
            );
            break;
        }
    }
    ans
}

#[allow(dead_code)]
pub fn check_sig(
    r: &Scalar<Secp256k1>,
    s: &Scalar<Secp256k1>,
    msg: &BigInt,
    pk: &Point<Secp256k1>,
) {
    let s_inv: Scalar<Secp256k1> = s.invert().unwrap_or_else(|| Scalar::<Secp256k1>::zero());
    let r_prime =
        (&s_inv * &Scalar::<Secp256k1>::from_bigint(&msg)) * Point::generator() + (r * &s_inv) * pk;
    assert_eq!(
        r_prime.x_coord().unwrap_or_else(|| BigInt::from(0u16)),
        r.to_bigint()
    );
}

pub fn scalar_split(num: &Scalar<Secp256k1>, count: &u16) -> Vec<Scalar<Secp256k1>> {
    let mut partition: Vec<Scalar<Secp256k1>> = Vec::new();
    for _j in 0..count - 1 {
        partition.push(Scalar::<Secp256k1>::random());
    }
    let partial_sum: Scalar<Secp256k1> = partition.iter().sum();
    partition.push(num - partial_sum);
    partition
}
