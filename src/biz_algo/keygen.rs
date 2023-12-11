// chain_code = left half of SHA512(pk)
use std::convert::TryInto;
use std::{fs, ops::Deref, time};

use crate::mp_ecdsa::{
    feldman_vss::VerifiableSS,
    party_i::{KeyGenBroadcastMessage1, KeyGenDecommitMessage1, Keys, Parameters},
};
use anyhow::Result;
use bip32::ChainCode;
use bip39::{Language, Mnemonic};
use curv::{
    arithmetic::traits::Converter,
    cryptographic_primitives::proofs::sigma_dlog::DLogProof,
    elliptic::curves::{secp256_k1::Secp256k1, Point, Scalar},
    BigInt,
};
use paillier::EncryptionKey;
use reqwest::Client;
use sha2::{Digest, Sha256, Sha512};

use crate::biz_algo::{
    aes_decrypt, aes_encrypt, broadcast, poll_for_broadcasts, poll_for_p2p, postb, sendp2p, Params,
    PartySignup, AEAD, *,
};

pub async fn run_keygen(
    addr: &String,
    keysfile_path: &String,
    params: &Vec<&str>,
) -> Result<(String, String), &'static str> {
    let threshold: u16 = params[0].parse::<u16>().unwrap();
    let parties: u16 = params[1].parse::<u16>().unwrap();

    let client = Client::new();

    // delay
    let delay = time::Duration::from_millis(25);
    let params = Parameters {
        threshold,
        share_count: parties,
    };

    // signup
    let tn_params = Params {
        threshold: threshold.to_string(),
        parties: parties.to_string(),
        share_count: parties.to_string(),
    };
    let party_signup = signup(&addr, &client, "signupkeygen", &tn_params).await;
    let party_num_int = party_signup.number;
    let uuid = party_signup.uuid;

    println!("number: {:?}, uuid: {:?}", party_num_int, uuid);
    unsafe {
        use crate::util::{MEMBER_ID, SESSION_ID};
        SESSION_ID.set(uuid.clone()).unwrap();
        MEMBER_ID.set(party_num_int).unwrap();
    }

    let party_keys = Keys::create(party_num_int);
    let mnemonic = Mnemonic::from_entropy(&party_keys.u_i.to_bytes(), Language::English).unwrap(); // 24-word mnemonic
    let phrase: &str = mnemonic.phrase();

    let (bc_i, decom_i) = party_keys.phase1_broadcast_phase3_proof_of_correct_key();
    // round 1: send commitment to ephemeral public keys
    broadcast(
        &addr,
        &client,
        party_num_int,
        "round1",
        serde_json::to_string(&bc_i).unwrap(),
        uuid.clone(),
    )
    .await;
    let round1_ans_vec = poll_for_broadcasts(
        &addr,
        &client,
        party_num_int,
        parties,
        delay,
        "round1",
        uuid.clone(),
    )
    .await;

    let mut bc1_vec = round1_ans_vec
        .iter()
        .map(|m| serde_json::from_str::<KeyGenBroadcastMessage1>(m).unwrap())
        .collect::<Vec<_>>();
    bc1_vec.insert(party_num_int as usize - 1, bc_i);

    // round 2: send ephemeral public keys
    broadcast(
        &addr,
        &client,
        party_num_int,
        "round2",
        serde_json::to_string(&decom_i).unwrap(),
        uuid.clone(),
    )
    .await;
    let round2_ans_vec = poll_for_broadcasts(
        &addr,
        &client,
        party_num_int,
        parties,
        delay,
        "round2",
        uuid.clone(),
    )
    .await;

    let mut j = 0;
    let mut point_vec: Vec<Point<Secp256k1>> = Vec::new();
    let mut decom_vec: Vec<KeyGenDecommitMessage1> = Vec::new();
    let mut enc_keys: Vec<BigInt> = Vec::new();
    for i in 1..=parties {
        if i == party_num_int {
            point_vec.push(decom_i.y_i.clone());
            decom_vec.push(decom_i.clone());
        } else {
            let decom_j: KeyGenDecommitMessage1 = serde_json::from_str(&round2_ans_vec[j]).unwrap();
            point_vec.push(decom_j.y_i.clone());
            decom_vec.push(decom_j.clone());
            enc_keys.push(
                (decom_j.y_i.clone() * party_keys.u_i.clone())
                    .x_coord()
                    .unwrap(),
            );
            j = j + 1;
        }
    }

    let (head, tail) = point_vec.split_at(1);
    let y_sum = tail.iter().fold(head[0].clone(), |acc, x| acc + x);

    // check commitment correctness
    let (vss_scheme, secret_shares, _index) = party_keys
        .phase1_verify_com_phase3_verify_correct_key_phase2_distribute(
            &params, &decom_vec, &bc1_vec,
        )
        .expect("invalid key");

    // round 3: send secret shares via aes-p2p
    let mut j = 0;
    for (k, i) in (1..=parties).enumerate() {
        if i != party_num_int {
            // prepare encrypted share for party i
            let key_i = BigInt::to_bytes(&enc_keys[j]);
            let plaintext = BigInt::to_bytes(&secret_shares[k].to_bigint());
            let aead_pack_i = aes_encrypt(&key_i, &plaintext);
            assert!(sendp2p(
                &addr,
                &client,
                party_num_int,
                i,
                "round3",
                serde_json::to_string(&aead_pack_i).unwrap(),
                uuid.clone(),
            )
            .await
            .is_ok());
            j += 1;
        }
    }
    let round3_ans_vec = poll_for_p2p(
        &addr,
        &client,
        party_num_int,
        parties,
        delay,
        "round3",
        uuid.clone(),
    )
    .await;

    let mut j = 0;
    let mut party_shares: Vec<Scalar<Secp256k1>> = Vec::new();
    for i in 1..=parties {
        if i == party_num_int {
            party_shares.push(secret_shares[(i - 1) as usize].clone());
        } else {
            let aead_pack: AEAD = serde_json::from_str(&round3_ans_vec[j]).unwrap();
            let key_i = BigInt::to_bytes(&enc_keys[j]);
            let out = aes_decrypt(&key_i, aead_pack);
            let out_bn = BigInt::from_bytes(&out);
            let out_fe = Scalar::<Secp256k1>::from(&out_bn);
            party_shares.push(out_fe);
            j += 1;
        }
    }

    // round 4: send vss commitments
    broadcast(
        &addr,
        &client,
        party_num_int,
        "round4",
        serde_json::to_string(&vss_scheme).unwrap(),
        uuid.clone(),
    )
    .await;
    let round4_ans_vec = poll_for_broadcasts(
        &addr,
        &client,
        party_num_int,
        parties,
        delay,
        "round4",
        uuid.clone(),
    )
    .await;

    let mut j = 0;
    let mut vss_scheme_vec: Vec<VerifiableSS<Secp256k1>> = Vec::new();
    for i in 1..=parties {
        if i == party_num_int {
            vss_scheme_vec.push(vss_scheme.clone());
        } else {
            let vss_scheme_j: VerifiableSS<Secp256k1> =
                serde_json::from_str(&round4_ans_vec[j]).unwrap();
            vss_scheme_vec.push(vss_scheme_j);
            j += 1;
        }
    }

    let (shared_keys, dlog_proof) = party_keys
        .phase2_verify_vss_construct_keypair_phase3_pok_dlog(
            &params,
            &point_vec,
            &party_shares,
            &vss_scheme_vec,
            party_num_int,
        )
        .expect("invalid vss");

    // round 5: send dlog proof
    broadcast(
        &addr,
        &client,
        party_num_int,
        "round5",
        serde_json::to_string(&dlog_proof).unwrap(),
        uuid.clone(),
    )
    .await;
    let round5_ans_vec = poll_for_broadcasts(
        &addr,
        &client,
        party_num_int,
        parties,
        delay,
        "round5",
        uuid.clone(),
    )
    .await;

    let mut j = 0;
    let mut dlog_proof_vec: Vec<DLogProof<Secp256k1, Sha256>> = Vec::new();
    for i in 1..=parties {
        if i == party_num_int {
            dlog_proof_vec.push(dlog_proof.clone());
        } else {
            let dlog_proof_j: DLogProof<Secp256k1, Sha256> =
                serde_json::from_str(&round5_ans_vec[j]).unwrap();
            dlog_proof_vec.push(dlog_proof_j);
            j += 1;
        }
    }
    Keys::verify_dlog_proofs(&params, &dlog_proof_vec, &point_vec).expect("bad dlog proof");

    // save key to file
    let paillier_key_vec = (0..parties)
        .map(|i| bc1_vec[i as usize].e.clone())
        .collect::<Vec<EncryptionKey>>();
    // let chain_code = ChainCode::from(&Sha512::digest(y_sum.to_bytes(false).deref())[..32]);
    let chain_code: ChainCode = Sha512::digest(y_sum.to_bytes(false).deref())[..32]
        .try_into()
        .unwrap();
    let keygen_json = serde_json::to_string(&(
        party_keys,
        shared_keys,
        party_num_int,
        vss_scheme_vec,
        paillier_key_vec,
        y_sum,
        chain_code,
    ))
    .unwrap();
    println!("Keys data written to file: {:?}", keysfile_path);
    println!("Phrase: {}", phrase);
    fs::write(&keysfile_path, keygen_json.clone()).expect("Unable to save !");
    Ok((phrase.to_string(), keygen_json))
}

pub async fn keygen_signup(
    addr: &String,
    client: &Client,
    params: &Params,
) -> Result<PartySignup, ()> {
    let res_body = postb(&addr, &client, "signupkeygen", params).await;
    serde_json::from_str(&res_body).unwrap()
}
