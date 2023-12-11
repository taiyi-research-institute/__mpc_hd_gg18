// reshare_smarter version under (t,n)-scheme
// m ( n <= m <= 2 * n) parties involved, ONLY n parties receive new shares
// t' (t' > t) parties give x_i
#![allow(unused_variables, unused_assignments, dead_code)]
use std::iter::zip;
use std::{fs, ops::Deref, time};

use crate::mp_ecdsa::{
    feldman_vss::{ShamirSecretSharing, VerifiableSS},
    party_i::*,
};
use bip32::ChainCode;
use bip39::{Language, Mnemonic};
use curv::{
    arithmetic::traits::Converter,
    cryptographic_primitives::{
        commitments::{hash_commitment::HashCommitment, traits::Commitment},
        proofs::sigma_dlog::DLogProof,
    },
    elliptic::curves::{secp256_k1::Secp256k1, Point, Scalar},
    BigInt,
};
use paillier::*;
use reqwest::Client;
use serde_json::json;
use sha2::{Digest, Sha256, Sha512};
use std::convert::TryInto;

use crate::biz_algo::{
    aes_decrypt, aes_encrypt, broadcast, poll_all_for_p2p, poll_for_broadcasts, scalar_split,
    sendp2p, Params, PartySignup, AEAD,
};

pub async fn reshare_all_xi(
    addr: String,
    params: &Params,
    keysfile_path: &String,
    if_give: bool,    // if give x_i
    if_hold: bool,    // if hold old shares
    if_receive: bool, // if receive new shares
) {
    let client = Client::new();
    let delay = time::Duration::from_millis(25);
    let threshold: u16 = params.threshold.parse::<u16>().unwrap();
    let parties: u16 = params.parties.parse::<u16>().unwrap(); // all parties that contribute/receive shares
    let share_count: u16 = params.share_count.parse::<u16>().unwrap();
    println!(
        "threshold: {}, parties: {}, share count: {}",
        threshold, parties, share_count
    );
    assert!(
        (parties >= share_count) && (parties <= 2 * share_count),
        "PARTIES smaller (or larger) than SHARE_COUNT (* 2)"
    );
    assert!(
        (if_give && if_hold) == if_give,
        "IF_GIVE contradicts IF_HOLD"
    );
    assert!(if_give || if_receive, "at least either GIVE or RECEIVE");

    // signup, party_num_int in [1..m]
    let (party_num_int, uuid) = match signup(&addr, &client, &params).await.unwrap() {
        PartySignup { number, uuid } => (number, uuid),
    };

    unsafe {
        use crate::util::{MEMBER_ID, SESSION_ID};
        SESSION_ID.set(uuid.clone()).unwrap();
        MEMBER_ID.set(party_num_int).unwrap();
    }

    let debug = json!({"manager_addr": &addr, "party_num": party_num_int, "uuid": uuid});
    println!("{}", serde_json::to_string_pretty(&debug).unwrap());

    // initialization
    let mut party_keys = Keys::create(party_num_int);
    let mut shared_keys = SharedKeys {
        y: Point::<Secp256k1>::zero(),
        x_i: Scalar::<Secp256k1>::random(),
    };
    let mut party_id = parties + 1;
    let vss_scheme_zero = VerifiableSS::<Secp256k1> {
        parameters: ShamirSecretSharing {
            threshold,
            share_count,
        },
        commitments: vec![Point::<Secp256k1>::zero(); threshold as usize + 1],
    };
    let mut vss_scheme_vec: Vec<VerifiableSS<Secp256k1>> = Vec::with_capacity(share_count as usize);
    let mut paillier_key_vec: Vec<EncryptionKey> = Vec::with_capacity(share_count as usize);
    let mut expected_y_sum = Point::<Secp256k1>::generator().to_point();
    // let mut chain_code =
    //     ChainCode::from(&Sha512::digest(expected_y_sum.to_bytes(false).deref())[..32]);
    let mut chain_code: ChainCode = Sha512::digest(expected_y_sum.to_bytes(false).deref())[..32]
        .try_into()
        .unwrap();

    // read data from keys file
    if if_give {
        let data = fs::read_to_string(keysfile_path)
            .expect(format!("Unable to load keys file at location: {}", keysfile_path).as_str());
        (
            party_keys,
            shared_keys,
            party_id,
            vss_scheme_vec,
            paillier_key_vec,
            expected_y_sum,
            chain_code,
        ) = serde_json::from_str(&data).unwrap();
    }

    // round 0: collect party info
    broadcast(
        &addr,
        &client,
        party_num_int,
        "round0",
        serde_json::to_string(&(party_num_int, party_id, if_give, if_hold, if_receive)).unwrap(),
        uuid.clone(),
    )
    .await;
    let round0_ans_vec =
        poll_for_broadcasts(&addr, &client, 0u16, parties, delay, "round0", uuid.clone()).await;
    let reshare_info_vec = round0_ans_vec
        .iter()
        .map(|m| serde_json::from_str::<(u16, u16, bool, bool, bool)>(m).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(reshare_info_vec.len(), parties as usize);

    let (givers_vec, givers_id_vec): (Vec<_>, Vec<_>) = reshare_info_vec
        .iter()
        .filter(|x| x.2)
        .map(|x| (x.0, x.1 - 1))
        .unzip();
    let holders_vec = reshare_info_vec
        .iter()
        .filter(|x| x.3)
        .map(|x| x.0)
        .collect::<Vec<u16>>();
    let receivers_vec = reshare_info_vec
        .iter()
        .filter(|x| x.4)
        .map(|x| x.0)
        .collect::<Vec<u16>>();

    let givers: u16 = givers_vec.len() as u16;
    assert!(
        givers_vec.len() > threshold as usize,
        "GIVERS no smaller than THRESHOLD + 1"
    );
    assert!(
        holders_vec.len() <= share_count as usize,
        "HOLDERS no more than SHARE_COUNT"
    );
    assert!(
        receivers_vec.len() == share_count as usize,
        "RECEIVERS should be SHARE_COUNT"
    );
    println!("givers: {:?}", givers_vec);
    println!("holders: {:?}", holders_vec);
    println!("receivers: {:?}", receivers_vec);

    // derive w_i from x_i and split
    let mut w_i = Scalar::<Secp256k1>::random();
    if if_give {
        let lambda = VerifiableSS::<Secp256k1>::map_share_to_new_params(
            &ShamirSecretSharing {
                threshold,
                share_count,
            },
            party_id - 1,
            &givers_id_vec,
        );
        w_i = lambda * &shared_keys.x_i;
    }
    let w_i_partition = scalar_split(&w_i, &share_count);

    let mut party_keys_wi = Keys::create_from(w_i.clone(), party_num_int);
    let (com_i, decom_i) = party_keys_wi.phase1_broadcast_phase3_proof_of_correct_key();

    // round 1: send commitment to g_w_i
    broadcast(
        &addr,
        &client,
        party_num_int,
        "round1",
        serde_json::to_string(&com_i).unwrap(),
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
    let mut com_vec = round1_ans_vec
        .iter()
        .map(|m| serde_json::from_str::<KeyGenBroadcastMessage1>(m).unwrap())
        .collect::<Vec<_>>();
    com_vec.insert(party_num_int as usize - 1, com_i);

    // round 2: send decommitment to g_w_i
    broadcast(
        &addr,
        &client,
        party_num_int,
        "round2",
        serde_json::to_string(&decom_i).unwrap(),
        uuid.clone(),
    )
    .await;
    let round2_ans_vec =
        poll_for_broadcasts(&addr, &client, 0u16, parties, delay, "round2", uuid.clone()).await;

    // len PARTIES, ordered by PARTY_NUM_INT
    let mut point_vec: Vec<Point<Secp256k1>> = Vec::new();
    let mut decom_vec: Vec<KeyGenDecommitMessage1> = Vec::new();
    let mut enc_keys: Vec<BigInt> = Vec::new();
    for x in round2_ans_vec.iter() {
        let decom_j: KeyGenDecommitMessage1 = serde_json::from_str(&x).unwrap();
        point_vec.push(decom_j.y_i.clone());
        decom_vec.push(decom_j.clone());
        enc_keys.push(
            (decom_j.y_i.clone() * party_keys_wi.u_i.clone())
                .x_coord()
                .unwrap(),
        );
    }

    // test length
    assert_eq!(decom_vec.len(), usize::from(parties));
    assert_eq!(com_vec.len(), usize::from(parties));
    // test decommitment and paillier key proof
    let correct_key_correct_decom_all = (0..com_vec.len()).all(|i| {
        HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(
            &BigInt::from_bytes(decom_vec[i].y_i.to_bytes(true).as_ref()),
            &decom_vec[i].blind_factor,
        ) == com_vec[i].com
            && com_vec[i]
                .correct_key_proof
                .verify(&com_vec[i].e, zk_paillier::zkproofs::SALT_STRING)
                .is_ok()
    });
    if !correct_key_correct_decom_all {
        panic!("invalid key");
    }
    let y_sum: Point<Secp256k1> = givers_vec
        .iter()
        .fold(Point::<Secp256k1>::zero(), |acc, x| {
            acc + point_vec[*x as usize - 1].clone()
        });
    if if_give {
        assert_eq!(y_sum.x_coord(), expected_y_sum.x_coord());
        assert_eq!(y_sum.y_coord(), expected_y_sum.y_coord());
    }

    let (vss_scheme, secret_shares) = VerifiableSS::share(threshold, share_count, &w_i);
    let secret_shares_vec = secret_shares.to_vec();
    // round 3: update vss_scheme_vec
    if if_give {
        let pos_give = givers_vec.iter().position(|&x| x == party_num_int).unwrap() as u16;
        broadcast(
            &addr,
            &client,
            &pos_give + 1,
            "round3",
            serde_json::to_string(&vss_scheme).unwrap(),
            uuid.clone(),
        )
        .await;
    }
    let round3_ans_vec =
        poll_for_broadcasts(&addr, &client, 0u16, givers, delay, "round3", uuid.clone()).await;
    vss_scheme_vec = round3_ans_vec
        .iter()
        .map(|m| serde_json::from_str::<VerifiableSS<Secp256k1>>(m).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(vss_scheme_vec.len(), usize::from(givers));
    if givers < share_count {
        vss_scheme_vec.resize(share_count.into(), vss_scheme_zero);
    }

    // round 4: send 2 shares and 1 chain code to receivers by index
    if if_give {
        let pos_give = givers_vec.iter().position(|&x| x == party_num_int).unwrap() as u16;
        for ((secret_share, w_i_share), receiver_index) in
            zip(zip(&secret_shares_vec, &w_i_partition), &receivers_vec)
        {
            let key_i = BigInt::to_bytes(&enc_keys[*receiver_index as usize - 1]);
            let mut plaintext = BigInt::to_bytes(&secret_share.to_bigint());
            let aead_pack_i1 = aes_encrypt(&key_i, &plaintext);
            plaintext = BigInt::to_bytes(&w_i_share.to_bigint());
            let aead_pack_i2 = aes_encrypt(&key_i, &plaintext);
            plaintext = BigInt::to_bytes(&BigInt::from_bytes(&chain_code));
            let aead_pack_i3 = aes_encrypt(&key_i, &plaintext);
            assert!(sendp2p(
                &addr,
                &client,
                &pos_give + 1,
                *receiver_index,
                "round4",
                serde_json::to_string(&(aead_pack_i1, aead_pack_i2, aead_pack_i3)).unwrap(),
                uuid.clone()
            )
            .await
            .is_ok());
        }
    }

    if if_receive {
        let round4_ans_vec = poll_all_for_p2p(
            &addr,
            &client,
            party_num_int,
            givers,
            delay,
            "round4",
            uuid.clone(),
        )
        .await;
        assert_eq!(round4_ans_vec.len(), givers as usize);

        let mut party_shares: Vec<Scalar<Secp256k1>> = Vec::new();
        let mut w_ji_vec: Vec<Scalar<Secp256k1>> = Vec::new();
        let mut chain_code_vec: Vec<ChainCode> = Vec::new();
        for (round4_ans, giver_index) in zip(&round4_ans_vec, &givers_vec) {
            let (aead_pack_i1, aead_pack_i2, aead_pack_i3) =
                serde_json::from_str::<(AEAD, AEAD, AEAD)>(round4_ans).unwrap();
            let key_i = BigInt::to_bytes(&enc_keys[*giver_index as usize - 1]);
            let mut out = aes_decrypt(&key_i, aead_pack_i1);
            let mut out_bn = BigInt::from_bytes(&out[..]);
            let mut out_fe = Scalar::<Secp256k1>::from(&out_bn);
            party_shares.push(out_fe);

            out = aes_decrypt(&key_i, aead_pack_i2);
            out_bn = BigInt::from_bytes(&out[..]);
            out_fe = Scalar::<Secp256k1>::from(&out_bn);
            w_ji_vec.push(out_fe);

            out = aes_decrypt(&key_i, aead_pack_i3);
            // chain_code_vec.push(ChainCode::from(out.as_slice()));
            chain_code_vec.push(out.try_into().unwrap());
        }
        assert!(
            &chain_code_vec.windows(2).all(|w| w[0] == w[1]),
            "chain code received not match!"
        );

        // test length
        assert_eq!(party_shares.len(), givers as usize);
        // test polynomial evaluation
        let pos_rec = receivers_vec
            .iter()
            .position(|&x| x == party_num_int)
            .unwrap() as u16;
        let correct_ss_verify = (0..party_shares.len()).all(|i| {
            vss_scheme_vec[i]
                .validate_share(&party_shares[i], &pos_rec + 1)
                .is_ok()
        });
        if !correct_ss_verify {
            panic!("invalid vss")
        }

        shared_keys.x_i = party_shares.iter().sum();
        shared_keys.y = y_sum.clone();
        println!("NEW x_{:?}: {:#?}", &pos_rec + 1, &shared_keys.x_i);

        // proof of x_i by Schnorr identification protocol
        let dlog_proof: DLogProof<Secp256k1, Sha256> = DLogProof::prove(&shared_keys.x_i);
        // round 5: send dlog proof
        broadcast(
            &addr,
            &client,
            &pos_rec + 1,
            "round5",
            serde_json::to_string(&dlog_proof).unwrap(),
            uuid.clone(),
        )
        .await;
        let round5_ans_vec = poll_for_broadcasts(
            &addr,
            &client,
            0u16,
            share_count,
            delay,
            "round5",
            uuid.clone(),
        )
        .await;
        let dlog_proof_vec = round5_ans_vec
            .iter()
            .map(|m| serde_json::from_str::<DLogProof<Secp256k1, Sha256>>(m).unwrap())
            .collect::<Vec<_>>();
        let point_vec_new: Vec<Point<Secp256k1>> = receivers_vec
            .iter()
            .map(|x| point_vec[*x as usize - 1].clone())
            .collect::<Vec<_>>();
        Keys::verify_dlog_proofs(
            &Parameters {
                threshold,
                share_count,
            },
            &dlog_proof_vec,
            &point_vec_new,
        )
        .expect("bad dlog proof");

        if parties == (holders_vec.len() as u16) {
            let data = fs::read_to_string(keysfile_path).expect(
                format!("Unable to load keys file at location: {}", keysfile_path).as_str(),
            );
            let (mut party_keys, _, _, _, mut paillier_key_vec, _, chain_code): (
                Keys,
                SharedKeys,
                u16,
                Vec<VerifiableSS<Secp256k1>>,
                Vec<EncryptionKey>,
                Point<Secp256k1>,
                ChainCode,
            ) = serde_json::from_str(&data).unwrap();
            assert!(chain_code == chain_code_vec[0], "chain code not match!");
            party_keys.party_index = &pos_rec + 1;
            paillier_key_vec = receivers_vec
                .iter()
                .map(|x| paillier_key_vec[*x as usize - 1].clone())
                .collect::<Vec<EncryptionKey>>();
            // save key to file:
            let mnemonic =
                Mnemonic::from_entropy(&party_keys.u_i.to_bytes(), Language::English).unwrap();
            let share_phrase: &str = mnemonic.phrase(); // 24-word
            let keygen_json = serde_json::to_string(&(
                party_keys,
                shared_keys,
                &pos_rec + 1,
                vss_scheme_vec,
                paillier_key_vec,
                y_sum,
                chain_code,
            ))
            .unwrap();
            println!("Keys data written to file: {:?}", keysfile_path);
            println!("Phrase of u_i: {}", share_phrase);
            fs::write(&keysfile_path, keygen_json).expect("Unable to save !");
        } else {
            party_keys_wi.u_i = w_ji_vec.iter().sum();
            party_keys_wi.y_i = &party_keys_wi.u_i * Point::<Secp256k1>::generator();
            party_keys_wi.party_index = &pos_rec + 1;
            paillier_key_vec = receivers_vec
                .iter()
                .map(|x| com_vec[*x as usize - 1].e.clone())
                .collect::<Vec<EncryptionKey>>();
            //save key to file:
            let mnemonic =
                Mnemonic::from_entropy(&party_keys_wi.u_i.to_bytes(), Language::English).unwrap();
            let share_phrase: &str = mnemonic.phrase(); // 24-word
            let keygen_json = serde_json::to_string(&(
                party_keys_wi,
                shared_keys,
                &pos_rec + 1,
                vss_scheme_vec,
                paillier_key_vec,
                y_sum,
                chain_code_vec[0],
            ))
            .unwrap();
            println!("Keys data written to file: {:?}", keysfile_path);
            println!("Phrase of u_i: {}", share_phrase);
            fs::write(&keysfile_path, keygen_json).expect("Unable to save !");
        }
    }
    println!("THE END!");
}

pub async fn signup(addr: &String, client: &Client, params: &Params) -> Result<PartySignup, ()> {
    let res_body = postb(&addr, &client, "signupreshare", params)
        .await
        .unwrap();
    let answer: Result<PartySignup, ()> = serde_json::from_str(&res_body).unwrap();
    return answer;
}

pub async fn postb<T>(addr: &String, client: &Client, path: &str, body: T) -> Option<String>
where
    T: serde::ser::Serialize,
{
    let res = client
        .post(&format!("{}/{}", addr, path))
        .json(&body)
        .send()
        .await;
    Some(res.unwrap().text().await.unwrap())
}
