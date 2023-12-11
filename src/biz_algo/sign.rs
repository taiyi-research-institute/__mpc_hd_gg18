use std::time;

use crate::mp_ecdsa::{feldman_vss::*, mta::*, party_i::*};
use curv::{
    arithmetic::{BasicOps, Converter, Modulo},
    cryptographic_primitives::proofs::{
        sigma_correct_homomorphic_elgamal_enc::HomoELGamalProof, sigma_dlog::DLogProof,
    },
    elliptic::curves::{secp256_k1::Secp256k1, Point, Scalar},
    BigInt,
};
use paillier::*;
use reqwest::Client;
use serde_json::json;
use sha2::Sha256;

use crate::biz_algo::{
    broadcast, check_sig, poll_for_broadcasts, poll_for_p2p, sendp2p, signup, Params,
};

pub async fn sign(
    addr: &String,
    party_keys: Keys,
    shared_keys: SharedKeys,
    party_id: u16,
    vss_scheme_vec: &mut Vec<VerifiableSS<Secp256k1>>,
    paillier_key_vector: Vec<EncryptionKey>,
    y_sum: &Point<Secp256k1>,
    params: &Params,
    message: &[u8],
    tweak_sk: &Scalar<Secp256k1>,
) {
    let client = Client::new();
    let delay = time::Duration::from_millis(25);
    let threshold: u16 = params.threshold.parse::<u16>().unwrap();
    let parties: u16 = params.parties.parse::<u16>().unwrap();
    let share_count: u16 = params.share_count.parse::<u16>().unwrap();
    println!(
        "threshold: {}, parties: {}, share count: {}",
        threshold, parties, share_count
    );
    assert!(parties > threshold, "PARTIES smaller than THRESHOLD + 1");
    assert!(parties < share_count + 1, "PARTIES bigger than SHARE_COUNT");

    let party_signup = signup(&addr, &client, "signupkeygen", &params).await;
    let party_num_int = party_signup.number;
    let uuid = party_signup.uuid;
    unsafe {
        use crate::util::{MEMBER_ID, SESSION_ID};
        SESSION_ID.set(uuid.clone()).unwrap();
        MEMBER_ID.set(party_num_int).unwrap();
    }

    let debug = json!({"manager_addr": &addr, "party_num": party_num_int, "uuid": uuid});
    println!("{}", serde_json::to_string_pretty(&debug).unwrap());

    // round 0: collect signer IDs
    broadcast(
        &addr,
        &client,
        party_num_int,
        "round0",
        serde_json::to_string(&party_id).unwrap(),
        uuid.clone(),
    )
    .await;
    let round0_ans_vec = poll_for_broadcasts(
        &addr,
        &client,
        party_num_int,
        parties,
        delay,
        "round0",
        uuid.clone(),
    )
    .await;
    let mut signers_vec = round0_ans_vec
        .iter()
        .map(|m| serde_json::from_str::<u16>(m).unwrap() - 1)
        .collect::<Vec<_>>();
    signers_vec.insert(party_num_int as usize - 1, party_id - 1);

    /*
    // to be theoretically correct everywhere
    if sign_at_path == true {
        // update uj * G as (uj + tweak_sk) * G
        // where j = party_id of party_num_int == 1
        vss_scheme_vec[usize::from(signers_vec[usize::from(0u16)])].commitments[0] =
            vss_scheme_vec[usize::from(signers_vec[usize::from(0u16)])].commitments[0].clone()
            + Point::generator() * tweak_sk;
    }
    let mut private = PartyPrivate::set_private(party_keys.clone(), shared_keys);
    if sign_at_path == true {
        if party_num_int == 1 {
            // update uj as (uj + tweak_sk) and xj as (xj + tweak_sk)
            private = private.update_private_key(&tweak_sk, &tweak_sk);
        } else {
            // only update xi as (xi + tweak_sk)
            private = private.update_private_key(&Scalar::<Secp256k1>::zero(), &tweak_sk);
        }
    }
    */

    // to be practically tricky, only applicable to sign
    // (1) ignore sign_at_path
    // (2) omit updates for all ui
    // (3) only update u1 * G as (u1 + tweak_sk) * G and all xi as (xi + tweak_sk)
    vss_scheme_vec[0].commitments[0] =
        vss_scheme_vec[0].commitments[0].clone() + Point::generator() * tweak_sk;
    let mut private = PartyPrivate::set_private(party_keys.clone(), shared_keys);
    private = private.update_private_key(&Scalar::<Secp256k1>::zero(), &tweak_sk);

    let sign_keys = SignKeys::create(
        &private,
        &vss_scheme_vec[usize::from(signers_vec[usize::from(party_num_int - 1)])],
        signers_vec[usize::from(party_num_int - 1)],
        &signers_vec,
    );

    let (com, decommit) = sign_keys.phase1_broadcast();
    let (m_a_k, _) = MessageA::a(&sign_keys.k_i, &party_keys.ek, &[]);
    // round 1: send commitment and do MtA/MtAwc (a) (b)
    broadcast(
        &addr,
        &client,
        party_num_int,
        "round1",
        serde_json::to_string(&(com.clone(), m_a_k.clone())).unwrap(),
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

    let mut j = 0;
    let mut bc1_vec: Vec<SignBroadcastPhase1> = Vec::new();
    let mut m_a_vec: Vec<MessageA> = Vec::new();

    for i in 1..=parties {
        if i == party_num_int {
            bc1_vec.push(com.clone());
        } else {
            let (bc1_j, m_a_party_j): (SignBroadcastPhase1, MessageA) =
                serde_json::from_str(&round1_ans_vec[j]).unwrap();
            bc1_vec.push(bc1_j);
            m_a_vec.push(m_a_party_j);
            j = j + 1;
        }
    }
    assert_eq!(signers_vec.len(), bc1_vec.len());

    // do MtA/MtAwc (c) (d)
    let mut m_b_gamma_send_vec: Vec<MessageB> = Vec::new();
    let mut beta_vec: Vec<Scalar<Secp256k1>> = Vec::new();
    let mut m_b_w_send_vec: Vec<MessageB> = Vec::new();
    let mut ni_vec: Vec<Scalar<Secp256k1>> = Vec::new();
    let mut j = 0;
    for i in 1..=parties {
        if i != party_num_int {
            let (m_b_gamma, beta_gamma, _, _) = MessageB::b(
                &sign_keys.gamma_i,
                &paillier_key_vector[usize::from(signers_vec[usize::from(i - 1)])],
                m_a_vec[j].clone(),
                &[],
            )
            .unwrap();
            let (m_b_w, beta_wi, _, _) = MessageB::b(
                &sign_keys.w_i,
                &paillier_key_vector[usize::from(signers_vec[usize::from(i - 1)])],
                m_a_vec[j].clone(),
                &[],
            )
            .unwrap();
            m_b_gamma_send_vec.push(m_b_gamma);
            m_b_w_send_vec.push(m_b_w);
            beta_vec.push(beta_gamma);
            ni_vec.push(beta_wi);
            j = j + 1;
        }
    }

    // round 2: send Paillier ciphertext
    let mut j = 0;
    for i in 1..=parties {
        if i != party_num_int {
            assert!(sendp2p(
                &addr,
                &client,
                party_num_int,
                i,
                "round2",
                serde_json::to_string(&(m_b_gamma_send_vec[j].clone(), m_b_w_send_vec[j].clone()))
                    .unwrap(),
                uuid.clone(),
            )
            .await
            .is_ok());
            j = j + 1;
        }
    }

    let round2_ans_vec = poll_for_p2p(
        &addr,
        &client,
        party_num_int,
        parties,
        delay,
        "round2",
        uuid.clone(),
    )
    .await;

    let mut m_b_gamma_rec_vec: Vec<MessageB> = Vec::new();
    let mut m_b_w_rec_vec: Vec<MessageB> = Vec::new();

    for i in 0..parties - 1 {
        let (m_b_gamma_i, m_b_w_i): (MessageB, MessageB) =
            serde_json::from_str(&round2_ans_vec[i as usize]).unwrap();
        m_b_gamma_rec_vec.push(m_b_gamma_i);
        m_b_w_rec_vec.push(m_b_w_i);
    }

    // do MtA (e) / MtAwc (e) (f)
    let mut alpha_vec: Vec<Scalar<Secp256k1>> = Vec::new();
    let mut miu_vec: Vec<Scalar<Secp256k1>> = Vec::new();

    let xi_com_vec = Keys::get_commitments_to_xi(&vss_scheme_vec);
    let mut j = 0;
    for i in 1..=parties {
        if i != party_num_int {
            let m_b = m_b_gamma_rec_vec[j].clone();
            let alpha_ij_gamma = m_b
                .verify_proofs_get_alpha(&party_keys.dk, &sign_keys.k_i)
                .expect("wrong dlog or m_b");
            let m_b = m_b_w_rec_vec[j].clone();
            let alpha_ij_wi = m_b
                .verify_proofs_get_alpha(&party_keys.dk, &sign_keys.k_i)
                .expect("wrong dlog or m_b");
            alpha_vec.push(alpha_ij_gamma.0);
            miu_vec.push(alpha_ij_wi.0);
            let g_w_i = Keys::update_commitments_to_xi(
                &xi_com_vec[usize::from(signers_vec[usize::from(i - 1)])],
                &vss_scheme_vec[usize::from(signers_vec[usize::from(i - 1)])],
                signers_vec[usize::from(i - 1)],
                &signers_vec,
            );
            assert_eq!(m_b.b_proof.pk.clone(), g_w_i);
            j = j + 1;
        }
    }

    let delta_i = sign_keys.phase2_delta_i(&alpha_vec, &beta_vec);
    let sigma = sign_keys.phase2_sigma_i(&miu_vec, &ni_vec);

    // round 3: send delta_i
    broadcast(
        &addr,
        &client,
        party_num_int,
        "round3",
        serde_json::to_string(&delta_i).unwrap(),
        uuid.clone(),
    )
    .await;
    let round3_ans_vec = poll_for_broadcasts(
        &addr,
        &client,
        party_num_int,
        parties,
        delay,
        "round3",
        uuid.clone(),
    )
    .await;
    let mut delta_vec: Vec<Scalar<Secp256k1>> = Vec::new();
    format_vec_from_reads(
        &round3_ans_vec,
        party_num_int as usize,
        delta_i,
        &mut delta_vec,
    );
    let delta_inv = SignKeys::phase3_reconstruct_delta(&delta_vec);

    // round 4: send decommitment to g_gamma_i
    broadcast(
        &addr,
        &client,
        party_num_int,
        "round4",
        serde_json::to_string(&decommit).unwrap(),
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
    let mut decommit_vec: Vec<SignDecommitPhase1> = Vec::new();
    format_vec_from_reads(
        &round4_ans_vec,
        party_num_int as usize,
        decommit,
        &mut decommit_vec,
    );
    let decomm_i = decommit_vec.remove((party_num_int - 1) as usize);
    bc1_vec.remove((party_num_int - 1) as usize);
    let b_proof_vec = (0..m_b_gamma_rec_vec.len())
        .map(|i| &m_b_gamma_rec_vec[i].b_proof)
        .collect::<Vec<&DLogProof<Secp256k1, Sha256>>>();
    let R = SignKeys::phase4(&delta_inv, &b_proof_vec, decommit_vec, &bc1_vec)
        .expect("bad gamma_i decommit");

    // add local g_gamma_i
    let R = R + decomm_i.g_gamma_i * &delta_inv;

    // assume the message is already hashed (by the signer)
    let message_bn = BigInt::from_bytes(message);
    let message_int = BigInt::from_bytes(message);
    let two = BigInt::from(2);
    let message_bn = message_bn.modulus(&two.pow(256));
    let local_sig =
        LocalSignature::phase5_local_sig(&sign_keys.k_i, &message_bn, &R, &sigma, &y_sum);

    let (phase5_com, phase_5a_decom, helgamal_proof, dlog_proof_rho) =
        local_sig.phase5a_broadcast_5b_zkproof();

    // round 5: GG18 Phase(5A)
    broadcast(
        &addr,
        &client,
        party_num_int,
        "round5",
        serde_json::to_string(&phase5_com).unwrap(),
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
    let mut commit5a_vec: Vec<Phase5Com1> = Vec::new();
    format_vec_from_reads(
        &round5_ans_vec,
        party_num_int.clone() as usize,
        phase5_com,
        &mut commit5a_vec,
    );

    // round 6: GG18 Phase(5B)
    broadcast(
        &addr,
        &client,
        party_num_int,
        "round6",
        serde_json::to_string(&(
            phase_5a_decom.clone(),
            helgamal_proof.clone(),
            dlog_proof_rho.clone(),
        ))
        .unwrap(),
        uuid.clone(),
    )
    .await;
    let round6_ans_vec = poll_for_broadcasts(
        &addr,
        &client,
        party_num_int,
        parties,
        delay,
        "round6",
        uuid.clone(),
    )
    .await;
    let mut decommit5a_and_elgamal_and_dlog_vec: Vec<(
        Phase5ADecom1,
        HomoELGamalProof<Secp256k1, Sha256>,
        DLogProof<Secp256k1, Sha256>,
    )> = Vec::new();
    format_vec_from_reads(
        &round6_ans_vec,
        party_num_int as usize,
        (
            phase_5a_decom.clone(),
            helgamal_proof.clone(),
            dlog_proof_rho.clone(),
        ),
        &mut decommit5a_and_elgamal_and_dlog_vec,
    );
    let decommit5a_and_elgamal_vec_includes_i = decommit5a_and_elgamal_and_dlog_vec.clone();
    decommit5a_and_elgamal_and_dlog_vec.remove((party_num_int - 1) as usize);
    commit5a_vec.remove((party_num_int - 1) as usize);
    let phase_5a_decomm_vec = (0..parties - 1)
        .map(|i| decommit5a_and_elgamal_and_dlog_vec[i as usize].0.clone())
        .collect::<Vec<Phase5ADecom1>>();
    let phase_5a_elgamal_vec = (0..parties - 1)
        .map(|i| decommit5a_and_elgamal_and_dlog_vec[i as usize].1.clone())
        .collect::<Vec<HomoELGamalProof<Secp256k1, Sha256>>>();
    let phase_5a_dlog_vec = (0..parties - 1)
        .map(|i| decommit5a_and_elgamal_and_dlog_vec[i as usize].2.clone())
        .collect::<Vec<DLogProof<Secp256k1, Sha256>>>();
    let (phase5_com2, phase_5d_decom2) = local_sig
        .phase5c(
            &phase_5a_decomm_vec,
            &commit5a_vec,
            &phase_5a_elgamal_vec,
            &phase_5a_dlog_vec,
            &phase_5a_decom.V_i,
            &R.clone(),
        )
        .expect("error phase5");

    // round 7: GG18 Phase(5C)
    broadcast(
        &addr,
        &client,
        party_num_int,
        "round7",
        serde_json::to_string(&phase5_com2).unwrap(),
        uuid.clone(),
    )
    .await;
    let round7_ans_vec = poll_for_broadcasts(
        &addr,
        &client,
        party_num_int,
        parties,
        delay,
        "round7",
        uuid.clone(),
    )
    .await;
    let mut commit5c_vec: Vec<Phase5Com2> = Vec::new();
    format_vec_from_reads(
        &round7_ans_vec,
        party_num_int.clone() as usize,
        phase5_com2,
        &mut commit5c_vec,
    );

    // round 8: GG18 Phase(5D)
    broadcast(
        &addr,
        &client,
        party_num_int,
        "round8",
        serde_json::to_string(&phase_5d_decom2).unwrap(),
        uuid.clone(),
    )
    .await;
    let round8_ans_vec = poll_for_broadcasts(
        &addr,
        &client,
        party_num_int,
        parties,
        delay,
        "round8",
        uuid.clone(),
    )
    .await;
    let mut decommit5d_vec: Vec<Phase5DDecom2> = Vec::new();
    format_vec_from_reads(
        &round8_ans_vec,
        party_num_int.clone() as usize,
        phase_5d_decom2.clone(),
        &mut decommit5d_vec,
    );

    let phase_5a_decomm_vec_includes_i = (0..parties)
        .map(|i| decommit5a_and_elgamal_vec_includes_i[i as usize].0.clone())
        .collect::<Vec<Phase5ADecom1>>();
    let s_i = local_sig
        .phase5d(
            &decommit5d_vec,
            &commit5c_vec,
            &phase_5a_decomm_vec_includes_i,
        )
        .expect("bad com 5d");

    // round 9: GG18 Phase(5E)
    broadcast(
        &addr,
        &client,
        party_num_int,
        "round9",
        serde_json::to_string(&s_i).unwrap(),
        uuid.clone(),
    )
    .await;
    let round9_ans_vec = poll_for_broadcasts(
        &addr,
        &client,
        party_num_int,
        parties,
        delay,
        "round9",
        uuid.clone(),
    )
    .await;
    let mut s_i_vec: Vec<Scalar<Secp256k1>> = Vec::new();
    format_vec_from_reads(
        &round9_ans_vec,
        party_num_int.clone() as usize,
        s_i,
        &mut s_i_vec,
    );

    s_i_vec.remove((party_num_int - 1) as usize);
    let sig = local_sig
        .output_signature(&s_i_vec)
        .expect("verification failed");

    println!("child pubkey: {:#?} \n", y_sum);
    println!("verifying signature with child pub key");

    // let ret_dict = json!({
    //     "r": BigInt::from_bytes(sig.r.to_bytes().as_ref()).to_str_radix(16),
    //     "s": BigInt::from_bytes(sig.s.to_bytes().as_ref()).to_str_radix(16),
    //     "status": "signature_ready",
    //     "recid": sig.recid.clone(),
    //     "x": &y_sum.x_coord(),
    //     "y": &y_sum.y_coord(),
    //     "msg_int": message_int,
    // });
    check_sig(&sig.r, &sig.s, &message_bn, &y_sum);
    println!("party {:?} Output Signature: \n", party_num_int);
    println!("r: {:#?}", sig.r);
    println!("s: {:#?} \n", sig.s);
    println!("recid: {:?} \n", sig.recid.clone());
    println!("x: {:#?}", &y_sum.x_coord());
    println!("y: {:#?}", &y_sum.y_coord());
    println!("msg_int: {}", message_int);
}

fn format_vec_from_reads<'a, T: serde::Deserialize<'a> + Clone>(
    ans_vec: &'a Vec<String>,
    party_num: usize,
    value_i: T,
    new_vec: &'a mut Vec<T>,
) {
    let mut j = 0;
    for i in 1..ans_vec.len() + 2 {
        if i == party_num {
            new_vec.push(value_i.clone());
        } else {
            let value_j: T = serde_json::from_str(&ans_vec[j]).unwrap();
            new_vec.push(value_j);
            j = j + 1;
        }
    }
}
