// replace (bitcoin::util::bip32, secp256k1) by (bip32, k256 v0.11.0)

use bip32::{
    ChainCode, ChildNumber, DerivationPath, Error, ExtendedKey, ExtendedKeyAttrs, Prefix,
    PrivateKey, PublicKey, Result, XPrv, XPub, KEY_SIZE,
};
use curv::elliptic::curves::{secp256_k1::Secp256k1, Point, Scalar};
use hmac::{Hmac, Mac, NewMac};
use std::{
    convert::{TryFrom, TryInto},
    str::FromStr,
};

pub type HmacSha512 = Hmac<sha2::Sha512>;

// input: path_str (&str), public_key (Point<Secp256k1>)
// output: tweak_sk (Scalar<Secp256k1>), new_public_key (Point<Secp256k1>)
pub fn get_hd_key(
    path_str: &str,
    par_pk: Point<Secp256k1>,
    chain_code: ChainCode,
) -> Result<(Scalar<Secp256k1>, Point<Secp256k1>)> {
    let path = DerivationPath::from_str(path_str).unwrap();
    let mut ex_pk = ExtendedKey {
        prefix: Prefix::XPUB,
        attrs: ExtendedKeyAttrs {
            parent_fingerprint: [0u8; 4],
            child_number: ChildNumber(0u32),
            chain_code,
            depth: 0u8,
        },
        key_bytes: <&[u8] as TryInto<[u8; 33]>>::try_into(par_pk.to_bytes(true).as_ref()).unwrap(),
    };
    let mut pk = XPub::try_from(ex_pk).unwrap();
    let scalar_one = XPrv::try_from(ExtendedKey {
        prefix: Prefix::XPRV,
        attrs: ExtendedKeyAttrs {
            parent_fingerprint: [0u8; 4],
            child_number: ChildNumber(0u32),
            chain_code,
            depth: 0u8,
        },
        key_bytes: [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 1,
        ],
    })
    .unwrap();
    let mut total_tweak = scalar_one.private_key().clone();
    for ccnum in path.as_ref() {
        let depth = pk.attrs().depth.checked_add(1).ok_or(Error::Depth)?;

        let mut hmac =
            HmacSha512::new_from_slice(&pk.attrs().chain_code).map_err(|_| Error::Crypto)?;
        if ccnum.is_hardened() {
            // Cannot derive child public keys for hardened `ChildNumber`s
            return Err(Error::ChildNumber);
        } else {
            hmac.update(&pk.public_key().to_bytes());
        }
        hmac.update(&ccnum.to_bytes());

        let result = hmac.finalize().into_bytes();
        let (tweak, chain_code) = result.split_at(KEY_SIZE);
        let public_key = pk.public_key().derive_child(tweak.try_into()?)?;
        let binding = total_tweak.derive_child(tweak.try_into()?)?;
        total_tweak = binding;

        ex_pk = ExtendedKey {
            prefix: Prefix::XPUB,
            attrs: ExtendedKeyAttrs {
                parent_fingerprint: pk.public_key().fingerprint(),
                child_number: *ccnum,
                chain_code: chain_code.try_into()?,
                depth,
            },
            key_bytes: <&[u8] as TryInto<[u8; 33]>>::try_into(&public_key.to_bytes()).unwrap(),
        };
        pk = XPub::try_from(ex_pk).unwrap();
    }

    let tweak_sk =
        Scalar::<Secp256k1>::from_bytes(&total_tweak.to_bytes()).unwrap() - Scalar::from(1u32);
    let child_pk = Point::<Secp256k1>::from_bytes(&pk.public_key().to_bytes()).unwrap();
    Ok((tweak_sk, child_pk))
}
