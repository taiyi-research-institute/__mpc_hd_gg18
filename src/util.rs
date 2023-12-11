use std::sync::OnceLock;

use miniz_oxide::{deflate::compress_to_vec, inflate::decompress_to_vec};
use serde::{de::DeserializeOwned, Serialize};
use sqlx::{mysql::MySqlPoolOptions, MySqlPool, Row};

// Table: zengo_fn
// Fields: mod, fn, param, session_id, member_id, param_value
pub static DB: OnceLock<MySqlPool> = OnceLock::new();
pub static mut SESSION_ID: OnceLock<String> = OnceLock::new();
pub static mut MEMBER_ID: OnceLock<u16> = OnceLock::new();
pub static INSERT_TEMPLATE: &str = r"
    INSERT INTO zengo_fn
        (mod, fn, param, session_id, member_id, param_value)
    VALUES (?, ?, ?, ?, ?, ?);
";
pub static SELECT_TEMPLATE: &str = r"
    SELECT param_value
    FROM zengo_fn
    WHERE mod = ? AND fn = ? AND param = ?;
";

pub async fn init_sampler() {
    let db_inner = MySqlPoolOptions::new()
        .max_connections(16)
        .connect("mysql://winston:winston114514@127.0.0.1:3306/gather")
        .await
        .unwrap();
    DB.set(db_inner).unwrap();
}

pub fn add_sample<T>(module: &str, function: &str, param: &str, param_value: &T)
where
    T: Serialize + DeserializeOwned,
{
    let param_bytes = param_value.compress();
    let session_id = unsafe { SESSION_ID.get().unwrap() };
    let member_id = unsafe { MEMBER_ID.get().unwrap() };
    let db = DB.get().unwrap();
    let future = sqlx::query(INSERT_TEMPLATE)
        .bind(module)
        .bind(function)
        .bind(param)
        .bind(session_id)
        .bind(member_id)
        .bind(param_bytes)
        .execute(db);
    let handle = tokio::runtime::Handle::current();
    handle.block_on(future).unwrap();
}

pub fn find_samples<T>(module: &str, function: &str, param: &str) -> Vec<T>
where
    T: Serialize + DeserializeOwned,
{
    let db = DB.get().unwrap();
    let future = sqlx::query(SELECT_TEMPLATE)
        .bind(module)
        .bind(function)
        .bind(param)
        .fetch_all(db);
    let handle = tokio::runtime::Handle::current();
    let param_bytes = handle.block_on(future).unwrap();
    let mut param_values: Vec<T> = Vec::new();
    for row in param_bytes {
        let param_value: Vec<u8> = row.get("param_value");
        let param_value: T = param_value.decompress();
        param_values.push(param_value);
    }
    param_values
}

pub trait CompressAble<T> {
    fn compress(&self) -> Vec<u8>;
}

pub trait DecompressAble<T> {
    fn decompress(&self) -> T;
}

impl<T> CompressAble<T> for T
where
    T: Serialize + DeserializeOwned,
{
    fn compress(&self) -> Vec<u8> {
        let json = serde_json::to_string(&self).unwrap();
        let bytes = compress_to_vec(json.as_bytes(), 7);
        bytes
    }
}

impl<S, D> DecompressAble<D> for S
where
    S: AsRef<[u8]>,
    D: Serialize + DeserializeOwned,
{
    fn decompress(&self) -> D {
        let bytes = decompress_to_vec(self.as_ref()).unwrap();
        let json = String::from_utf8(bytes).unwrap();
        let obj = serde_json::from_str(&json).unwrap();
        obj
    }
}
