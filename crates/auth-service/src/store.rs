//! DynamoDB single-table storage (protocol §12).
//!
//! Nothing stored here identifies a person: account IDs are random, passkeys
//! are public keys, recovery codes are stored as hashes, and challenges and
//! DPoP `jti`s are short-lived. Every multi-item change is one conditional
//! `TransactWriteItems`, so concurrent requests can never leave an account in
//! an inconsistent state (for example zero passkeys, or a passkey surviving a
//! recovery).

use auth_core::webauthn::RegisteredCredential;
use auth_core::{b64, crypto};
use aws_sdk_dynamodb::Client;
use aws_sdk_dynamodb::error::{DisplayErrorContext, SdkError};
use aws_sdk_dynamodb::operation::transact_write_items::TransactWriteItemsError;
use aws_sdk_dynamodb::primitives::Blob;
use aws_sdk_dynamodb::types::{
    AttributeValue, Delete, Put, ReturnValue, TransactWriteItem, Update,
};
use std::collections::HashMap;

use crate::error::ApiError;

type Item = HashMap<String, AttributeValue>;

/// A storage error.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// A transaction condition failed; one flag per transaction item.
    #[error("transaction condition failed: {0:?}")]
    Condition(Vec<bool>),
    /// A single-item condition failed.
    #[error("condition failed")]
    ConditionFailed,
    /// The AWS call failed.
    #[error("DynamoDB: {0}")]
    Aws(String),
    /// An item does not have the expected shape.
    #[error("corrupt item: {0}")]
    Corrupt(&'static str),
}

impl From<StoreError> for ApiError {
    fn from(e: StoreError) -> Self {
        match e {
            StoreError::Condition(_) | StoreError::ConditionFailed => {
                ApiError::Conflict("concurrent modification")
            }
            other => ApiError::Internal(other.to_string()),
        }
    }
}

fn aws<E: std::error::Error + 'static, R: std::fmt::Debug>(e: SdkError<E, R>) -> StoreError {
    StoreError::Aws(DisplayErrorContext(e).to_string())
}

// ------------------------------------------------------------------ keys and values

fn h(x: &[u8]) -> String {
    b64::encode(&crypto::sha256(x))
}

fn acct_pk(account_id: &str) -> String {
    format!("ACCT#{account_id}")
}

fn cred_sk(credential_id: &[u8]) -> String {
    format!("CRED#{}", h(credential_id))
}

fn credid_pk(credential_id: &[u8]) -> String {
    format!("CREDID#{}", h(credential_id))
}

fn recovery_pk(recovery_key: &str) -> String {
    format!("RECOVERY#{recovery_key}")
}

fn chal_pk(challenge: &[u8]) -> String {
    format!("CHAL#{}", b64::encode(challenge))
}

fn jti_pk(jkt: &[u8], jti: &[u8]) -> String {
    let mut m = jkt.to_vec();
    m.push(0);
    m.extend_from_slice(jti);
    format!("JTI#{}", h(&m))
}

fn s(v: impl Into<String>) -> AttributeValue {
    AttributeValue::S(v.into())
}

fn n(v: u64) -> AttributeValue {
    AttributeValue::N(v.to_string())
}

fn bin(v: &[u8]) -> AttributeValue {
    AttributeValue::B(Blob::new(v.to_vec()))
}

fn key(pk: String, sk: &str) -> Item {
    HashMap::from([("pk".to_string(), s(pk)), ("sk".to_string(), s(sk))])
}

fn get_s<'a>(item: &'a Item, name: &'static str) -> Result<&'a str, StoreError> {
    item.get(name)
        .and_then(|v| v.as_s().ok())
        .map(String::as_str)
        .ok_or(StoreError::Corrupt(name))
}

fn get_n(item: &Item, name: &'static str) -> Result<u64, StoreError> {
    item.get(name)
        .and_then(|v| v.as_n().ok())
        .and_then(|v| v.parse().ok())
        .ok_or(StoreError::Corrupt(name))
}

fn get_b(item: &Item, name: &'static str) -> Result<Vec<u8>, StoreError> {
    item.get(name)
        .and_then(|v| v.as_b().ok())
        .map(|b| b.as_ref().to_vec())
        .ok_or(StoreError::Corrupt(name))
}

fn get_bool(item: &Item, name: &'static str) -> Result<bool, StoreError> {
    item.get(name)
        .and_then(|v| v.as_bool().ok())
        .copied()
        .ok_or(StoreError::Corrupt(name))
}

// ------------------------------------------------------------------ records

/// What a WebAuthn ceremony was started for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CeremonyKind {
    /// Sign-up.
    Register,
    /// Sign-in.
    Login,
    /// Account recovery.
    Recover,
    /// Adding a passkey to an existing account.
    AddPasskey,
}

impl CeremonyKind {
    fn as_str(self) -> &'static str {
        match self {
            CeremonyKind::Register => "register",
            CeremonyKind::Login => "login",
            CeremonyKind::Recover => "recover",
            CeremonyKind::AddPasskey => "add_passkey",
        }
    }

    fn parse(v: &str) -> Option<Self> {
        Some(match v {
            "register" => CeremonyKind::Register,
            "login" => CeremonyKind::Login,
            "recover" => CeremonyKind::Recover,
            "add_passkey" => CeremonyKind::AddPasskey,
            _ => return None,
        })
    }
}

/// A pending WebAuthn ceremony.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ceremony {
    /// Purpose.
    pub kind: CeremonyKind,
    /// Account the ceremony is for (all kinds except sign-in).
    pub account_id: Option<String>,
    /// Recovery key the ceremony was started with (recovery only).
    pub recovery_key: Option<String>,
    /// Thumbprint of the device key the ceremony is bound to (protocol §8).
    pub jkt: Vec<u8>,
    /// Expiry (Unix seconds).
    pub expires_at: u64,
}

/// The account record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountMeta {
    /// Creation time.
    pub created_at: u64,
    /// Session epoch (protocol §6.3).
    pub epoch: u64,
    /// Number of registered passkeys.
    pub passkey_count: u64,
    /// Key of the current recovery code item.
    pub recovery_key: String,
}

/// A stored passkey.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialRecord {
    /// Credential ID.
    pub credential_id: Vec<u8>,
    /// Registration ID: fresh for every registration of this credential.
    pub registration_id: Vec<u8>,
    /// COSE_Key.
    pub public_key: Vec<u8>,
    /// COSE algorithm.
    pub alg: i64,
    /// Signature counter.
    pub sign_count: u32,
    /// Backup eligibility.
    pub backup_eligible: bool,
    /// Backup state.
    pub backup_state: bool,
    /// AAGUID.
    pub aaguid: Vec<u8>,
    /// Transport hints.
    pub transports: Vec<String>,
    /// Registration time.
    pub created_at: u64,
    /// Last successful sign-in, if any.
    pub last_used_at: Option<u64>,
}

fn meta_from(item: &Item) -> Result<AccountMeta, StoreError> {
    Ok(AccountMeta {
        created_at: get_n(item, "created_at")?,
        epoch: get_n(item, "epoch")?,
        passkey_count: get_n(item, "passkey_count")?,
        recovery_key: get_s(item, "recovery_key")?.to_string(),
    })
}

fn credential_from(item: &Item) -> Result<CredentialRecord, StoreError> {
    let alg = get_s(item, "alg")?
        .parse()
        .map_err(|_| StoreError::Corrupt("alg"))?;
    let transports = match item.get("transports") {
        Some(AttributeValue::L(l)) => l.iter().filter_map(|v| v.as_s().ok().cloned()).collect(),
        _ => Vec::new(),
    };
    Ok(CredentialRecord {
        credential_id: get_b(item, "credential_id")?,
        registration_id: get_b(item, "registration_id")?,
        public_key: get_b(item, "public_key")?,
        alg,
        sign_count: u32::try_from(get_n(item, "sign_count")?)
            .map_err(|_| StoreError::Corrupt("sign_count"))?,
        backup_eligible: get_bool(item, "backup_eligible")?,
        backup_state: get_bool(item, "backup_state")?,
        aaguid: get_b(item, "aaguid")?,
        transports,
        created_at: get_n(item, "created_at")?,
        last_used_at: item
            .get("last_used_at")
            .and_then(|v| v.as_n().ok())
            .and_then(|v| v.parse().ok()),
    })
}

fn credential_item(account_id: &str, p: NewPasskey<'_>, now: u64) -> Item {
    let c = p.credential;
    let mut item = key(acct_pk(account_id), &cred_sk(&c.credential_id));
    item.insert("credential_id".into(), bin(&c.credential_id));
    item.insert("registration_id".into(), bin(p.registration_id));
    item.insert("public_key".into(), bin(&c.cose_key));
    // Stored as a string so negative COSE identifiers round-trip unambiguously.
    item.insert("alg".into(), s(c.alg.to_string()));
    item.insert("sign_count".into(), n(u64::from(c.sign_count)));
    item.insert(
        "backup_eligible".into(),
        AttributeValue::Bool(c.backup_eligible),
    );
    item.insert("backup_state".into(), AttributeValue::Bool(c.backup_state));
    item.insert("aaguid".into(), bin(&c.aaguid));
    item.insert(
        "transports".into(),
        AttributeValue::L(c.transports.iter().map(|t| s(t.clone())).collect()),
    );
    item.insert("created_at".into(), n(now));
    item
}

fn credid_item(account_id: &str, credential_id: &[u8]) -> Item {
    let mut item = key(credid_pk(credential_id), "CREDID");
    item.insert("account_id".into(), s(account_id));
    item
}

fn recovery_item(account_id: &str, recovery_key: &str) -> Item {
    let mut item = key(recovery_pk(recovery_key), "RECOVERY");
    item.insert("account_id".into(), s(account_id));
    item
}

/// A verified credential about to be stored, with its fresh registration ID.
#[derive(Debug, Clone, Copy)]
pub struct NewPasskey<'a> {
    /// The verified credential.
    pub credential: &'a RegisteredCredential,
    /// Its registration ID (protocol §8).
    pub registration_id: &'a [u8],
}

/// Errors when adding a passkey.
#[derive(Debug, PartialEq, Eq)]
pub enum AddError {
    /// The account has the maximum number of passkeys.
    TooMany,
    /// The credential is already registered (to any account).
    Exists,
    /// The account no longer exists.
    NoAccount,
}

/// Errors when removing a passkey.
#[derive(Debug, PartialEq, Eq)]
pub enum RemoveError {
    /// It is the account's only passkey.
    Last,
    /// No such passkey on this account.
    NotFound,
}

/// The DynamoDB table.
#[derive(Debug, Clone)]
pub struct Store {
    client: Client,
    table: String,
}

impl Store {
    /// A store for `table`.
    pub fn new(client: Client, table: String) -> Self {
        Self { client, table }
    }

    fn put(&self, item: Item, condition: Option<&str>) -> Result<TransactWriteItem, StoreError> {
        let mut p = Put::builder().table_name(&self.table).set_item(Some(item));
        if let Some(c) = condition {
            p = p.condition_expression(c);
        }
        Ok(TransactWriteItem::builder()
            .put(p.build().map_err(|e| StoreError::Aws(e.to_string()))?)
            .build())
    }

    fn delete(
        &self,
        k: Item,
        condition: Option<(&str, Item)>,
    ) -> Result<TransactWriteItem, StoreError> {
        let mut d = Delete::builder().table_name(&self.table).set_key(Some(k));
        if let Some((c, values)) = condition {
            d = d.condition_expression(c);
            if !values.is_empty() {
                d = d.set_expression_attribute_values(Some(values));
            }
        }
        Ok(TransactWriteItem::builder()
            .delete(d.build().map_err(|e| StoreError::Aws(e.to_string()))?)
            .build())
    }

    fn update(
        &self,
        k: Item,
        expr: &str,
        condition: &str,
        values: Item,
    ) -> Result<TransactWriteItem, StoreError> {
        let u = Update::builder()
            .table_name(&self.table)
            .set_key(Some(k))
            .update_expression(expr)
            .condition_expression(condition)
            .set_expression_attribute_values(Some(values))
            .build()
            .map_err(|e| StoreError::Aws(e.to_string()))?;
        Ok(TransactWriteItem::builder().update(u).build())
    }

    async fn transact(&self, items: Vec<TransactWriteItem>) -> Result<(), StoreError> {
        match self
            .client
            .transact_write_items()
            .set_transact_items(Some(items))
            .send()
            .await
        {
            Ok(_) => Ok(()),
            Err(SdkError::ServiceError(e)) => match e.err() {
                TransactWriteItemsError::TransactionCanceledException(ex) => {
                    let failed = ex
                        .cancellation_reasons()
                        .iter()
                        .map(|r| r.code() == Some("ConditionalCheckFailed"))
                        .collect::<Vec<_>>();
                    if failed.iter().any(|f| *f) {
                        Err(StoreError::Condition(failed))
                    } else {
                        Err(StoreError::Aws(format!("transaction canceled: {ex:?}")))
                    }
                }
                other => Err(StoreError::Aws(DisplayErrorContext(other).to_string())),
            },
            Err(e) => Err(aws(e)),
        }
    }

    async fn get(&self, k: Item) -> Result<Option<Item>, StoreError> {
        let out = self
            .client
            .get_item()
            .table_name(&self.table)
            .set_key(Some(k))
            .consistent_read(true)
            .send()
            .await
            .map_err(aws)?;
        Ok(out.item)
    }

    // -------------------------------------------------------------- ceremonies

    /// Stores a pending ceremony keyed by its challenge.
    pub async fn put_ceremony(&self, challenge: &[u8], c: &Ceremony) -> Result<(), StoreError> {
        let mut item = key(chal_pk(challenge), "CHAL");
        item.insert("kind".into(), s(c.kind.as_str()));
        if let Some(a) = &c.account_id {
            item.insert("account_id".into(), s(a.clone()));
        }
        if let Some(r) = &c.recovery_key {
            item.insert("recovery_key".into(), s(r.clone()));
        }
        item.insert("jkt".into(), bin(&c.jkt));
        item.insert("expires_at".into(), n(c.expires_at));
        item.insert("ttl".into(), n(c.expires_at.saturating_add(3600)));
        self.client
            .put_item()
            .table_name(&self.table)
            .set_item(Some(item))
            .condition_expression("attribute_not_exists(pk)")
            .send()
            .await
            .map_err(aws)?;
        Ok(())
    }

    /// Atomically removes and returns the ceremony for `challenge`, so each
    /// challenge can be used at most once.
    pub async fn take_ceremony(&self, challenge: &[u8]) -> Result<Option<Ceremony>, StoreError> {
        let out = self
            .client
            .delete_item()
            .table_name(&self.table)
            .set_key(Some(key(chal_pk(challenge), "CHAL")))
            .return_values(ReturnValue::AllOld)
            .send()
            .await
            .map_err(aws)?;
        let Some(item) = out.attributes else {
            return Ok(None);
        };
        Ok(Some(Ceremony {
            kind: CeremonyKind::parse(get_s(&item, "kind")?).ok_or(StoreError::Corrupt("kind"))?,
            account_id: item.get("account_id").and_then(|v| v.as_s().ok()).cloned(),
            recovery_key: item
                .get("recovery_key")
                .and_then(|v| v.as_s().ok())
                .cloned(),
            jkt: get_b(&item, "jkt")?,
            expires_at: get_n(&item, "expires_at")?,
        }))
    }

    // -------------------------------------------------------------- DPoP replay

    /// Records a DPoP proof `jti` until `expires_at`. Returns `false` if it was
    /// already recorded and has not expired (a replay).
    pub async fn record_jti(
        &self,
        jkt: &[u8],
        jti: &[u8],
        now: u64,
        expires_at: u64,
    ) -> Result<bool, StoreError> {
        let mut item = key(jti_pk(jkt, jti), "JTI");
        item.insert("expires_at".into(), n(expires_at));
        item.insert("ttl".into(), n(expires_at));
        let r = self
            .client
            .put_item()
            .table_name(&self.table)
            .set_item(Some(item))
            .condition_expression("attribute_not_exists(pk) OR expires_at < :now")
            .expression_attribute_values(":now", n(now))
            .send()
            .await;
        match r {
            Ok(_) => Ok(true),
            Err(SdkError::ServiceError(e)) if e.err().is_conditional_check_failed_exception() => {
                Ok(false)
            }
            Err(e) => Err(aws(e)),
        }
    }

    // -------------------------------------------------------------- accounts

    /// Creates an account with its first passkey and recovery code.
    pub async fn create_account(
        &self,
        account_id: &str,
        passkey: NewPasskey<'_>,
        recovery_key: &str,
        now: u64,
    ) -> Result<(), StoreError> {
        let mut meta = key(acct_pk(account_id), "META");
        meta.insert("created_at".into(), n(now));
        meta.insert("epoch".into(), n(0));
        meta.insert("passkey_count".into(), n(1));
        meta.insert("recovery_key".into(), s(recovery_key));
        let not_exists = Some("attribute_not_exists(pk)");
        self.transact(vec![
            self.put(meta, not_exists)?,
            self.put(credential_item(account_id, passkey, now), not_exists)?,
            self.put(
                credid_item(account_id, &passkey.credential.credential_id),
                not_exists,
            )?,
            self.put(recovery_item(account_id, recovery_key), not_exists)?,
        ])
        .await
    }

    /// The account record (strongly consistent).
    pub async fn get_meta(&self, account_id: &str) -> Result<Option<AccountMeta>, StoreError> {
        self.get(key(acct_pk(account_id), "META"))
            .await?
            .as_ref()
            .map(meta_from)
            .transpose()
    }

    /// A passkey of the account (strongly consistent).
    pub async fn get_credential(
        &self,
        account_id: &str,
        credential_id: &[u8],
    ) -> Result<Option<CredentialRecord>, StoreError> {
        let item = self
            .get(key(acct_pk(account_id), &cred_sk(credential_id)))
            .await?;
        match item {
            Some(i) => {
                let c = credential_from(&i)?;
                // Guard against hash-key collisions: the stored ID must match.
                Ok((c.credential_id == credential_id).then_some(c))
            }
            None => Ok(None),
        }
    }

    /// Updates a passkey after a successful sign-in. The update only applies if
    /// the stored counter is still `old_count`, so two concurrent sign-ins
    /// cannot both advance from the same counter value. Returns `false` if the
    /// condition failed.
    pub async fn record_login(
        &self,
        account_id: &str,
        credential_id: &[u8],
        old_count: u32,
        new_count: u32,
        backup_state: bool,
        now: u64,
    ) -> Result<bool, StoreError> {
        let r = self
            .client
            .update_item()
            .table_name(&self.table)
            .set_key(Some(key(acct_pk(account_id), &cred_sk(credential_id))))
            .update_expression("SET sign_count = :new, backup_state = :bs, last_used_at = :now")
            .condition_expression("attribute_exists(pk) AND sign_count = :old")
            .expression_attribute_values(":new", n(u64::from(new_count)))
            .expression_attribute_values(":old", n(u64::from(old_count)))
            .expression_attribute_values(":bs", AttributeValue::Bool(backup_state))
            .expression_attribute_values(":now", n(now))
            .send()
            .await;
        match r {
            Ok(_) => Ok(true),
            Err(SdkError::ServiceError(e)) if e.err().is_conditional_check_failed_exception() => {
                Ok(false)
            }
            Err(e) => Err(aws(e)),
        }
    }

    /// The account record and all its passkeys (strongly consistent).
    pub async fn list_account(
        &self,
        account_id: &str,
    ) -> Result<Option<(AccountMeta, Vec<CredentialRecord>)>, StoreError> {
        let mut meta = None;
        let mut creds = Vec::new();
        let mut start: Option<Item> = None;
        loop {
            let out = self
                .client
                .query()
                .table_name(&self.table)
                .key_condition_expression("pk = :pk")
                .expression_attribute_values(":pk", s(acct_pk(account_id)))
                .consistent_read(true)
                .set_exclusive_start_key(start)
                .send()
                .await
                .map_err(aws)?;
            for item in out.items() {
                let sk = get_s(item, "sk")?;
                if sk == "META" {
                    meta = Some(meta_from(item)?);
                } else if sk.starts_with("CRED#") {
                    creds.push(credential_from(item)?);
                }
            }
            match out.last_evaluated_key {
                Some(k) if !k.is_empty() => start = Some(k),
                _ => break,
            }
        }
        Ok(meta.map(|m| (m, creds)))
    }

    /// Adds a passkey, enforcing the per-account limit and global uniqueness.
    pub async fn add_credential(
        &self,
        account_id: &str,
        passkey: NewPasskey<'_>,
        max: u64,
        now: u64,
    ) -> Result<Result<(), AddError>, StoreError> {
        let not_exists = Some("attribute_not_exists(pk)");
        let r = self
            .transact(vec![
                self.update(
                    key(acct_pk(account_id), "META"),
                    "SET passkey_count = passkey_count + :one",
                    "attribute_exists(pk) AND passkey_count < :max",
                    HashMap::from([(":one".into(), n(1)), (":max".into(), n(max))]),
                )?,
                self.put(credential_item(account_id, passkey, now), not_exists)?,
                self.put(
                    credid_item(account_id, &passkey.credential.credential_id),
                    not_exists,
                )?,
            ])
            .await;
        match r {
            Ok(()) => Ok(Ok(())),
            Err(StoreError::Condition(f)) => {
                if f.get(1).copied().unwrap_or(false) || f.get(2).copied().unwrap_or(false) {
                    Ok(Err(AddError::Exists))
                } else if self.get_meta(account_id).await?.is_none() {
                    Ok(Err(AddError::NoAccount))
                } else {
                    Ok(Err(AddError::TooMany))
                }
            }
            Err(e) => Err(e),
        }
    }

    /// Removes a passkey unless it is the account's last one.
    pub async fn remove_credential(
        &self,
        account_id: &str,
        credential_id: &[u8],
    ) -> Result<Result<(), RemoveError>, StoreError> {
        let r = self
            .transact(vec![
                self.update(
                    key(acct_pk(account_id), "META"),
                    "SET passkey_count = passkey_count - :one",
                    "attribute_exists(pk) AND passkey_count > :one",
                    HashMap::from([(":one".into(), n(1))]),
                )?,
                self.delete(
                    key(acct_pk(account_id), &cred_sk(credential_id)),
                    Some((
                        "attribute_exists(pk) AND credential_id = :id",
                        HashMap::from([(":id".into(), bin(credential_id))]),
                    )),
                )?,
                self.delete(
                    key(credid_pk(credential_id), "CREDID"),
                    Some((
                        "attribute_exists(pk) AND account_id = :a",
                        HashMap::from([(":a".into(), s(account_id))]),
                    )),
                )?,
            ])
            .await;
        match r {
            Ok(()) => Ok(Ok(())),
            Err(StoreError::Condition(f)) => {
                if f.get(1).copied().unwrap_or(false) || f.get(2).copied().unwrap_or(false) {
                    Ok(Err(RemoveError::NotFound))
                } else {
                    Ok(Err(RemoveError::Last))
                }
            }
            Err(e) => Err(e),
        }
    }

    /// Increments the session epoch ("sign out everywhere"). Returns `false` if
    /// the account does not exist.
    pub async fn bump_epoch(&self, account_id: &str) -> Result<bool, StoreError> {
        let r = self
            .client
            .update_item()
            .table_name(&self.table)
            .set_key(Some(key(acct_pk(account_id), "META")))
            .update_expression("SET epoch = epoch + :one")
            .condition_expression("attribute_exists(pk)")
            .expression_attribute_values(":one", n(1))
            .send()
            .await;
        match r {
            Ok(_) => Ok(true),
            Err(SdkError::ServiceError(e)) if e.err().is_conditional_check_failed_exception() => {
                Ok(false)
            }
            Err(e) => Err(aws(e)),
        }
    }

    // -------------------------------------------------------------- recovery

    /// The account a recovery code belongs to.
    pub async fn get_recovery(&self, recovery_key: &str) -> Result<Option<String>, StoreError> {
        let item = self.get(key(recovery_pk(recovery_key), "RECOVERY")).await?;
        item.as_ref()
            .map(|i| get_s(i, "account_id").map(String::from))
            .transpose()
    }

    /// Replaces the account's recovery code.
    pub async fn rotate_recovery(
        &self,
        account_id: &str,
        old_key: &str,
        new_key: &str,
    ) -> Result<(), StoreError> {
        self.transact(vec![
            self.delete(
                key(recovery_pk(old_key), "RECOVERY"),
                Some((
                    "attribute_exists(pk) AND account_id = :a",
                    HashMap::from([(":a".into(), s(account_id))]),
                )),
            )?,
            self.put(
                recovery_item(account_id, new_key),
                Some("attribute_not_exists(pk)"),
            )?,
            self.update(
                key(acct_pk(account_id), "META"),
                "SET recovery_key = :new",
                "attribute_exists(pk) AND recovery_key = :old",
                HashMap::from([(":new".into(), s(new_key)), (":old".into(), s(old_key))]),
            )?,
        ])
        .await
    }

    /// Recovers an account: consumes the recovery code, replaces every passkey
    /// with `new_cred`, issues a new recovery code and increments the epoch, all
    /// atomically. `meta` and `creds` must be the state read just before; the
    /// transaction fails if anything changed since. Returns the new epoch.
    pub async fn recover_account(
        &self,
        account_id: &str,
        meta: &AccountMeta,
        creds: &[CredentialRecord],
        passkey: NewPasskey<'_>,
        new_recovery_key: &str,
        now: u64,
    ) -> Result<u64, StoreError> {
        let new_cred = passkey.credential;
        let new_epoch = meta
            .epoch
            .checked_add(1)
            .ok_or(StoreError::Corrupt("epoch"))?;
        let mut items = vec![
            self.update(
                key(acct_pk(account_id), "META"),
                "SET epoch = :e1, recovery_key = :new, passkey_count = :one",
                "attribute_exists(pk) AND epoch = :e AND recovery_key = :old AND passkey_count = :n",
                HashMap::from([
                    (":e1".into(), n(new_epoch)),
                    (":e".into(), n(meta.epoch)),
                    (":new".into(), s(new_recovery_key)),
                    (":old".into(), s(meta.recovery_key.clone())),
                    (":one".into(), n(1)),
                    (":n".into(), n(meta.passkey_count)),
                ]),
            )?,
            self.delete(
                key(recovery_pk(&meta.recovery_key), "RECOVERY"),
                Some(("attribute_exists(pk) AND account_id = :a", HashMap::from([(":a".into(), s(account_id))]))),
            )?,
            self.put(recovery_item(account_id, new_recovery_key), Some("attribute_not_exists(pk)"))?,
        ];
        let mut reused = false;
        for c in creds {
            if c.credential_id == new_cred.credential_id {
                // Re-registering the same credential overwrites it below.
                reused = true;
                continue;
            }
            items.push(self.delete(key(acct_pk(account_id), &cred_sk(&c.credential_id)), None)?);
            items.push(self.delete(key(credid_pk(&c.credential_id), "CREDID"), None)?);
        }
        let cond = if reused {
            None
        } else {
            Some("attribute_not_exists(pk)")
        };
        items.push(self.put(credential_item(account_id, passkey, now), cond)?);
        items.push(self.put(credid_item(account_id, &new_cred.credential_id), cond)?);
        self.transact(items).await?;
        Ok(new_epoch)
    }

    /// Deletes every item belonging to the account.
    pub async fn delete_account(
        &self,
        account_id: &str,
        meta: &AccountMeta,
        creds: &[CredentialRecord],
    ) -> Result<(), StoreError> {
        let mut items = vec![
            self.delete(
                key(acct_pk(account_id), "META"),
                Some((
                    "attribute_exists(pk) AND epoch = :e AND passkey_count = :n",
                    HashMap::from([
                        (":e".into(), n(meta.epoch)),
                        (":n".into(), n(meta.passkey_count)),
                    ]),
                )),
            )?,
            self.delete(key(recovery_pk(&meta.recovery_key), "RECOVERY"), None)?,
        ];
        for c in creds {
            items.push(self.delete(key(acct_pk(account_id), &cred_sk(&c.credential_id)), None)?);
            items.push(self.delete(key(credid_pk(&c.credential_id), "CREDID"), None)?);
        }
        self.transact(items).await
    }
}
