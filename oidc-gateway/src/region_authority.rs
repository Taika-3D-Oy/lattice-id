pub struct LookupResult {
    pub found: bool,
    pub region: Option<String>,
}

fn user_idx_table() -> String {
    "user-idx".to_string()
}

/// Check whether an email hash exists in the local region's user index.
pub async fn lookup(email_hash: &str) -> Result<LookupResult, String> {
    let key = format!("email:{email_hash}");
    let exists = crate::store::kv_exists(&user_idx_table(), &key).await?;
    if exists {
        Ok(LookupResult {
            found: true,
            region: Some("local".to_string()),
        })
    } else {
        Ok(LookupResult {
            found: false,
            region: None,
        })
    }
}
