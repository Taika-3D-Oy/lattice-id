mod bindings {
    wit_bindgen::generate!({
        world: "hasher",
        path: "wit",
        generate_all,
    });
}

use bindings::exports::lattice_id::crypto::password::Guest;

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use rand_core::OsRng;

struct Component;

impl Guest for Component {
    fn hash(plain: String) -> Result<String, String> {
        // Use lower memory cost for Wasm (tuned for acceptable performance
        // inside wasmCloud). Production deployments behind a native hasher
        // can increase this.
        let m_cost = 32768; // 32 MiB

        let params = Params::new(m_cost, 3, 1, None).map_err(|e| e.to_string())?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let salt = SaltString::generate(&mut OsRng);
        let hash = argon2
            .hash_password(plain.as_bytes(), &salt)
            .map_err(|e| e.to_string())?;
        Ok(hash.to_string())
    }

    fn verify(plain: String, phc_hash: String) -> Result<bool, String> {
        let parsed = PasswordHash::new(&phc_hash).map_err(|e| e.to_string())?;
        let result = Argon2::default()
            .verify_password(plain.as_bytes(), &parsed)
            .is_ok();
        Ok(result)
    }
}

bindings::export!(Component with_types_in bindings);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_and_verify() {
        let plain = "my_super_secret_password".to_string();

        // Hash it
        let hash = Component::hash(plain.clone()).expect("hash failed");

        // Verify with correct password
        let is_valid = Component::verify(plain, hash.clone()).expect("verify failed");
        assert!(is_valid, "Password should be valid");

        // Verify with incorrect password
        let is_invalid =
            Component::verify("wrong_password".to_string(), hash).expect("verify failed");
        assert!(!is_invalid, "Wrong password should be invalid");
    }
}
