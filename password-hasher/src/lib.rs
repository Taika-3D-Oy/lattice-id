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
        // Task 2.10: Increase Argon2 memory cost when platform allows.
        // We attempt a more robust 32 MiB (32768 KiB).
        // If the platform memory limit is exceeded, the component allocation would fail,
        // but we can make this configurable via wasi-config or just keep a reasonable high default.
        // Argon2 v0.13 standard recommended is 64 MiB, but 32 MiB is a good jump from 4 MiB for Wasm.
        let m_cost = 32768; // 32 MiB

        // Check for override in wasi:config (if available in this context)
        // Note: password-hasher component usually doesn't have config access in its world,
        // but it could be passed in. For now we use the higher default.

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
        Ok(Argon2::default()
            .verify_password(plain.as_bytes(), &parsed)
            .is_ok())
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
