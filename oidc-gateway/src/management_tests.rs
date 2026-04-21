#[cfg(test)]
mod tests {
    use crate::management::*;
    use serde_json::json;

    fn mock_claims(role: &str, tenant_id: Option<&str>) -> serde_json::Value {
        if let Some(tid) = tenant_id {
            json!({
                "sub": "user123",
                "role": role,
                "tenant_id": tid
            })
        } else {
            json!({
                "sub": "user123",
                "role": role
            })
        }
    }

    fn mock_claims_with_tenants(role: &str, tenants: Vec<(&str, &str)>) -> serde_json::Value {
        let tenant_objs: Vec<_> = tenants
            .iter()
            .map(|(id, r)| json!({ "tenant_id": id, "role": r }))
            .collect();
        json!({
            "sub": "user123",
            "role": role,
            "tenants": tenant_objs
        })
    }

    #[test]
    fn test_role_level() {
        assert_eq!(role_level("owner"), 4);
        assert_eq!(role_level("admin"), 3);
        assert_eq!(role_level("manager"), 2);
        assert_eq!(role_level("member"), 1);
        assert_eq!(role_level("guest"), 0);
        assert_eq!(role_level(""), 0);
    }

    #[test]
    fn test_get_caller_tenant_role() {
        // Superadmin is always owner
        let superadmin = mock_claims("superadmin", None);
        assert_eq!(get_caller_tenant_role(&superadmin, "t1"), "owner");

        // Direct tenant_id claim
        let admin_t1 = mock_claims("admin", Some("t1"));
        assert_eq!(get_caller_tenant_role(&admin_t1, "t1"), "admin");
        assert_eq!(get_caller_tenant_role(&admin_t1, "t2"), "");

        // Multi-tenant array claim
        let multi = mock_claims_with_tenants("member", vec![("t1", "manager"), ("t2", "member")]);
        assert_eq!(get_caller_tenant_role(&multi, "t1"), "manager");
        assert_eq!(get_caller_tenant_role(&multi, "t2"), "member");
        assert_eq!(get_caller_tenant_role(&multi, "t3"), "");
    }

    #[test]
    fn test_claim_has_tenant_role() {
        let manager_t1 = mock_claims("manager", Some("t1"));

        // Exact match
        assert!(claim_has_tenant_role(&manager_t1, "t1", "manager"));
        // Lower role required
        assert!(claim_has_tenant_role(&manager_t1, "t1", "member"));
        // Higher role required
        assert!(!claim_has_tenant_role(&manager_t1, "t1", "admin"));
        // Wrong tenant
        assert!(!claim_has_tenant_role(&manager_t1, "t2", "member"));

        let superadmin = mock_claims("superadmin", None);
        assert!(claim_has_tenant_role(&superadmin, "any", "owner"));
    }

    #[test]
    fn test_role_escalation_prevention() {
        // Manager tries to add an admin
        let manager_role = "manager";
        let target_role_admin = "admin";
        let target_role_member = "member";

        assert!(role_level(target_role_admin) > role_level(manager_role));
        assert!(role_level(target_role_member) < role_level(manager_role));

        // Admin tries to add an owner
        let admin_role = "admin";
        let target_role_owner = "owner";
        assert!(role_level(target_role_owner) > role_level(admin_role));
    }
}
