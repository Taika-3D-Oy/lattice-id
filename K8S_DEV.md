# Kubernetes Development Guide

Learnings, setup steps, and workflow recommendations from bringing Lattice-ID up on a local Kind cluster with the wasmCloud v2 operator.

## Learnings

### NATS JetStream KV key constraints

NATS KV keys only accept: `A-Za-z0-9`, `_`, `-`, `/`, `=`, `.` (dot valid in middle only).
Characters like `:`, `@`, `~`, `+`, `#`, and spaces are all **invalid** and produce a confusing error:

```
JetStream error: key cannot be empty or start/end with '.'
```

The error message is misleading — it fires for *any* invalid character, not just dots. We resolve this with `sanitize_key()` in both `core-service/src/store.rs` and `oidc-gateway/src/store.rs`:

- `:` → `/`
- `@` → `_at_`

This means `email:admin@test.local` becomes `email/admin_at_test.local`.

Any code that iterates keys via `kv_list_keys` and matches with `starts_with` must use the *sanitized* prefix (e.g. `"user/"` not `"user:"`).

### OCI cache on wasmCloud host pods

Host pods cache pulled images at `/oci-cache/` and use `IfNotPresent` policy. Pushing a new binary with the same `:dev` tag does **not** automatically invalidate the cache. You must manually clear it:

```bash
for pod in $(kubectl get pods -l wasmcloud.com/hostgroup=default -o name); do
  kubectl exec $pod -- sh -c 'rm -rf /oci-cache/kind-registry_5000_*'
done
```

### Binary filenames: hyphens vs underscores

Cargo's `wasm32-wasip2` target produces binary names that **match the package name** from `Cargo.toml`, using hyphens:

- Package `core-service` → `core-service.wasm` (binary/service)
- Package `oidc-gateway` → `oidc_gateway.wasm` (cdylib, Cargo converts hyphens to underscores for libs)
- Package `password-hasher` → `password_hasher.wasm` (cdylib)

Pushing the wrong filename (e.g. a stale 13KB artifact) produces a cryptic "Service must export a single interface with the 'run' function" error.

### taika3d:lid/kv plugin binding

The custom wasmCloud host exposes two KV plugins through the `taika3d:lid` package:

- `keyvalue-nats-cas`: NATS JetStream backed with CAS
- `keyvalue-in-memory`: ephemeral in-memory cache

Each persistent bucket and the ephemeral cache get their own `hostInterface` entry:

```yaml
hostInterfaces:
  - name: lid-users
    namespace: taika3d
    package: lid
    interfaces:
      - keyvalue-nats-cas
    config:
      bucket: lid-users
  - name: lid-cache
    namespace: taika3d
    package: lid
    interfaces:
      - keyvalue-in-memory
```

### KV bucket naming

Buckets must pre-exist in NATS before the workload starts. Store names are derived from `kv_prefix` config (default `lid`): `lid-users`, `lid-user-idx`, `lid-sessions`, `lid-clients`, `lid-tenants`, `lid-memberships`, `lid-audit`. Don't try to `open()` a bare prefix like `"lid"` — that bucket doesn't exist.

### Service components and wasi:cli/run

The `wasm32-wasip2` target automatically generates the `wasi:cli/run` export via the command adapter. Services use `#[wstd::main]` with `wit_bindgen::generate!({ generate_all })`. You do **not** need to declare `export wasi:cli/run` in `world.wit` — doing so causes conflicts.

---

## Local K8s Setup (from scratch)

### Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| Rust | stable | `rustup install stable && rustup target add wasm32-wasip2` |
| wash | Taika3D custom fork | build from `https://github.com/Taika-3D-Oy/wasmCloud` via `cargo install --path crates/wash --force` |
| Kind | 0.31+ | `brew install kind` |
| kubectl | 1.30+ | `brew install kubectl` |
| Helm | 3.x | `brew install helm` |

Use the custom `wash` binary first on your `PATH`; stock upstream `wash` does not provide the `taika3d:lid` host interfaces required by Lattice-ID.

### 1. Create Kind cluster with local OCI registry

```bash
# Create registry container
docker run -d --restart=always -p 5001:5000 --network bridge --name kind-registry registry:2

# Create cluster
kind create cluster --name wasmcloud --config deploy/kind-config.yaml

# Connect registry to kind network
docker network connect kind kind-registry 2>/dev/null || true

# Create in-cluster DNS for the registry
kubectl apply -f - <<EOF
apiVersion: v1
kind: Service
metadata:
  name: kind-registry
spec:
  type: ClusterIP
  ports:
    - port: 5000
      targetPort: 5000
---
apiVersion: v1
kind: Endpoints
metadata:
  name: kind-registry
subsets:
  - addresses:
      - ip: $(docker inspect -f '{{.NetworkSettings.Networks.kind.IPAddress}}' kind-registry)
    ports:
      - port: 5000
EOF
```

### 2. Install wasmCloud operator

```bash
helm install wasmcloud oci://ghcr.io/wasmcloud/charts/runtime-operator \
  --version 2.0.1 \
  --set 'hostConfig.allowInsecureRegistries=true'
```

Wait for all pods (3 host pods, 1 NATS, 1 gateway, 1 operator):

```bash
kubectl get pods -w
```

### 3. Create NATS KV buckets

The host pods have NATS TLS certs mounted. Use a temporary pod with the data-plane TLS secret:

```bash
kubectl run nats-setup --rm -i --restart=Never \
  --image=natsio/nats-box:latest \
  --overrides='{
    "spec": {
      "volumes": [{"name":"tls","secret":{"secretName":"wasmcloud-data-tls"}}],
      "containers": [{
        "name":"nats-setup",
        "image":"natsio/nats-box:latest",
        "stdin":true,"tty":false,
        "volumeMounts":[{"name":"tls","mountPath":"/tls","readOnly":true}],
        "command":["sh","-c","
          NATS=\"nats --server nats://nats:4222 --tlscert /tls/tls.crt --tlskey /tls/tls.key --tlsca /tls/ca.crt\";
          for b in lid-users lid-user-idx lid-sessions lid-clients lid-tenants lid-memberships lid-audit lid-keys lid-abuse-rate-limits; do
            $NATS kv add $b 2>&1;
          done
        "]
      }]
    }
  }'
```

### 4. Build and push components

```bash
cargo build --workspace --target wasm32-wasip2 --release

wash oci push --insecure localhost:5001/lattice-id/core-service:dev \
  target/wasm32-wasip2/release/core-service.wasm

wash oci push --insecure localhost:5001/lattice-id/oidc-gateway:dev \
  target/wasm32-wasip2/release/oidc_gateway.wasm

wash oci push --insecure localhost:5001/lattice-id/password-hasher:dev \
  target/wasm32-wasip2/release/password_hasher.wasm

wash oci push --insecure localhost:5001/lattice-id/email-worker:dev \
  target/wasm32-wasip2/release/email_worker.wasm
```

### 5. Deploy

```bash
kubectl apply -f deploy/workloaddeployment-local.yaml
```

Verify:

```bash
kubectl get workloaddeployment lattice-id
# Wait for READY: True, then:
curl http://localhost:8000/healthz
# → {"status":"ok"}
```

### 6. Bootstrap the first superadmin

The local dev manifest includes a `bootstrap_hook` that promotes the first
registrant to superadmin automatically. If you want to restrict bootstrap to a
specific email, edit `deploy/workloaddeployment-local.yaml` and change the
inline Rhai condition before registering.

The same manifest also sets a non-empty `internal_auth_secret` so `/internal/*`
endpoints are not left open by default, even in local K8s development.

### Redeploy after code changes

```bash
# 1. Build
cargo build --workspace --target wasm32-wasip2 --release

# 2. Push changed components
wash oci push --insecure localhost:5001/lattice-id/core-service:dev \
  target/wasm32-wasip2/release/core-service.wasm
wash oci push --insecure localhost:5001/lattice-id/oidc-gateway:dev \
  target/wasm32-wasip2/release/oidc_gateway.wasm
wash oci push --insecure localhost:5001/lattice-id/password-hasher:dev \
  target/wasm32-wasip2/release/password_hasher.wasm
wash oci push --insecure localhost:5001/lattice-id/email-worker:dev \
  target/wasm32-wasip2/release/email_worker.wasm

# 3. Clear OCI cache on host pods
for pod in $(kubectl get pods -l wasmcloud.com/hostgroup=default -o name); do
  kubectl exec $pod -- sh -c 'rm -rf /oci-cache/kind-registry_5000_lattice-id_*'
done

# 4. Bounce the workload
kubectl delete workloaddeployment lattice-id
kubectl apply -f deploy/workloaddeployment-local.yaml
```

---

## Development Workflows

### Workflow 1: `wash dev` (fast inner loop — recommended for daily dev)

```bash
./dev.sh start    # starts wash dev + admin UI
./dev.sh stop     # tears down
./dev.sh reset    # stop + clear KV data for fresh bootstrap
```

**What it gives you:**
- Hot reload: `wash dev` watches for file changes, rebuilds, and redeploys automatically
- Embedded NATS (no cluster needed)
- File-backed KV in `dev-data/keyvalue/` (inspectable, easy to reset)
- All three components run in one process with full wiring
- Port 8000 for the HTTP API

**Best for:** Day-to-day feature work, debugging OIDC flows, admin UI development.

### Workflow 2: Kind + wasmCloud operator (integration / pre-deploy)

Use this when you want to validate how the system behaves under real conditions:
- Mutual TLS between components and NATS
- JetStream KV (not file-backed)
- OCI image pull + caching behavior
- WorkloadDeployment lifecycle (rolling updates, restarts)
- Multi-host scheduling

**Best for:** Pre-merge validation, deployment manifest testing, debugging K8s-specific issues.

### Workflow 3: Hybrid (wash dev + Kind for dependencies)

This is the most productive workflow for developing **one component** against a larger deployed system:

1. **Deploy the full system on Kind** (steps above).
2. **Stop the Kind workload** for the piece you want to iterate on.
3. **Run that piece locally with `wash dev`**, pointing it at the Kind cluster's NATS.

This isn't directly supported by the current wasmCloud v2 operator yet, but the concept is:
- The Kind cluster provides NATS + KV + the components you're NOT changing
- `wash dev` provides hot-reload for the component you ARE changing
- You get fast iteration on one piece with the rest of the system live

**Future possibility:** wasmCloud's wash CLI may gain ability to connect to a remote NATS cluster for `wash dev`, letting you develop a single component against a live lattice. For now, the two workflows above cover the gap.

### Recommended daily pattern

```
  ┌──────────────────────────────┐
  │  Write code, test with       │
  │  wash dev (hot reload)       │◄─── Inner loop: seconds
  └──────────┬───────────────────┘
             │ Feature works locally
             ▼
  ┌──────────────────────────────┐
  │  Run integration tests       │
  │  bash tests/integration_*.sh │◄─── Mid loop: minutes
  └──────────┬───────────────────┘
             │ Tests pass
             ▼
  ┌──────────────────────────────┐
  │  Build, push, deploy to Kind │
  │  Test on real K8s + NATS TLS │◄─── Outer loop: pre-merge
  └──────────────────────────────┘
```

---

## Email Delivery Configuration

The `email-worker` component is invoked directly by the gateway via the
`lattice-id:notify/email` WIT interface.  It delivers emails via one of three
providers configured by `email_provider`:

| Provider | Config key | Description |
|----------|-----------|-------------|
| `log` (default) | `email_provider: "log"` | Logs emails to stderr — for local dev |
| `http` | `email_provider: "http"` | Sends via HTTP API (SendGrid v3 format / Bearer auth) |
| `ses` | `email_provider: "ses"` | Sends via AWS SES v2 API with SigV4 signing |

### AWS SES Setup

1. **Verify your sender address** in the AWS SES console:
   - Go to SES → Verified identities → Create identity
   - Verify a domain (recommended) or individual email address
   - If still in SES sandbox, also verify recipient addresses

2. **Create an IAM user** for email sending:
   ```bash
   aws iam create-user --user-name lattice-id-ses
   aws iam put-user-policy --user-name lattice-id-ses \
     --policy-name ses-send \
     --policy-document '{
       "Version": "2012-10-17",
       "Statement": [{
         "Effect": "Allow",
         "Action": ["ses:SendEmail"],
         "Resource": "*"
       }]
     }'
   aws iam create-access-key --user-name lattice-id-ses
   ```
   Save the `AccessKeyId` and `SecretAccessKey` from the output.

3. **Configure the WorkloadDeployment** manifest — set these in the
   `wasi:config:store` host interface:

   ```yaml
   email_provider: "ses"
   email_ses_region: "eu-north-1"        # your SES region
   email_ses_access_key_id: "AKIA..."    # from step 2
   email_ses_secret_access_key: "..."    # from step 2
   email_from: "noreply@yourdomain.com"  # must be SES-verified
   ```

   For production, store credentials in K8s Secrets and reference via `secretFrom`.

4. **Move out of SES sandbox** (for production):
   - SES Console → Account dashboard → Request production access
   - Until then, you can only send to verified recipient addresses

### SendGrid / Generic HTTP API Setup

Set `email_provider: "http"` and configure:

```yaml
email_http_url: "https://api.sendgrid.com/v3/mail/send"
email_http_api_key: "SG.your-api-key"
email_from: "noreply@yourdomain.com"
```

### Registration & Email Verification Defaults

| Config Key | Default | Effect |
|-----------|---------|--------|
| `require_email_verification` | `"true"` | Users start as "pending", must verify email before login |
| `allow_registration` | not set | Registration closed by default; open during bootstrap (no superadmin exists) |

After bootstrap, the superadmin can open registration via:
```bash
TOKEN="..."  # superadmin access token
curl -X PUT http://localhost:8000/api/settings \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"allow_registration": true}'
```

For local dev (`deploy/workloaddeployment-local.yaml`), both are relaxed:
`require_email_verification: "false"` and `allow_registration: "true"`.
