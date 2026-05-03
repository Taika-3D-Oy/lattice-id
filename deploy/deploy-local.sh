#!/usr/bin/env bash
# deploy-local.sh — Deploy lattice-id on a single Kind cluster
# with shared NATS for integration testing.
#
# The lattice-id workload runs as a wasmCloud WorkloadDeployment with
# lattice-db co-located as a service (TCP on 127.0.0.1:4080).
# NATS (with JetStream) provides persistent storage for lattice-db.
# The HTTP gateway is exposed on localhost:8000.
# NATS client port is exposed on localhost:4222 for CLI testing.
#
# Usage:
#   bash deploy/deploy-local.sh            # full setup from scratch
#   bash deploy/deploy-local.sh rebuild    # rebuild + redeploy both workloads
#   bash deploy/deploy-local.sh teardown   # destroy everything
#   bash deploy/deploy-local.sh status     # show cluster status

set -euo pipefail
cd "$(dirname "$0")/.."

CLUSTER_NAME="lattice-id-local"
NAMESPACE="default"
REGISTRY_NAME="kind-registry"
REGISTRY_PORT=5001
HELM_VERSION="2.0.1"

# lattice-db image source for mirroring into local registry
LATTICE_DB_IMAGE="${LATTICE_DB_IMAGE:-ghcr.io/taika-3d-oy/lattice-db/storage-service:latest}"

log() { echo "==> $*"; }
die() { echo "ERROR: $*" >&2; exit 1; }

# ── Prerequisite checks ─────────────────────────────────────

check_prereqs() {
  local missing=()
  for cmd in kind kubectl helm docker cargo wash; do
    command -v "$cmd" &>/dev/null || missing+=("$cmd")
  done
  if [[ ${#missing[@]} -gt 0 ]]; then
    die "Missing required tools: ${missing[*]}"
  fi
}

# ── Teardown ─────────────────────────────────────────────────

teardown() {
  log "Tearing down local environment"
  kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || true
  docker rm -f "$REGISTRY_NAME" 2>/dev/null || true
  log "Done"
}

if [[ "${1:-}" == "teardown" ]]; then
  teardown
  exit 0
fi

# ── Status ───────────────────────────────────────────────────

if [[ "${1:-}" == "status" ]]; then
  echo "--- Cluster ---"
  kind get clusters 2>/dev/null | grep "$CLUSTER_NAME" && echo "Cluster: running" || echo "Cluster: not found"
  echo ""
  echo "--- Pods ---"
  kubectl get pods -o wide 2>/dev/null || echo "No pods"
  echo ""
  echo "--- Workloads ---"
  kubectl get workloaddeployment 2>/dev/null || echo "No workloads"
  echo ""
  echo "--- Test ---"
  echo "  curl http://localhost/healthz"
  echo "  curl http://localhost/.well-known/openid-configuration"
  exit 0
fi

check_prereqs

# ── Build & Push ─────────────────────────────────────────────

build_and_push() {
  log "Building lattice-id (release, wasm32-wasip3)"
  cargo build --workspace --target wasm32-wasip3 --release

  log "Pushing components to local OCI registry"

  # lattice-id components
  local components=(oidc-gateway password-hasher email-worker)

  for comp in "${components[@]}"; do
    local wasm="${comp//-/_}"
    wash oci push --insecure "localhost:${REGISTRY_PORT}/lattice-id/${comp}:dev" \
      "target/wasm32-wasip3/release/${wasm}.wasm"
  done

  # lattice-db: mirror from GHCR into local registry so the in-cluster host
  # never needs GHCR credentials (it can't read Docker config from inside the pod).
  log "Mirroring lattice-db from GHCR to local registry"
  local ldb_wasm="/tmp/storage_service_mirror.wasm"
  wash oci pull "${LATTICE_DB_IMAGE}" "${ldb_wasm}" \
    || die "Failed to pull ${LATTICE_DB_IMAGE} — is it a public GHCR package?"
  wash oci push --insecure "localhost:${REGISTRY_PORT}/lattice-db/storage-service:dev" \
    "${ldb_wasm}"

  # admin-ui-host (separate crate, embeds admin-ui dist/ assets)
  if [[ -d admin-ui/dist ]]; then
    log "Building admin-ui-host"
    (cd admin-ui/host && cargo build --target wasm32-wasip2 --release)
    wash oci push --insecure "localhost:${REGISTRY_PORT}/lattice-id/admin-ui-host:dev" \
      admin-ui/host/target/wasm32-wasip2/release/admin_ui_host.wasm
  else
    log "Skipping admin-ui-host (run 'cd admin-ui && trunk build --release' first)"
  fi
}

# ── NATS data-plane pod (standalone JetStream for lattice-db + messaging) ──

deploy_nats_data() {
  log "Deploying nats-data (standalone JetStream)"

  kubectl create configmap nats-data-config \
    --from-file=nats-data.conf=deploy/nats-data.conf \
    --dry-run=client -o yaml | kubectl apply -f -

  cat <<'EOF' | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nats-data
  labels:
    app: nats-data
spec:
  replicas: 1
  selector:
    matchLabels:
      app: nats-data
  template:
    metadata:
      labels:
        app: nats-data
    spec:
      containers:
        - name: nats
          image: nats:2-alpine
          args: ["-c", "/etc/nats/nats-data.conf"]
          ports:
            - containerPort: 4222
              name: client
          volumeMounts:
            - name: config
              mountPath: /etc/nats
              readOnly: true
      volumes:
        - name: config
          configMap:
            name: nats-data-config
---
apiVersion: v1
kind: Service
metadata:
  name: nats-data
  labels:
    app: nats-data
spec:
  type: ClusterIP
  selector:
    app: nats-data
  ports:
    - port: 4222
      targetPort: 4222
      name: client
EOF

  kubectl rollout status deploy/nats-data --timeout=60s
}

# ── Deploy workloads ─────────────────────────────────────────

deploy_workloads() {
  log "Deploying lattice-id (with co-located lattice-db service)"
  kubectl apply -f deploy/workloaddeployment-local.yaml
}

# ── Rebuild mode ─────────────────────────────────────────────

if [[ "${1:-}" == "rebuild" ]]; then
  build_and_push

  log "Clearing OCI caches and redeploying"
  for pod in $(kubectl get pods -l wasmcloud.com/hostgroup -o name 2>/dev/null); do
    kubectl exec "$pod" -- \
      sh -c 'rm -rf /oci-cache/kind-registry_5000_*' 2>/dev/null || true
  done
  kubectl delete workloaddeployment --all 2>/dev/null || true
  sleep 3
  deploy_workloads
  log "Rebuild done — wait for workloads to come up"
  exit 0
fi

# ══════════════════════════════════════════════════════════════
# Full Setup
# ══════════════════════════════════════════════════════════════

# 1. Docker registry (HTTP, local only)
if docker inspect "$REGISTRY_NAME" &>/dev/null; then
  log "Registry '$REGISTRY_NAME' already running"
else
  log "Starting local Docker registry on port ${REGISTRY_PORT}"
  docker run -d --restart=always -p "${REGISTRY_PORT}:5000" \
    --network bridge --name "$REGISTRY_NAME" registry:2
fi

# 2. Create Kind cluster
if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
  log "Kind cluster '$CLUSTER_NAME' already exists"
else
  log "Creating Kind cluster '$CLUSTER_NAME'"
  kind create cluster --name "$CLUSTER_NAME" --config deploy/kind-config.yaml
fi

# Connect registry to Kind's Docker network
docker network connect kind "$REGISTRY_NAME" 2>/dev/null || true

# 3. In-cluster registry DNS
log "Setting up in-cluster registry DNS"
REGISTRY_IP=$(docker inspect -f '{{.NetworkSettings.Networks.kind.IPAddress}}' "$REGISTRY_NAME")
kubectl apply -f - <<EOF
apiVersion: v1
kind: Service
metadata:
  name: kind-registry
  namespace: $NAMESPACE
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
  namespace: $NAMESPACE
subsets:
  - addresses:
      - ip: ${REGISTRY_IP}
    ports:
      - port: 5000
EOF

# 4. wasmCloud operator (includes NATS with JetStream + mTLS)
log "Installing wasmCloud runtime-operator v${HELM_VERSION}"
helm install wasmcloud oci://ghcr.io/wasmcloud/charts/runtime-operator \
  --namespace "$NAMESPACE" \
  --version "$HELM_VERSION" \
  --set 'gateway.service.type=NodePort' \
  --set 'gateway.service.nodePort=30950' 2>/dev/null || \
  log "wasmcloud already installed"

log "Waiting for wasmCloud pods"
kubectl wait --for=condition=available --timeout=120s \
  deployment --all 2>/dev/null || true

# 5. Expose NATS on NodePort for host-side testing (optional)
log "Patching NATS service to NodePort 30422"
kubectl patch svc nats --type=json \
  -p '[{"op":"replace","path":"/spec/type","value":"NodePort"},{"op":"add","path":"/spec/ports/0/nodePort","value":30422}]' \
  2>/dev/null || true

# Expose gateway on NodePort 80 so the Host header is bare 'localhost' (no :port suffix),
# matching the workload's virtual-host config.
log "Creating gateway-local NodePort=80"
kubectl apply -f - <<'EOF'
apiVersion: v1
kind: Service
metadata:
  name: gateway-local
  namespace: default
spec:
  type: NodePort
  selector:
    wasmcloud.com/name: runtime-gateway
  ports:
    - name: http
      port: 80
      targetPort: http
      nodePort: 80
EOF

# 6. Patch host: custom wash (wasip3 support), insecure registry, data-nats → nats-data
log "Patching host: image=wash:p3, insecure-registry, wasip3, data-nats→nats-data"
kind load docker-image localhost:5001/wasmcloud/wash:p3 --name lattice-id-local
kubectl patch deploy hostgroup-default --type=json \
  -p "[
    {\"op\":\"replace\",\"path\":\"/spec/template/spec/containers/0/image\",\"value\":\"localhost:5001/wasmcloud/wash:p3\"},
    {\"op\":\"replace\",\"path\":\"/spec/template/spec/containers/0/imagePullPolicy\",\"value\":\"Never\"},
    {\"op\":\"replace\",\"path\":\"/spec/template/spec/containers/0/args/7\",\"value\":\"--data-nats-url=nats://nats-data:4222\"},
    {\"op\":\"remove\",\"path\":\"/spec/template/spec/containers/0/args/10\"},
    {\"op\":\"remove\",\"path\":\"/spec/template/spec/containers/0/args/9\"},
    {\"op\":\"remove\",\"path\":\"/spec/template/spec/containers/0/args/8\"},
    {\"op\":\"add\",\"path\":\"/spec/template/spec/containers/0/args/-\",\"value\":\"--allow-insecure-registries\"},
    {\"op\":\"add\",\"path\":\"/spec/template/spec/containers/0/args/-\",\"value\":\"--wasip3\"}
  ]" \
  2>/dev/null || true

kubectl rollout status deploy/hostgroup-default --timeout=60s 2>/dev/null || true
sleep 5

# 7. NATS data-plane (standalone JetStream for lattice-db + messaging)
deploy_nats_data

# 8. Build and push all components
build_and_push

# 9. Deploy both workloads
deploy_workloads

# 9. Wait for health
log "Waiting for lattice-id to become ready"
for attempt in $(seq 1 60); do
  if curl -sf http://localhost/healthz 2>/dev/null | grep -q ok; then
    break
  fi
  echo -n "."
  sleep 3
done
echo ""

if curl -sf http://localhost/healthz &>/dev/null; then
  log "lattice-id is ready!"
else
  log "WARNING: lattice-id not responding yet — check logs"
fi

# ── Summary ──────────────────────────────────────────────────

echo ""
log "Local environment deployed!"
echo ""
  echo "  HTTP Gateway:  http://localhost"
echo "  NATS:          nats://localhost:4222  (mTLS, add '127.0.0.1 nats' to /etc/hosts)"
echo ""
echo "  Quick test:"
echo "    curl http://localhost/healthz"
echo "    curl http://localhost/.well-known/openid-configuration"
echo ""
echo "  Integration tests:"
echo "    BASE_URL=http://localhost bash tests/integration_protocol.sh"
echo ""
echo "  Rebuild after code changes:"
echo "    bash deploy/deploy-local.sh rebuild"
echo ""
echo "  Tear down:"
echo "    bash deploy/deploy-local.sh teardown"
