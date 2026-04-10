#!/usr/bin/env bash
# deploy-two-region.sh — Production-like two-region deployment using separate
# Kind clusters to eliminate operator CRD contention.
#
# Each region gets its own Kind cluster with a dedicated NATS, runtime-operator,
# and wasmCloud host.  Cross-region user lookup is done via HTTP: each region's
# oidc-gateway calls the remote region's /internal/lookup endpoint.
#
# Architecture:
#   ┌──────────────────┐              ┌──────────────────┐
#   │  lattice-id-eu   │              │  lattice-id-us   │
#   │  ┌────────────┐  │   HTTP GET   │  ┌────────────┐  │
#   │  │  operator   │  │  /internal/  │  │  operator   │  │
#   │  │  host       │  │   lookup     │  │  host       │  │
#   │  │  gateway    │──┼──────────────┼──│  gateway    │  │
#   │  │  NATS(mTLS) │  │              │  │  NATS(mTLS) │  │
#   │  └────────────┘  │              │  └────────────┘  │
#   │  eu.lid.internal  │              │  us.lid.internal  │
#   │  :8000            │              │  :8001            │
#   └──────────────────┘              └──────────────────┘
#             ▲                                 ▲
#             └───── shared OCI registry ───────┘
#
# Usage:
#   bash deploy/deploy-two-region.sh          # full setup from scratch
#   bash deploy/deploy-two-region.sh rebuild  # rebuild + redeploy only
#   bash deploy/deploy-two-region.sh teardown # destroy everything

set -euo pipefail
cd "$(dirname "$0")/.."

# ── Configuration ────────────────────────────────────────────

EU_CLUSTER="lattice-id-eu"
US_CLUSTER="lattice-id-us"
EU_CTX="kind-${EU_CLUSTER}"
US_CTX="kind-${US_CLUSTER}"
EU_NS="eu"
US_NS="us"

REGISTRY_NAME="kind-registry"
REGISTRY_PORT=5001

HELM_VERSION="2.0.1"
EU_GATEWAY_NODEPORT=8000
US_GATEWAY_NODEPORT=8001
EU_HOST_PORT=8000
US_HOST_PORT=8001
EU_HOSTNAME="eu.lid.internal"
US_HOSTNAME="us.lid.internal"

BUCKETS="lid-users lid-user-idx lid-sessions lid-clients lid-tenants lid-memberships lid-audit lid-keys lid-abuse-rate-limits"

log() { echo "==> $*"; }
die() { echo "ERROR: $*" >&2; exit 1; }

# Compute cross-cluster HTTP URLs using Docker network IPs + gateway NodePort.
# Each region's oidc-gateway uses HTTP to query remote regions' /internal/lookup.
# Hostnames (eu.lid.internal / us.lid.internal) are resolved via CoreDNS to
# Docker-network IPs, so the Host header matches the gateway's virtual-host config.
compute_region_urls() {
  EU_NODE_IP=$(docker inspect -f '{{.NetworkSettings.Networks.kind.IPAddress}}' "${EU_CLUSTER}-control-plane")
  US_NODE_IP=$(docker inspect -f '{{.NetworkSettings.Networks.kind.IPAddress}}' "${US_CLUSTER}-control-plane")
  EU_INTERNAL_URL="http://${EU_HOSTNAME}:${EU_GATEWAY_NODEPORT}"
  US_INTERNAL_URL="http://${US_HOSTNAME}:${US_GATEWAY_NODEPORT}"
  log "Region URLs: EU=${EU_INTERNAL_URL} (${EU_NODE_IP}) US=${US_INTERNAL_URL} (${US_NODE_IP})"
}

# Apply a workload YAML with region URL substitution.
apply_workload() {
  local ctx="$1" yaml="$2"
  sed -e "s|__EU_URL__|${EU_INTERNAL_URL}|g" \
      -e "s|__US_URL__|${US_INTERNAL_URL}|g" \
      "$yaml" | kubectl apply --context "$ctx" -f -
}

# ── Teardown ─────────────────────────────────────────────────

teardown() {
  log "Tearing down two-region environment"
  kind delete cluster --name "$EU_CLUSTER" 2>/dev/null || true
  kind delete cluster --name "$US_CLUSTER" 2>/dev/null || true
  docker rm -f "$REGISTRY_NAME" 2>/dev/null || true
  log "Done"
}

if [[ "${1:-}" == "teardown" ]]; then
  teardown
  exit 0
fi

# ── Build & Push ─────────────────────────────────────────────

build_and_push() {
  log "Building workspace (release, wasm32-wasip2)"
  cargo build --workspace --target wasm32-wasip2 --release

  log "Pushing components to local registry"
  local components=(core-service oidc-gateway password-hasher email-worker abuse-protection key-manager region-authority)
  for comp in "${components[@]}"; do
    local wasm
    if [[ -f "target/wasm32-wasip2/release/${comp}.wasm" ]]; then
      wasm="${comp}"
    else
      wasm="${comp//-/_}"
    fi
    wash oci push --insecure "localhost:${REGISTRY_PORT}/lattice-id/${comp}:dev" \
      "target/wasm32-wasip2/release/${wasm}.wasm"
  done
}

# ── Rebuild mode ─────────────────────────────────────────────

if [[ "${1:-}" == "rebuild" ]]; then
  build_and_push

  log "Clearing OCI caches and redeploying"
  for ctx_ns in "${EU_CTX}:${EU_NS}" "${US_CTX}:${US_NS}"; do
    ctx="${ctx_ns%%:*}"
    ns="${ctx_ns##*:}"
    for pod in $(kubectl get pods -n "$ns" --context "$ctx" \
        -l wasmcloud.com/hostgroup -o name 2>/dev/null); do
      kubectl exec -n "$ns" --context "$ctx" "$pod" -- \
        sh -c 'rm -rf /oci-cache/kind-registry_5000_*' 2>/dev/null || true
    done
    kubectl delete workloaddeployment -n "$ns" --context "$ctx" --all 2>/dev/null || true
  done
  sleep 2
  compute_region_urls
  apply_workload "$EU_CTX" deploy/workloaddeployment-eu.yaml
  apply_workload "$US_CTX" deploy/workloaddeployment-us.yaml
  log "Rebuild done — wait for workloads."
  exit 0
fi

# ══════════════════════════════════════════════════════════════
# Full Setup
# ══════════════════════════════════════════════════════════════

# 0. Check /etc/hosts for hostname entries (needed for host-machine access)
if ! grep -q "${EU_HOSTNAME}" /etc/hosts 2>/dev/null; then
  log "WARNING: ${EU_HOSTNAME} not found in /etc/hosts"
  log "  Add this line to /etc/hosts for host-machine access:"
  log "  127.0.0.1 ${EU_HOSTNAME} ${US_HOSTNAME}"
  log ""
fi

# 1. Docker registry (shared, HTTP)
if docker inspect "$REGISTRY_NAME" &>/dev/null; then
  log "Registry '$REGISTRY_NAME' already running"
else
  log "Starting local Docker registry"
  docker run -d --restart=always -p "${REGISTRY_PORT}:5000" \
    --network bridge --name "$REGISTRY_NAME" registry:2
fi

# 2. Create Kind clusters (separate — each gets its own control plane)
create_cluster() {
  local name="$1" config="$2"
  if kind get clusters 2>/dev/null | grep -q "^${name}$"; then
    log "Kind cluster '$name' already exists"
  else
    log "Creating Kind cluster '$name'"
    kind create cluster --name "$name" --config "$config"
  fi
}

create_cluster "$EU_CLUSTER" deploy/kind-eu.yaml
create_cluster "$US_CLUSTER" deploy/kind-us.yaml

# Connect registry to Kind Docker network (all Kind clusters share "kind")
docker network connect kind "$REGISTRY_NAME" 2>/dev/null || true

# 3. Cluster basics: namespace + registry DNS
setup_cluster() {
  local ctx="$1" ns="$2"

  log "Creating namespace $ns in $ctx"
  kubectl create namespace "$ns" --context "$ctx" --dry-run=client -o yaml | \
    kubectl apply --context "$ctx" -f -

  local reg_ip
  reg_ip=$(docker inspect -f '{{.NetworkSettings.Networks.kind.IPAddress}}' "$REGISTRY_NAME")

  log "Setting up in-cluster registry DNS ($ns)"
  cat <<EOF | kubectl apply --context "$ctx" -f -
apiVersion: v1
kind: Service
metadata:
  name: kind-registry
  namespace: $ns
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
  namespace: $ns
subsets:
  - addresses:
      - ip: ${reg_ip}
    ports:
      - port: 5000
EOF
}

setup_cluster "$EU_CTX" "$EU_NS"
setup_cluster "$US_CTX" "$US_NS"

# 3b. Cross-cluster DNS — patch CoreDNS so each cluster can resolve the other's hostname.
# eu.lid.internal → EU Docker IP, us.lid.internal → US Docker IP.
patch_coredns() {
  local ctx="$1"
  local eu_ip us_ip
  eu_ip=$(docker inspect -f '{{.NetworkSettings.Networks.kind.IPAddress}}' "${EU_CLUSTER}-control-plane")
  us_ip=$(docker inspect -f '{{.NetworkSettings.Networks.kind.IPAddress}}' "${US_CLUSTER}-control-plane")

  log "Patching CoreDNS in $ctx for cross-cluster hostnames"
  kubectl --context "$ctx" -n kube-system get configmap coredns -o json | \
    python3 -c "
import sys, json
cm = json.load(sys.stdin)
corefile = cm['data']['Corefile']
hosts_block = '''
lid.internal:53 {
    hosts {
        ${eu_ip} ${EU_HOSTNAME}
        ${us_ip} ${US_HOSTNAME}
        fallthrough
    }
}
'''
if '${EU_HOSTNAME}' not in corefile:
    corefile = hosts_block + corefile
    cm['data']['Corefile'] = corefile
json.dump(cm, sys.stdout)
" | kubectl --context "$ctx" -n kube-system apply -f -

  # Restart CoreDNS to pick up changes
  kubectl --context "$ctx" -n kube-system rollout restart deployment/coredns
}

patch_coredns "$EU_CTX"
patch_coredns "$US_CTX"

# Wait for CoreDNS to restart
for ctx in "$EU_CTX" "$US_CTX"; do
  kubectl rollout status deployment/coredns -n kube-system --context "$ctx" --timeout=30s 2>/dev/null || true
done

# 4. Install wasmCloud operator — ONE per cluster (no CRD contention!)
install_wasmcloud() {
  local ctx="$1" ns="$2" nodeport="$3"
  log "Installing wasmCloud runtime-operator v${HELM_VERSION} in $ns ($ctx) nodePort=${nodeport}"
  helm install wasmcloud oci://ghcr.io/wasmcloud/charts/runtime-operator \
    --kube-context "$ctx" \
    --namespace "$ns" \
    --version "$HELM_VERSION" \
    --set "gateway.service.type=NodePort" \
    --set "gateway.service.nodePort=${nodeport}" 2>/dev/null || \
    log "wasmcloud in $ctx already installed"
}

install_wasmcloud "$EU_CTX" "$EU_NS" "$EU_GATEWAY_NODEPORT"
install_wasmcloud "$US_CTX" "$US_NS" "$US_GATEWAY_NODEPORT"

# Wait for base deployments
log "Waiting for pods in both clusters"
for ctx_ns in "${EU_CTX}:${EU_NS}" "${US_CTX}:${US_NS}"; do
  ctx="${ctx_ns%%:*}"
  ns="${ctx_ns##*:}"
  kubectl wait --for=condition=available --timeout=120s \
    --context "$ctx" -n "$ns" deployment --all 2>/dev/null || true
done

# 5. Load custom wash image (has taika3d KV plugins)
log "Loading lattice-id-wash:dev into both clusters"
kind load docker-image lattice-id-wash:dev --name "$EU_CLUSTER"
kind load docker-image lattice-id-wash:dev --name "$US_CLUSTER"

# 6. Patch host: custom image + imagePullPolicy + hostgroup + insecure registry
patch_host() {
  local ctx="$1" ns="$2" region="$3"
  log "Patching host in $ns ($ctx): image, hostgroup=$region, insecure-registry"
  kubectl patch deploy hostgroup-default -n "$ns" --context "$ctx" --type=json \
    -p "[
      {\"op\":\"replace\",\"path\":\"/spec/template/spec/containers/0/image\",\"value\":\"lattice-id-wash:dev\"},
      {\"op\":\"replace\",\"path\":\"/spec/template/spec/containers/0/imagePullPolicy\",\"value\":\"Never\"},
      {\"op\":\"replace\",\"path\":\"/spec/template/spec/containers/0/args/2\",\"value\":\"--host-group=${region}\"},
      {\"op\":\"add\",\"path\":\"/spec/template/spec/containers/0/args/-\",\"value\":\"--allow-insecure-registries\"}
    ]"
}

patch_host "$EU_CTX" "$EU_NS" "$EU_NS"
patch_host "$US_CTX" "$US_NS" "$US_NS"

log "Waiting for host pods to restart"
for ctx_ns in "${EU_CTX}:${EU_NS}" "${US_CTX}:${US_NS}"; do
  ctx="${ctx_ns%%:*}"
  ns="${ctx_ns##*:}"
  kubectl rollout status deploy/hostgroup-default -n "$ns" --context "$ctx" \
    --timeout=90s 2>/dev/null || true
done
sleep 5

# Cross-region communication uses HTTP (region-authority makes outgoing
# HTTP requests to remote regions' /internal/lookup endpoint).  No NATS
# bridge or leaf-node federation is needed.

# ── Workloads ────────────────────────────────────────────────

# 7. Create KV buckets
create_buckets() {
  local ctx="$1" ns="$2"
  log "Creating KV buckets in $ns ($ctx)"
  python3 - "$ctx" "$ns" "$BUCKETS" <<'PYEOF'
import subprocess, json, sys
ctx, ns, buckets_str = sys.argv[1], sys.argv[2], sys.argv[3]
buckets = buckets_str.split()
cmds = "; ".join([
    f"nats --server nats://nats:4222 --tlscert /tls/tls.crt --tlskey /tls/tls.key --tlsca /tls/ca.crt kv add {b} 2>&1 || true"
    for b in buckets
])
overrides = {
    "spec": {
        "volumes": [{"name": "tls", "secret": {"secretName": "wasmcloud-data-tls"}}],
        "containers": [{
            "name": "nats-setup",
            "image": "natsio/nats-box:latest",
            "stdin": True,
            "tty": False,
            "volumeMounts": [{"name": "tls", "mountPath": "/tls", "readOnly": True}],
            "command": ["sh", "-c", cmds]
        }]
    }
}
subprocess.run([
    "kubectl", "run", f"nats-setup-{ns}", "--rm", "-i", "--restart=Never",
    "--context", ctx, "-n", ns,
    "--image=natsio/nats-box:latest",
    f"--overrides={json.dumps(overrides)}"
], timeout=120)
PYEOF
}

create_buckets "$EU_CTX" "$EU_NS"
create_buckets "$US_CTX" "$US_NS"

# 12. Build and push components
build_and_push

# 13. Deploy workloads
log "Deploying workloads"
compute_region_urls
apply_workload "$EU_CTX" deploy/workloaddeployment-eu.yaml
apply_workload "$US_CTX" deploy/workloaddeployment-us.yaml

# 14. Health check loop
log "Waiting for workloads to become ready"
EU_HEALTH="http://${EU_HOSTNAME}:${EU_HOST_PORT}/healthz"
US_HEALTH="http://${US_HOSTNAME}:${US_HOST_PORT}/healthz"
for attempt in $(seq 1 60); do
  eu_ok=0; us_ok=0
  curl -sf "${EU_HEALTH}" 2>/dev/null | grep -q ok && eu_ok=1
  curl -sf "${US_HEALTH}" 2>/dev/null | grep -q ok && us_ok=1
  if [[ $eu_ok -eq 1 && $us_ok -eq 1 ]]; then
    break
  fi
  echo -n "."
  sleep 5
done
echo ""

if curl -sf "${EU_HEALTH}" &>/dev/null; then
  log "EU region ready at http://${EU_HOSTNAME}:${EU_HOST_PORT}"
else
  log "WARNING: EU region not responding yet"
fi
if curl -sf "${US_HEALTH}" &>/dev/null; then
  log "US region ready at http://${US_HOSTNAME}:${US_HOST_PORT}"
else
  log "WARNING: US region not responding yet"
fi

# ── Summary ──────────────────────────────────────────────────

log ""
log "Two-region environment deployed (separate clusters — no CRD contention)!"
log ""
log "  EU: http://${EU_HOSTNAME}:${EU_HOST_PORT}  (cluster: ${EU_CLUSTER})"
log "  US: http://${US_HOSTNAME}:${US_HOST_PORT}  (cluster: ${US_CLUSTER})"
log ""
log "Host access (add to /etc/hosts if not already there):"
log "  127.0.0.1 ${EU_HOSTNAME} ${US_HOSTNAME}"
log ""
log "Kubectl:"
log "  kubectl --context ${EU_CTX} -n ${EU_NS} ..."
log "  kubectl --context ${US_CTX} -n ${US_NS} ..."
log ""
log "Cross-region test:"
log "  bash tests/integration_two_region.sh"
log ""
log "Rebuild (code changes only):"
log "  bash deploy/deploy-two-region.sh rebuild"
log ""
log "Tear down:"
log "  bash deploy/deploy-two-region.sh teardown"
