#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

BASE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
MODE="${1:---help}"
K3S_VERSION="v1.34.9+k3s1"
AWX_OPERATOR_VERSION="2.19.1"
AWX_NAMESPACE="awx"
AWX_NAME="awx"
K3S_INSTALLER_SHA256=""
READY_TIMEOUT_SECONDS=2400
OWNER_FILE="/etc/deployment-kits/awx/bootstrap-owner"
PROFILE_PATH="/etc/apparmor.d/cri-containerd.apparmor.d"
PROFILE_OWNER="/etc/deployment-kits/awx/apparmor-profile-owner"

log() { printf '[AWX] %s\n' "$*"; }
fail() { printf '[AWX] ERROR: %s\n' "$*" >&2; exit 1; }
require_root() { [[ "$EUID" -eq 0 ]] || fail 'Ejecuta con sudo'; }

load_env() {
  local file="$BASE/awx-bootstrap.env" line key value
  [[ -f "$file" ]] || return 0
  [[ ! -L "$file" ]] || fail 'awx-bootstrap.env no puede ser un enlace simbólico'
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%%#*}"
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    [[ -z "$line" ]] && continue
    [[ "$line" =~ ^([A-Z][A-Z0-9_]*)=(.*)$ ]] || fail 'Formato inválido en awx-bootstrap.env'
    key="${BASH_REMATCH[1]}"
    value="${BASH_REMATCH[2]}"
    value="${value#\"}"
    value="${value%\"}"
    [[ "$value" =~ ^[A-Za-z0-9_+./-]+$ ]] || fail "Valor inválido en $key"
    case "$key" in
      K3S_VERSION|AWX_OPERATOR_VERSION|AWX_NAMESPACE|AWX_NAME|K3S_INSTALLER_SHA256)
        printf -v "$key" '%s' "$value" ;;
      READY_TIMEOUT_SECONDS)
        READY_TIMEOUT_SECONDS="$value" ;;
      MIN_RAM_MIB|MIN_CPU|MIN_FREE_GIB)
        : ;;
      *) fail "Variable desconocida: $key" ;;
    esac
  done < "$file"
  [[ "$K3S_VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+\+k3s[0-9]+$ ]] || fail 'K3S_VERSION inválida'
  [[ "$AWX_OPERATOR_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail 'AWX_OPERATOR_VERSION inválida'
  [[ "$AWX_NAME" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ ]] || fail 'AWX_NAME inválido'
  [[ "$AWX_NAMESPACE" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ ]] || fail 'AWX_NAMESPACE inválido'
  [[ -z "$K3S_INSTALLER_SHA256" || "$K3S_INSTALLER_SHA256" =~ ^[a-fA-F0-9]{64}$ ]] || fail 'K3S_INSTALLER_SHA256 inválido'
  [[ "$READY_TIMEOUT_SECONDS" =~ ^[0-9]+$ ]] || fail 'READY_TIMEOUT_SECONDS inválido'
  (( READY_TIMEOUT_SECONDS >= 600 && READY_TIMEOUT_SECONDS <= 7200 )) || fail 'READY_TIMEOUT_SECONDS fuera de rango'
}

check_system() {
  [[ -f /etc/os-release ]] || fail 'No se encuentra /etc/os-release'
  . /etc/os-release
  [[ "$ID" == "ubuntu" && "$VERSION_ID" == "26.04" ]] || fail 'Este instalador necesita Ubuntu 26.04 LTS'
  [[ "$(uname -m)" == "x86_64" ]] || fail 'Este paquete está verificado solo para amd64/x86_64'
  command -v systemctl >/dev/null || fail 'Necesita systemd'
  log "Ubuntu $VERSION_ID amd64 detectado; K3s $K3S_VERSION y AWX Operator $AWX_OPERATOR_VERSION"
}

disable_cdrom_sources() {
  local file tmp
  file=/etc/apt/sources.list.d/cdrom.sources
  if [[ -f "$file" ]] && grep -qiE 'file:/+cdrom|cdrom:' "$file"; then
    if grep -qiE 'https?://' "$file"; then
      fail "$file mezcla CD-ROM con repositorios HTTP; desactívalo manualmente"
    fi
    mv "$file" "$file.disabled"
    log 'Desactivado el repositorio de instalación CD-ROM'
  fi
  for file in /etc/apt/sources.list /etc/apt/sources.list.d/*.list; do
    [[ -f "$file" ]] || continue
    if grep -qE '^[[:space:]]*deb(-src)?[[:space:]].*(file:/+cdrom|cdrom:)' "$file"; then
      tmp="$(mktemp)"
      awk '/^[[:space:]]*deb(-src)?[[:space:]]/ && /(file:\/+cdrom|cdrom:)/ { print "# " $0; next } {print}' "$file" > "$tmp"
      install -m 0644 "$tmp" "$file"
      rm -f "$tmp"
      log "Desactivada entrada CD-ROM en $file"
    fi
  done
}

install_dependencies() {
  export DEBIAN_FRONTEND=noninteractive
  disable_cdrom_sources
  apt-get update
  apt-get install -y --no-install-recommends ca-certificates curl git apparmor
}

profile_contents() {
  cat <<'PROFILE'
abi <abi/3.0>,
#include <tunables/global>

profile cri-containerd.apparmor.d flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>
  network,
  capability,
  file,
  umount,
  signal (receive) peer=unconfined,
  signal (receive) peer=runc,
  signal (receive) peer=crun,
  signal (send,receive) peer=cri-containerd.apparmor.d,
  signal (send,receive) peer=cri-containerd.apparmor.d//&unconfined,
  deny @{PROC}/* w,
  deny @{PROC}/{[^1-9],[^1-9][^0-9],[^1-9s][^0-9y][^0-9s],[^1-9][^0-9][^0-9][^0-9]*}/** w,
  deny @{PROC}/sys/[^k]** w,
  deny @{PROC}/sys/kernel/{?,??,[^s][^h][^m]**} w,
  deny @{PROC}/sysrq-trigger rwklx,
  deny @{PROC}/mem rwklx,
  deny @{PROC}/kmem rwklx,
  deny @{PROC}/kcore rwklx,
  deny mount,
  deny /sys/[^f]*/** wklx,
  deny /sys/f[^s]*/** wklx,
  deny /sys/fs/[^c]*/** wklx,
  deny /sys/fs/c[^g]*/** wklx,
  deny /sys/fs/cg[^r]*/** wklx,
  deny /sys/firmware/** rwklx,
  deny /sys/devices/virtual/powercap/** rwklx,
  deny /sys/kernel/security/** rwklx,
  ptrace (trace,tracedby,read,readby) peer=cri-containerd.apparmor.d,
  ptrace (trace,tracedby,read,readby) peer=cri-containerd.apparmor.d//&unconfined,
}
PROFILE
}

setup_apparmor() {
  local tmp
  command -v apparmor_parser >/dev/null || fail 'apparmor_parser no disponible'
  [[ -e /etc/apparmor.d/abi/3.0 && -e /etc/apparmor.d/abstractions/base ]] || fail 'Faltan reglas base de AppArmor'
  install -d -m 0700 /etc/deployment-kits/awx
  tmp="$(mktemp)"
  profile_contents > "$tmp"
  if [[ -e "$PROFILE_PATH" ]] && ! cmp -s "$tmp" "$PROFILE_PATH"; then
    rm -f "$tmp"
    fail "Existe un perfil distinto en $PROFILE_PATH; no se sobrescribe"
  fi
  if [[ ! -e "$PROFILE_PATH" ]]; then
    install -m 0644 "$tmp" "$PROFILE_PATH"
    printf 'awx-bootstrap\n' > "$PROFILE_OWNER"
  fi
  rm -f "$tmp"
  systemctl enable --now apparmor.service >/dev/null
  apparmor_parser -Kr "$PROFILE_PATH"
  if [[ "$(sysctl -n kernel.apparmor_restrict_unprivileged_unconfined)" != "1" ]]; then
    sysctl -w kernel.apparmor_restrict_unprivileged_unconfined=1 >/dev/null
  fi
  [[ "$(sysctl -n kernel.apparmor_restrict_unprivileged_unconfined)" == "1" ]] || fail 'AppArmor debe seguir activo'
  log 'Perfil AppArmor limitado a containerd cargado; protección global activa'
}

install_k3s() {
  local script
  if command -v k3s >/dev/null 2>&1; then
    [[ -f "$OWNER_FILE" ]] || fail 'K3s preexistente no pertenece a este instalador'
    systemctl is-active --quiet k3s || fail 'K3s está instalado pero el servicio no está activo'
    log 'K3s existente y administrado por este instalador; se conserva'
    return
  fi
  script="$(mktemp)"
  curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 https://get.k3s.io -o "$script"
  [[ -s "$script" ]] || fail 'Descarga del instalador K3s vacía'
  if [[ -n "$K3S_INSTALLER_SHA256" ]]; then
    printf '%s  %s\n' "$K3S_INSTALLER_SHA256" "$script" | sha256sum -c --status || fail 'Checksum K3s incorrecto'
  fi
  chmod 0700 "$script"
  INSTALL_K3S_VERSION="$K3S_VERSION" \
    INSTALL_K3S_EXEC='server --write-kubeconfig-mode 0600 --secrets-encryption' \
    sh "$script"
  rm -f "$script"
  install -d -m 0700 /etc/deployment-kits/awx
  printf 'awx-bootstrap\n' > "$OWNER_FILE"
  chmod 0600 "$OWNER_FILE"
  install -d -m 0755 /etc/systemd/system/k3s.service.d
  printf '[Unit]\nAfter=apparmor.service\nRequires=apparmor.service\n' > /etc/systemd/system/k3s.service.d/10-apparmor.conf
  systemctl daemon-reload
  log 'K3s instalado y vinculado al arranque de AppArmor'
}

wait_for_node() {
  k3s kubectl wait --for=condition=Ready node --all --timeout=600s
}

apply_awx() {
  local work=/etc/deployment-kits/awx
  cat > "$work/kustomization.yaml" <<EOF
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
namespace: ${AWX_NAMESPACE}
resources:
  - github.com/ansible/awx-operator/config/default?ref=${AWX_OPERATOR_VERSION}
images:
  - name: quay.io/ansible/awx-operator
    newTag: ${AWX_OPERATOR_VERSION}
  - name: gcr.io/kubebuilder/kube-rbac-proxy
    newName: quay.io/brancz/kube-rbac-proxy
    newTag: v0.15.0
EOF
  cat > "$work/awx.yaml" <<EOF
apiVersion: awx.ansible.com/v1beta1
kind: AWX
metadata:
  name: ${AWX_NAME}
  namespace: ${AWX_NAMESPACE}
spec:
  service_type: clusterip
  postgres_storage_class: local-path
  postgres_storage_requirements:
    requests:
      storage: 8Gi
EOF
  k3s kubectl create namespace "$AWX_NAMESPACE" --dry-run=client -o yaml | k3s kubectl apply -f -
  k3s kubectl apply -k "$work"
  k3s kubectl -n "$AWX_NAMESPACE" rollout status deployment/awx-operator-controller-manager --timeout=600s
  k3s kubectl -n "$AWX_NAMESPACE" apply -f "$work/awx.yaml"
  log 'Operator e instancia AWX creados; comprobando migraciones y disponibilidad'
}

ready_replicas() {
  local name="$1" expected available
  expected="$(k3s kubectl -n "$AWX_NAMESPACE" get deployment "$name" -o jsonpath='{.spec.replicas}' 2>/dev/null || true)"
  available="$(k3s kubectl -n "$AWX_NAMESPACE" get deployment "$name" -o jsonpath='{.status.availableReplicas}' 2>/dev/null || true)"
  [[ -n "$expected" && "$expected" != "0" && "$expected" == "$available" ]]
}

migration_complete() {
  k3s kubectl -n "$AWX_NAMESPACE" get jobs \
    -o jsonpath='{range .items[*]}{.metadata.name}{" "}{.status.succeeded}{"\n"}{end}' 2>/dev/null |
    awk -v prefix="${AWX_NAME}-migration-" 'index($1,prefix)==1 && $2>=1 {ok=1} END {exit !ok}'
}

postgres_ready() {
  k3s kubectl -n "$AWX_NAMESPACE" exec "${AWX_NAME}-postgres-15-0" -- \
    pg_isready -h 127.0.0.1 -p 5432 >/dev/null 2>&1
}

print_diagnostics() {
  k3s kubectl -n "$AWX_NAMESPACE" get awx,pods,jobs,deploy,svc,pvc >&2 || true
  k3s kubectl -n "$AWX_NAMESPACE" logs deployment/awx-operator-controller-manager -c awx-manager --tail=50 >&2 || true
}

wait_for_awx() {
  local start now iteration=0 ip code
  start="$(date +%s)"
  while :; do
    if postgres_ready && migration_complete && \
       ready_replicas "${AWX_NAME}-web" && ready_replicas "${AWX_NAME}-task"; then
      ip="$(k3s kubectl -n "$AWX_NAMESPACE" get svc "${AWX_NAME}-service" -o jsonpath='{.spec.clusterIP}')"
      code="$(curl --silent --output /dev/null --write-out '%{http_code}' --max-time 10 "http://${ip}/" || true)"
      if [[ "$code" =~ ^(200|301|302|303|307|308)$ ]]; then
        log "AWX operativo: migraciones completas, web y task disponibles, HTTP $code"
        return 0
      fi
    fi
    now="$(date +%s)"
    if (( now - start >= READY_TIMEOUT_SECONDS )); then
      print_diagnostics
      fail "AWX no completó el arranque en ${READY_TIMEOUT_SECONDS}s"
    fi
    if (( iteration % 6 == 0 )); then
      log "Esperando AWX: $((now-start))s/${READY_TIMEOUT_SECONDS}s"
      k3s kubectl -n "$AWX_NAMESPACE" get pods,jobs --no-headers 2>/dev/null || true
    fi
    iteration=$((iteration + 1))
    sleep 10
  done
}

status() {
  command -v k3s >/dev/null || fail 'K3s no está instalado'
  k3s kubectl get nodes
  k3s kubectl -n "$AWX_NAMESPACE" get pods,jobs,deploy,svc,pvc
  log "Acceso privado: sudo k3s kubectl -n $AWX_NAMESPACE port-forward svc/$AWX_NAME-service 8080:80"
}

uninstall_lab() {
  [[ -f "$OWNER_FILE" ]] || fail 'No se ha encontrado la marca de propiedad de K3s; operación cancelada'
  [[ -x /usr/local/bin/k3s-uninstall.sh ]] || fail 'No existe k3s-uninstall.sh; operación cancelada'
  local unexpected answer
  unexpected="$(k3s kubectl get namespaces -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' |
    grep -Ev "^(${AWX_NAMESPACE}|default|kube-system|kube-public|kube-node-lease)$" || true)"
  [[ -z "$unexpected" ]] || fail "Hay otros namespaces: $unexpected. No se destruye K3s."
  printf '\nSe borrarán AWX, K3s y todos sus datos persistentes de este host.\n'
  printf 'Escribe BORRAR AWX Y K3S para confirmar: '
  IFS= read -r answer
  [[ "$answer" == 'BORRAR AWX Y K3S' ]] || fail 'Cancelado'
  /usr/local/bin/k3s-uninstall.sh
  if [[ -f "$PROFILE_OWNER" && -f "$PROFILE_PATH" ]]; then
    apparmor_parser -R "$PROFILE_PATH" || true
    rm -f "$PROFILE_PATH"
  fi
  rm -rf /etc/deployment-kits/awx
  if [[ "$(sysctl -n kernel.apparmor_restrict_unprivileged_unconfined)" != "1" ]]; then
    sysctl -w kernel.apparmor_restrict_unprivileged_unconfined=1 >/dev/null
  fi
  log 'Laboratorio K3s/AWX eliminado; Ubuntu y otros servicios del host se conservan'
}

load_env
case "$MODE" in
  --help|-h)
    cat <<'USAGE'
Uso:
  bash install-awx.sh --check
  sudo bash install-awx.sh --install
  sudo bash install-awx.sh --resume
  sudo bash install-awx.sh --status
  sudo bash install-awx.sh --uninstall-lab
USAGE
    ;;
  --check)
    check_system ;;
  --install|--resume)
    require_root
    check_system
    install_dependencies
    setup_apparmor
    install_k3s
    wait_for_node
    apply_awx
    wait_for_awx
    status ;;
  --status)
    require_root
    status ;;
  --uninstall-lab)
    require_root
    check_system
    uninstall_lab ;;
  *)
    fail "Opción desconocida: $MODE" ;;
esac
