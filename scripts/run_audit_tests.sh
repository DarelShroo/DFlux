#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

# ==============================================================================
# DFlux Reusable Test, Diagnostics and Benchmark Suite
# ==============================================================================

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CARGO="${HOME}/.cargo/bin/cargo"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

log_pass() {
    echo -e "${GREEN}[PASS]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_fail() {
    echo -e "${RED}[FAIL]${NC} $*"
}

# 1. Unit & Integration Tests via Cargo
run_cargo_tests() {
    log_info "Ejecutando tests unitarios y de integración de DFlux..."
    cd "${PROJECT_DIR}"
    if ${CARGO} test --test audit_tests -- --nocapture; then
        log_pass "Todas las pruebas unitarias y de integración de Cargo pasaron exitosamente."
    else
        log_fail "Falló alguna prueba en 'cargo test --test audit_tests'."
        return 1
    fi
}

# 2. Non-Destructive Linux Routing and Interface Diagnostics
run_routing_diagnostics() {
    log_info "Ejecutando diagnóstico pasivo de red y enrutamiento en Linux..."
    
    echo "--- [1] Rutas por defecto del sistema ---"
    ip route show default || true

    echo "--- [2] Reglas de Policy Routing (ip rule) ---"
    ip rule show || true

    echo "--- [3] Tablas de routing personalizadas ---"
    echo "Tabla 100 (Remote/VPN si existe):"
    ip route show table 100 2>/dev/null || echo "(Tabla 100 no configurada o vacía)"

    echo "--- [4] Interfaces activas ---"
    ip -br link show

    echo "--- [5] Estado de nftables (tabla dflux) ---"
    if command -v nft >/dev/null 2>&1; then
        nft list table ip dflux 2>/dev/null || echo "(Tabla ip dflux no cargada actualmente)"
    else
        echo "(nftables no disponible en el PATH)"
    fi

    log_pass "Diagnóstico de routing completado sin modificaciones al host."
}

# 3. GitHub and HTTPS Endpoints Diagnostics
run_endpoint_diagnostics() {
    log_info "Comprobando resolución DNS, IPv4/IPv6 y TLS en endpoints de GitHub..."

    local endpoints=("github.com" "codeload.github.com" "api.github.com")
    for ep in "${endpoints[@]}"; do
        echo "=== Comprobando endpoint: ${ep} ==="
        
        # DNS Resolution
        echo "Direcciones IPv4:"
        getent ahostsv4 "${ep}" | awk '{print $1}' | sort -u || echo "Error resolviendo IPv4"
        echo "Direcciones IPv6:"
        getent ahostsv6 "${ep}" | awk '{print $1}' | sort -u || echo "Sin IPv6 o resolución fallida"

        # HTTP/TLS Check via curl
        local http_code
        local time_connect
        local time_appconnect
        local time_total

        if curl_out=$(curl -s -o /dev/null -w "%{http_code} %{time_connect} %{time_appconnect} %{time_total}" --connect-timeout 5 "https://${ep}/" 2>/dev/null); then
            read -r http_code time_connect time_appconnect time_total <<< "${curl_out}"
            echo "HTTP Code: ${http_code} | TCP Connect: ${time_connect}s | TLS Handshake: ${time_appconnect}s | Total: ${time_total}s"
            log_pass "Endpoint ${ep} accesible y respondiendo."
        else
            log_warn "Endpoint ${ep} no respondió en timeout o fue filtrado."
        fi
        echo ""
    done
}

# 4. Controlled Performance Benchmark (MB/s and Mb/s calculation)
run_performance_benchmark() {
    log_info "Ejecutando benchmark de rendimiento controlado (Git / HTTPS)..."

    local test_repo="https://github.com/DarelShroo/server.git"
    local temp_dest="/tmp/dflux_bench_$$"

    rm -rf "${temp_dest}"
    echo "Clonando repositorio de prueba: ${test_repo}"

    python3 -c "
import subprocess, time, sys, os, glob, shutil

test_repo = '${test_repo}'
temp_dest = '${temp_dest}'

start_time = time.monotonic()
proc = subprocess.run(['git', 'clone', '--quiet', test_repo, temp_dest], capture_output=True, text=True)
end_time = time.monotonic()

if proc.returncode != 0:
    print(f'[FAIL] git clone failed: {proc.stderr}', file=sys.stderr)
    shutil.rmtree(temp_dest, ignore_errors=True)
    sys.exit(1)

elapsed_sec = end_time - start_time

# Find git packfile to determine exact network wire transfer size
packs = glob.glob(os.path.join(temp_dest, '.git', 'objects', 'pack', '*.pack'))
if packs:
    size_bytes = os.path.getsize(packs[0])
else:
    size_bytes = sum(os.path.getsize(os.path.join(dirpath, f)) for dirpath, _, filenames in os.walk(temp_dest) for f in filenames)

shutil.rmtree(temp_dest, ignore_errors=True)

size_mib = size_bytes / (1024.0 * 1024.0)
size_mb = size_bytes / 1_000_000.0

mib_s = size_mib / elapsed_sec
mb_s = size_mb / elapsed_sec
mbps = (size_bytes * 8.0 / 1_000_000.0) / elapsed_sec

print('--------------------------------------------------------')
print(f'Bytes transferidos por red : {size_bytes:,} bytes ({size_mib:.2f} MiB / {size_mb:.2f} MB)')
print(f'Tiempo transcurrido        : {elapsed_sec:.3f} s')
print(f'Throughput Binario         : {mib_s:.2f} MiB/s')
print(f'Throughput Decimal         : {mb_s:.2f} MB/s')
print(f'Ancho de banda             : {mbps:.2f} Mb/s (Megabits por segundo)')
print('--------------------------------------------------------')

if mib_s >= 20.0:
    print('\033[0;32m[PASS]\033[0m Throughput superior a 20 MiB/s: Rendimiento excelente con paridad ISP.')
elif mib_s >= 10.0:
    print('\033[1;33m[WARN]\033[0m Throughput entre 10 y 20 MiB/s: Aceptable pero subóptimo.')
else:
    print('\033[0;31m[FAIL]\033[0m Throughput < 10 MiB/s: Degradación severa detectada.')
    sys.exit(1)
"
}

show_usage() {
    echo "Uso: $0 [OPCIÓN]"
    echo "Opciones:"
    echo "  --unit         Ejecuta solo tests unitarios y de integración (cargo test)"
    echo "  --routing      Ejecuta diagnóstico no destructivo de routing en Linux"
    echo "  --endpoints    Ejecuta pruebas sobre endpoints de GitHub (DNS, IPv4, IPv6, TLS)"
    echo "  --bench        Ejecuta benchmark de transferencia real (calcula MB/s y Mb/s)"
    echo "  --all          Ejecuta todas las fases (unit, routing, endpoints, bench)"
    echo "  --help         Muestra esta ayuda"
}

# Argument parsing
if [ $# -eq 0 ]; then
    show_usage
    exit 0
fi

case "$1" in
    --unit)
        run_cargo_tests
        ;;
    --routing)
        run_routing_diagnostics
        ;;
    --endpoints)
        run_endpoint_diagnostics
        ;;
    --bench)
        run_performance_benchmark
        ;;
    --all)
        log_info "Iniciando suite de auditoría integral de DFlux..."
        run_cargo_tests
        echo ""
        run_routing_diagnostics
        echo ""
        run_endpoint_diagnostics
        echo ""
        run_performance_benchmark
        echo ""
        log_pass "Suite completa ejecutada con éxito."
        ;;
    --help|-h)
        show_usage
        ;;
    *)
        log_fail "Opción desconocida: $1"
        show_usage
        exit 1
        ;;
esac
