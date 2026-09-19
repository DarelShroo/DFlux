# Operations

[English](#english) | [Español](#español)

---

## English

### Commands
DFlux provides several modes of operation via CLI. You can optionally specify the interfaces to use with `--direct-iface` and `--remote-iface`.

- **Probe**: `dflux probe <hostname> [--remote] [--direct-iface <iface>] [--remote-iface <iface>]`
- **Compare**: `dflux compare <hostname> [--direct-iface <iface>] [--remote-iface <iface>]`
- **Mode (Observe/Enforce)**: `dflux mode {observe|enforce} [--direct-iface <iface>] [--remote-iface <iface>]`
- **Rollback**: `dflux rollback`

### Transparent Gateway Mode (Enforce)
DFlux uses `nftables TPROXY` to transparently intercept traffic. Once started with `mode enforce`, you do NOT need to configure any proxy in your client applications.
Example:
```bash
# Starts transparent interception (Warning: modifies routing rules)
sudo target/release/dflux mode enforce --direct-iface eth0 --remote-iface wg0

# Traffic natively routes through DFlux
ollama run qwen3.5:9b
```
Press `Ctrl+C` to gracefully shut down the gateway. DFlux will automatically remove the `nftables` rules and return your system to normal.

### HTTP Proxy Mode (Observe)
If you prefer explicit proxying for safe testing without modifying system routing:
```bash
# Starts local HTTP proxy on 127.0.0.1:8080
target/release/dflux mode observe

# Test using explicit proxy
HTTP_PROXY=http://127.0.0.1:8080 ollama run qwen3.5:9b
```

---

## Español

### Comandos
DFlux ofrece múltiples modos de operación vía CLI. Puedes especificar opcionalmente las interfaces a usar con `--direct-iface` y `--remote-iface`.

- **Sondeo (Probe)**: `dflux probe <hostname> [--remote] [--direct-iface <iface>] [--remote-iface <iface>]`
- **Comparación (Compare)**: `dflux compare <hostname> [--direct-iface <iface>] [--remote-iface <iface>]`
- **Modo (Observe/Enforce)**: `dflux mode {observe|enforce} [--direct-iface <iface>] [--remote-iface <iface>]`
- **Rollback**: `dflux rollback`

### Modo Gateway Transparente (Enforce)
DFlux usa `nftables TPROXY` para interceptar transparentemente el tráfico. Una vez iniciado con `mode enforce`, NO necesitas configurar ningún proxy en tus aplicaciones cliente.
Ejemplo:
```bash
# Inicia la intercepción transparente (Aviso: modifica reglas de enrutamiento)
sudo target/release/dflux mode enforce --direct-iface eth0 --remote-iface wg0

# El tráfico es enrutado nativamente a través de DFlux
ollama run qwen3.5:9b
```
Presiona `Ctrl+C` para detener elegantemente el gateway. DFlux removerá automáticamente las reglas de `nftables` y retornará el sistema a la normalidad.

### Modo Proxy HTTP (Observe)
Si prefieres probar de forma aislada sin modificar el enrutamiento de tu sistema:
```bash
# Inicia el proxy local en 127.0.0.1:8080
target/release/dflux mode observe

# Probar usando proxy explícito
HTTP_PROXY=http://127.0.0.1:8080 ollama run qwen3.5:9b
```
