# DFlux

[English](#english) | [Español](#español)

---

## English

DFlux is a smart network egress and gateway service for Linux.

It acts as a **Transparent Gateway** that dynamically evaluates whether traffic destined for the Internet should go out via your standard ISP connection (DIRECT) or through a tunnel or VPN configured on your system (REMOTE).

### What problem does it solve?
Imagine that certain domains or IPs fail through your Internet Service Provider (ISP), or have broken routing rules. DFlux transparently intercepts your network traffic (e.g., ollama model downloads, HTTPS browsing), performs a quick health probe, and if the direct path is broken, **redirects that traffic through a remote connection (e.g., VPN, Warp) automatically**.

It does not decrypt HTTPS. It does not perform MITM. It only analyzes the destination's viability and chooses the appropriate outbound interface on your machine.

### Components

* **Decision Engine**: Tests TLS without strict validation across all interfaces and compares the results.
* **Routing Engine**: Controls `nftables` (TPROXY) to capture outbound traffic transparently and safely, reverting the system to its natural state upon stopping (fail-safe).
* **Egress Manager**: Hardware abstraction layer. It understands "Direct" vs "Remote" without being tied to tools like WireGuard. If you configure an OpenVPN interface as "tun0", DFlux will use it dynamically.

### Installation and Permissions

Because DFlux creates `nftables` rules and uses `SO_BINDTODEVICE` to route traffic:
```bash
cargo build --release
sudo setcap cap_net_raw,cap_net_admin+ep target/release/dflux
```

### Usage

#### Start the Transparent Gateway (Enforce Mode)
To intercept HTTP/HTTPS traffic from the system or local network transparently:
```bash
sudo target/release/dflux mode enforce --direct-iface wlp14s0 --remote-iface tun0
```
> If you press `Ctrl+C`, DFlux will immediately clean up the nftables rules, restoring the original routing.

#### Safe Isolated Testing (Observe Mode)
To run DFlux as a local HTTP proxy without modifying system routing rules:
```bash
target/release/dflux mode observe
```
Then test using: `HTTP_PROXY=http://127.0.0.1:8080 curl https://example.com`

#### Emergency Rollback
If the daemon crashed and left routing rules behind:
```bash
sudo target/release/dflux rollback
```

#### Test and Compare Domains (Diagnostic Mode)
```bash
target/release/dflux compare dd20bb891979d25aebc8bec07b2b3bbc.r2.cloudflarestorage.com --direct-iface wlp14s0 --remote-iface tun0
```

### Detailed Documentation
- [Architecture](docs/architecture.md)
- [Routing & TPROXY](docs/routing.md)
- [Egress & VPN](docs/egress.md)

---

## Español

DFlux es un servicio de egress y gateway de red inteligente para Linux.

Actúa como un **enrutador transparente (Transparent Gateway)** que evalúa dinámicamente si el tráfico destinado a Internet debe salir por tu conexión ISP normal (DIRECT) o mediante un túnel o VPN configurado en tu sistema (REMOTE).

### ¿Qué problema resuelve?
Imagina que ciertos dominios o IP fallan a través de tu proveedor de Internet (ISP), o tienen reglas de enrutamiento rotas. DFlux intercepta transparentemente el tráfico de tu red (ej. descargas de ollama, navegación HTTPS), hace una prueba rápida, y si el camino directo está roto, **redirige ese tráfico a través de una conexión remota (ej. VPN, Warp) automáticamente**.

No descifra HTTPS. No hace MITM. Solo analiza la viabilidad del destino y elige la interfaz de salida de tu máquina adecuada.

### Componentes

* **Decision Engine**: Prueba TLS sin validación estricta a través de todas las interfaces y compara (¿Cuál sirve?).
* **Routing Engine**: Controla `nftables` (TPROXY) para capturar tráfico saliente transparente de forma segura, y revierte el sistema a su estado natural al detenerse (fail-safe).
* **Egress Manager**: Abstracción del hardware de red. Entiende de "Directo" vs "Remoto" sin atarse a herramientas como WireGuard. Si configuras una VPN de OpenVPN como "tun0", DFlux la usará dinámicamente.

### Instalación y Permisos

Debido a que DFlux crea reglas de `nftables` y usa `SO_BINDTODEVICE` para enrutar el tráfico:
```bash
cargo build --release
sudo setcap cap_net_raw,cap_net_admin+ep target/release/dflux
```

### Uso

#### Iniciar el Gateway Transparente (Modo Enforce)
Para interceptar tráfico 80 y 443 del sistema o de la red local de forma transparente:
```bash
sudo target/release/dflux mode enforce --direct-iface wlp14s0 --remote-iface tun0
```
> Si presionas `Ctrl+C`, DFlux limpiará de inmediato las reglas de nftables restaurando el internet original.

#### Prueba Aislada Segura (Modo Observe)
Para ejecutar DFlux como un proxy HTTP local sin modificar las reglas de enrutamiento del sistema:
```bash
target/release/dflux mode observe
```
Luego puedes probarlo usando: `HTTP_PROXY=http://127.0.0.1:8080 curl https://example.com`

#### Rollback de Emergencia
Si el demonio se cerró inesperadamente y dejó reglas colgadas en el sistema:
```bash
sudo target/release/dflux rollback
```

#### Probar y comparar dominios (Modo diagnóstico)
```bash
target/release/dflux compare dd20bb891979d25aebc8bec07b2b3bbc.r2.cloudflarestorage.com --direct-iface wlp14s0 --remote-iface tun0
```

### Documentación Detallada
- [Arquitectura](docs/architecture.md)
- [Enrutamiento y TPROXY](docs/routing.md)
- [WireGuard y Egress](docs/egress.md)
