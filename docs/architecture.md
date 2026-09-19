# Architecture

[English](#english) | [Español](#español)

---

## English

DFlux follows a separation of concerns model to avoid dangerous coupling (like the previous coupling to WireGuard and bash scripts).

### Connection Flow and Transparent Gateway

```text
Client (e.g., ollama run qwen)
   ↓
(HTTPS tcp/443 traffic towards Internet)
   ↓
nftables (TPROXY) redirects the packet to DFlux's local port (12345)
   ↓
DFlux TCP Listener accepts the connection.
   ↓
DFlux extracts the original destination IP by querying `stream.local_addr()` (thanks to TPROXY).
   ↓
Inspector reads the first bytes (ClientHello) to extract the SNI (Host).
   ↓
Decision Engine queries the State Manager. If no cache exists, it launches probes (TCP+TLS)
via `DirectEgress` and `RemoteEgress`.
   ↓
If `DirectEgress` throws a TLS error but `RemoteEgress` succeeds, the Decision Engine
marks the Host as `Decision::Remote`.
   ↓
Outbound Engine creates a socket and uses `SO_BINDTODEVICE` to bind it to the assigned
interface (e.g., `tun0`).
   ↓
Bidirectional copy (`tokio::io::copy_bidirectional`).
   ↓
Internet
```

### Routing Engine

DFlux's `RoutingEngine` (written in pure Rust) atomically injects rules using the `nft` binary.
It uses an **automatic fail-safe / rollback** approach:
1. Upon invoking `start()`, it creates an isolated `dflux` table in `nftables`.
2. It establishes `tproxy` rules for well-known ports (80, 443).
3. It sets dynamic `masquerade` rules in `postrouting` using the interface names injected by the Egress Manager.
4. If the DFlux process terminates (whether via `Ctrl-C` or a crash), the `Drop` implementation invokes `stop()`, which executes an `nft delete table ip dflux`, completely cleaning up the system.

### Anti-DNS Poisoning & Secure DoH

ISPs often employ DNS poisoning to enforce blockades by routing DNS queries for blocked domains to their internal proxy servers. When this happens:
1. The client browser connects to the poisoned, fake ISP server IP.
2. DFlux intercepts this traffic, but instead of trusting the poisoned destination IP, DFlux extracts the true SNI from the TLS ClientHello.
3. DFlux uses a built-in **DNS-over-HTTPS (DoH)** resolver (using Cloudflare `1.1.1.1` and Google `8.8.8.8` APIs) to bypass the ISP's DNS infrastructure completely.
4. DFlux resolves the true IP of the server and forces the Outbound Engine to establish the TCP connection to the true IP via the remote VPN, completely subverting the DNS block.

### HTTPS Management without MITM

DFlux **never decrypts HTTPS**, nor does it alter the TLS validation of the ongoing connection:
1. The `Inspector` implements a buffer that "peeks" the first bytes of the protocol without consuming them, parsing the ASN.1/TLS structures to extract the SNI.
2. The *probes* do negotiate a TLS session in the background, but they only read the server's certificate and validate whether the signature matches the hostname, without intervening in the main connection. They do not install Certificate Authorities (CAs) on the system.

---

## Español

DFlux sigue un modelo de separación de responsabilidades para evitar acoplamientos peligrosos (como el anterior acoplamiento a WireGuard y bash scripts).

### Flujo de Conexión y Gateway Transparente

```text
Cliente (ej: ollama run qwen)
   ↓
(Tráfico HTTPS tcp/443 hacia Internet)
   ↓
nftables (TPROXY) redirige el paquete al puerto local de DFlux (12345)
   ↓
DFlux TCP Listener acepta la conexión.
   ↓
DFlux extrae la IP original de destino consultando `stream.local_addr()` (gracias a TPROXY).
   ↓
Inspector lee los primeros bytes (ClientHello) para extraer el SNI (Host).
   ↓
Decision Engine consulta el State Manager. Si no hay caché, lanza probes (TCP+TLS)
por `DirectEgress` y `RemoteEgress`.
   ↓
Si `DirectEgress` da error de TLS pero `RemoteEgress` funciona, el Decision Engine
marca el Host como `Decision::Remote`.
   ↓
Outbound Engine crea un socket y usa `SO_BINDTODEVICE` para atarlo a la interfaz
asignada (ej: `tun0`).
   ↓
Copiar bidireccional (tokio::io::copy_bidirectional).
   ↓
Internet
```

### Routing Engine

El `RoutingEngine` de DFlux (escrito en Rust puro) inyecta reglas atómicas utilizando el binario `nft`.
Utiliza un enfoque de **fail-safe / rollback automático**:
1. Al invocar `start()`, crea una tabla `dflux` aislada en `nftables`.
2. Establece reglas `tproxy` para puertos conocidos (80, 443).
3. Establece reglas `masquerade` de `postrouting` dinámicas usando los nombres de las interfaces inyectadas por el Egress Manager.
4. Si el proceso de DFlux finaliza (sea con `Ctrl-C` o un crash), la implementación de `Drop` invoca `stop()`, que ejecuta un `nft delete table ip dflux`, limpiando por completo el sistema.

### Anti-Envenenamiento DNS (DNS Poisoning) y DoH Seguro

Los ISPs a menudo emplean el envenenamiento de DNS para aplicar bloqueos, redirigiendo las consultas DNS de dominios bloqueados a sus servidores proxy internos. Cuando esto sucede:
1. El navegador del cliente se conecta a la IP falsa envenenada del servidor del ISP.
2. DFlux intercepta este tráfico, pero en lugar de confiar en la IP de destino envenenada, DFlux extrae el SNI verdadero del TLS ClientHello.
3. DFlux utiliza un resolutor **DNS-over-HTTPS (DoH)** integrado (utilizando las APIs de Cloudflare `1.1.1.1` y Google `8.8.8.8`) para eludir por completo la infraestructura DNS del ISP.
4. DFlux resuelve la IP verdadera del servidor y obliga al Outbound Engine a establecer la conexión TCP a la IP verdadera a través de la VPN remota, evadiendo completamente el bloqueo DNS.

### Gestión de HTTPS sin MITM

DFlux **nunca descifra HTTPS**, ni altera la validación TLS de la conexión en curso:
1. El `Inspector` implementa un buffer que "espía" (*peeks*) los primeros bytes del protocolo sin consumirlos, analizando las estructuras ASN.1/TLS para extraer el SNI.
2. Los sondeos (*probes*) sí negocian una sesión TLS en segundo plano, pero solo leen el certificado del servidor y validan si la firma coincide con el hostname, sin intervenir la conexión principal. No instalan Autoridades Certificadoras (CAs) en el sistema.
