# Egress Abstraction and VPNs

[English](#english) | [Español](#español)

---

## English

A common conceptual mistake is to confuse a "VPN" with the routing mechanism that decides which traffic goes through the VPN.

DFlux uses abstractions to separate both concepts.

### RemoteEgress (The tunnel)

DFlux assumes that the host system (Linux) has already managed the connection with a remote tunnel. This tunnel can be provided by:
- WireGuard (`wg-quick`, `NetworkManager`)
- OpenVPN
- Cloudflare WARP (`warp-cli`)

For DFlux, this simply presents itself as a network interface (e.g., `tun0`, `wg0`, `CloudflareWARP`).

DFlux receives this interface string via CLI or configuration (`DFluxConfig`).

### DirectEgress (Local ISP)

Just like the VPN, the default internet connection is simply another interface (e.g., `wlp14s0` or `eth0`).

### SO_BINDTODEVICE

In Linux, the most elegant way to ignore the main routing table for a specific connection and force the traffic to exit via the remote tunnel is to invoke `setsockopt` with `SO_BINDTODEVICE`.

This allows DFlux to choose in real time whether the outbound `TcpStream` should use the remote or direct interface, based on the **Decision Engine**'s result, regardless of whether the VPN is configured as the default gateway or not (ideally, the VPN **should not** be the default `0.0.0.0/0` route on the host; DFlux assumes the responsibility of diverting conflicting traffic to it).

---

## Español

Un error conceptual común es confundir "VPN" con el mecanismo de enrutamiento que decide qué tráfico va por la VPN.

DFlux utiliza abstracciones para separar ambos conceptos.

### RemoteEgress (El túnel)

DFlux asume que el sistema anfitrión (Linux) ya ha gestionado la conexión con un túnel remoto. Este túnel puede ser proporcionado por:
- WireGuard (`wg-quick`, `NetworkManager`)
- OpenVPN
- Cloudflare WARP (`warp-cli`)

Para DFlux, esto simplemente se presenta como una interfaz de red (ej. `tun0`, `wg0`, `CloudflareWARP`).

DFlux recibe este string de interfaz mediante CLI o configuración (`DFluxConfig`).

### DirectEgress (ISP Local)

Al igual que la VPN, la conexión a internet predeterminada es simplemente otra interfaz (ej. `wlp14s0` o `eth0`).

### SO_BINDTODEVICE

En Linux, la forma más elegante de ignorar la tabla de ruteo principal para una conexión específica y forzar que el tráfico salga por el túnel remoto es invocar `setsockopt` con `SO_BINDTODEVICE`.

Esto permite que DFlux elija en tiempo real si el `TcpStream` de salida debe utilizar la interfaz remota o la directa, basándose en el resultado del **Decision Engine**, independientemente de si la VPN está configurada como gateway predeterminado o no (idealmente, la VPN **no** debe ser la ruta predeterminada `0.0.0.0/0` en el host; DFlux asume la responsabilidad de desviar el tráfico conflictivo hacia ella).
