# Installation & Setup Guide (From Scratch)

[English](#english) | [Español](#español)

---

## English

This guide is designed for a **freshly formatted Linux machine**. It covers installing all dependencies, compiling DFlux, and setting it up to run permanently as a background `systemd` service. You will optionally learn how to configure a VPN (WireGuard) as a remote egress backend.

### 1. Install System Dependencies

Update your system and install the required tools, compilers, and networking libraries:
```bash
sudo apt update
sudo apt install -y curl build-essential pkg-config libssl-dev nftables
```

### 2. Install Rust
DFlux is written in Rust. Install the Rust compiler:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```
*When prompted, choose option `1` (Proceed with standard installation). After installation, restart your shell or run `source $HOME/.cargo/env`.*

### 3. (Optional) Setup a Remote Egress Backend (e.g. WireGuard)
DFlux works in `DIRECT` mode out of the box. If you want DFlux to route blocked traffic through an external connection, you need to configure a remote egress backend. Here is an example using WireGuard to create a new network interface (`tun0`) that routes traffic differently. Ensure it **does not hijack all system traffic**.

1. Create your config file: `sudo nano /etc/wireguard/tun0.conf`
2. Add your VPN configuration. **CRITICAL:** Add `Table = off` to the `[Interface]` section so it doesn't override your default internet.
```ini
[Interface]
PrivateKey = YOUR_PRIVATE_KEY
Address = 10.0.0.2/32
Table = off  # Prevents WireGuard from hijacking all system traffic

[Peer]
PublicKey = YOUR_SERVER_PUBLIC_KEY
AllowedIPs = 0.0.0.0/0
Endpoint = vpn.example.com:51820
```
3. Start the VPN:
```bash
sudo wg-quick up tun0
sudo systemctl enable wg-quick@tun0
```

### 4. Compile and Install DFlux
Clone the DFlux repository and compile the optimized release binary:
```bash
# Clone the repository
git clone https://github.com/yourusername/dflux.git
cd dflux

# Compile (this may take a few minutes)
cargo build --release

# Move the binary to the system path
sudo cp target/release/dflux /usr/local/bin/dflux

# Grant necessary networking capabilities (allows DFlux to manipulate nftables and bind sockets without full root)
sudo setcap cap_net_raw,cap_net_admin+ep /usr/local/bin/dflux
```

### 5. Create a Systemd Service
To ensure DFlux runs automatically on boot in the background, create a `systemd` service file.

1. Open a new service file:
```bash
sudo nano /etc/systemd/system/dflux.service
```
2. Paste the following configuration. 
> **Note on Network Interfaces:** DFlux attempts to auto-detect your default internet interface. However, it is highly recommended to specify it explicitly. You can find your active network interfaces by running `ip -br link` or `ip route show default`. Replace `wlp14s0` in the configuration below with your actual LAN interface (e.g., `eth0`, `enp3s0`).

```ini
[Unit]
Description=DFlux Transparent Egress Gateway
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
# Ensure you replace wlp14s0 with your actual LAN interface.
# If using a remote egress, append: --remote-iface tun0
ExecStart=/usr/local/bin/dflux mode enforce --direct-iface wlp14s0
Restart=on-failure
RestartSec=5
# Clean up network state before starting and after stopping
ExecStop=/usr/local/bin/dflux rollback
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
```

### 6. Enable and Start the Service
Reload `systemd` and start DFlux:
```bash
sudo systemctl daemon-reload
sudo systemctl enable dflux
sudo systemctl start dflux
```

You can check the live logs and see how DFlux evaluates and routes your traffic transparently:
```bash
sudo journalctl -u dflux -f
```

### 7. Stop and Disable the Service
If you need to stop DFlux, disable it from starting automatically, and clear any remaining network rules, run:
```bash
sudo systemctl stop dflux
sudo systemctl disable dflux
sudo /usr/local/bin/dflux rollback
```

---

## Español

Esta guía está diseñada para una **máquina Linux recién formateada**. Cubre la instalación de todas las dependencias, la compilación de DFlux y la configuración de DFlux para que se ejecute permanentemente como un servicio de fondo en `systemd`. Opcionalmente, aprenderás a configurar una VPN (WireGuard) como backend de salida (egress) remota.

### 1. Instalar Dependencias del Sistema

Actualiza tu sistema e instala las herramientas requeridas, compiladores y librerías de red:
```bash
sudo apt update
sudo apt install -y curl build-essential pkg-config libssl-dev nftables
```

### 2. Instalar Rust
DFlux está escrito en Rust. Instala el compilador:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```
*Cuando pregunte, elige la opción `1` (Proceed with standard installation). Tras la instalación, reinicia tu terminal o ejecuta `source $HOME/.cargo/env`.*

### 3. (Opcional) Configurar un Backend de Egress Remoto (ej. WireGuard)
DFlux funciona en modo `DIRECT` por defecto. Si deseas que DFlux canalice el tráfico bloqueado a través de una conexión externa, necesitas configurar un backend de salida remoto. Aquí tienes un ejemplo usando WireGuard para crear una nueva interfaz de red (`tun0`). Asegúrate de que **no secuestre todo el tráfico del sistema**.

1. Crea tu archivo de configuración: `sudo nano /etc/wireguard/tun0.conf`
2. Añade tu configuración VPN. **CRÍTICO:** Añade `Table = off` a la sección `[Interface]` para que no sobrescriba tu internet por defecto.
```ini
[Interface]
PrivateKey = TU_CLAVE_PRIVADA
Address = 10.0.0.2/32
Table = off  # Evita que WireGuard secuestre todo el tráfico del sistema

[Peer]
PublicKey = TU_CLAVE_PUBLICA
AllowedIPs = 0.0.0.0/0
Endpoint = vpn.ejemplo.com:51820
```
3. Levanta la VPN:
```bash
sudo wg-quick up tun0
sudo systemctl enable wg-quick@tun0
```

### 4. Compilar e Instalar DFlux
Clona el repositorio de DFlux y compila el binario optimizado:
```bash
# Clona el repositorio
git clone https://github.com/tu_usuario/dflux.git
cd dflux

# Compilar (esto puede tardar unos minutos)
cargo build --release

# Mover el binario a la ruta del sistema
sudo cp target/release/dflux /usr/local/bin/dflux

# Otorgar los permisos de red necesarios (permite a DFlux manipular nftables sin ser root completo)
sudo setcap cap_net_raw,cap_net_admin+ep /usr/local/bin/dflux
```

### 5. Crear el Servicio Systemd
Para que DFlux se ejecute automáticamente al arrancar el ordenador en segundo plano, crearemos un servicio `systemd`.

1. Abre un nuevo archivo de servicio:
```bash
sudo nano /etc/systemd/system/dflux.service
```
2. Pega la siguiente configuración.
> **Nota sobre Interfaces de Red:** DFlux intentará auto-detectar tu interfaz de internet predeterminada. Sin embargo, es muy recomendable especificarla explícitamente. Puedes averiguar cuáles son tus interfaces de red activas ejecutando `ip -br link` o `ip route show default`. Reemplaza `wlp14s0` en la configuración de abajo por tu interfaz LAN real (ej. `eth0`, `enp3s0`).

```ini
[Unit]
Description=DFlux Transparent Egress Gateway
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
# Reemplaza wlp14s0 por tu interfaz real
# Si usas un egress remoto, añade al final: --remote-iface tun0
ExecStart=/usr/local/bin/dflux mode enforce --direct-iface wlp14s0
Restart=on-failure
RestartSec=5
# Limpiar estado de red al detenerse
ExecStop=/usr/local/bin/dflux rollback
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
```

### 6. Habilitar y Arrancar el Servicio
Recarga `systemd` e inicia DFlux:
```bash
sudo systemctl daemon-reload
sudo systemctl enable dflux
sudo systemctl start dflux
```

Puedes observar los registros en vivo para ver cómo DFlux evalúa y enruta tu tráfico dinámicamente usando:
```bash
sudo journalctl -u dflux -f
```

### 7. Detener y Deshabilitar el Servicio
Si necesitas detener DFlux, evitar que arranque automáticamente y limpiar cualquier regla de red restante, ejecuta:
```bash
sudo systemctl stop dflux
sudo systemctl disable dflux
sudo /usr/local/bin/dflux rollback
```
