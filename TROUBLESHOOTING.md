# Troubleshooting

[English](#english) | [Español](#español)

---

## English

- **Failed to bind to interface (Are you running with CAP_NET_RAW?)**: DFlux attempts to use `SO_BINDTODEVICE` to route packets to the chosen interface. If you run it as a normal user without capabilities, it will be denied. Run `sudo setcap cap_net_raw,cap_net_admin+ep target/release/dflux` or run as root.
- **No IPs found**: Ensure your system DNS is correctly configured. DFlux uses the local system resolver for the initial lookup.
- **REMOTE failing**: Verify your remote interface (e.g., `tun0` or `wg0`) is active (`ip link show`) and has a valid endpoint. Ensure you passed the correct name via `--remote-iface`.
- **Gateway start fails or "Command not found: nft"**: The gateway transparent mode relies on `nftables`. Ensure the `nft` package is installed on your Linux system.
- **Lost internet after crash (Fail-Closed scenario)**: If DFlux crashes with a `SIGKILL` (kill -9) and the `Drop` handler couldn't clean up the routing table, your traffic might be stuck. To manually clear DFlux rules:
  ```bash
  sudo nft delete table ip dflux
  sudo ip rule del fwmark 1 lookup 100
  sudo ip route del local 0.0.0.0/0 dev lo table 100
  ```

---

## Español

- **Failed to bind to interface (Are you running with CAP_NET_RAW?)**: DFlux intenta usar `SO_BINDTODEVICE` para rutear los paquetes por la interfaz seleccionada. Si lo ejecutas como un usuario normal sin los permisos (capabilities) necesarios, será denegado. Ejecuta `sudo setcap cap_net_raw,cap_net_admin+ep target/release/dflux` o córrelo como root.
- **No IPs found**: Asegúrate de que el DNS de tu sistema esté correctamente configurado. DFlux utiliza el resolver del sistema local para la búsqueda inicial.
- **REMOTE failing**: Verifica que tu interfaz remota (ej. `tun0` o `wg0`) esté activa (`ip link show`) y tenga un endpoint válido configurado. Asegúrate de pasar el nombre correcto mediante `--remote-iface`.
- **Gateway start fails o "Command not found: nft"**: El modo de gateway transparente depende de `nftables`. Asegúrate de tener el paquete `nft` instalado en tu sistema Linux.
- **Pérdida de internet tras un crash (Escenario Fail-Closed)**: Si DFlux colapsa tras un `SIGKILL` (kill -9) y el manejador `Drop` no pudo limpiar la tabla de enrutamiento, tu tráfico puede quedarse atascado. Para limpiar las reglas de DFlux manualmente:
  ```bash
  sudo nft delete table ip dflux
  sudo ip rule del fwmark 1 lookup 100
  sudo ip route del local 0.0.0.0/0 dev lo table 100
  ```
