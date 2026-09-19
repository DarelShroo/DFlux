# Routing, TPROXY and Fail-Safe

[English](#english) | [Español](#español)

---

## English

DFlux dynamically utilizes `nftables` to establish its transparent interception rules.

Previously, `iptables REDIRECT` was used, which overwrote the original destination IP in the packet header (requiring a query to `libc` for `SO_ORIGINAL_DST`).
With the migration to `nftables TPROXY`:
- The original network tuple is completely preserved.
- DFlux's local socket (on port 12345) receives the marked packets as if its local IP were the real Internet destination.
- Upon accepting the connection, `stream.local_addr()` magically delivers the original IP required for decision making.

### Dynamic nftables rules

DFlux atomically compiles and loads the following internal rule set:

```nftables
table ip dflux {
    chain prerouting {
        type filter hook prerouting priority mangle; policy accept;
        # Redirect TCP 80 and 443 to the local TPROXY port 12345 and mark with 1
        tcp dport { 80, 443 } tproxy to :12345 meta mark set 1 accept
    }
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        # Masquerade on the direct interface (and remote if configured) for NAT forwarding
        oifname "wlp14s0" masquerade
        # oifname "tun0" masquerade (added dynamically if a remote egress is configured)
    }
}
```

Along with the necessary policy routing:
```bash
ip rule add fwmark 1 lookup 100
ip route add local 0.0.0.0/0 dev lo table 100
```

### Rollback and Fault Tolerance (Fail-Safe)

DFlux's design requires completely avoiding scenarios where the network collapses (fail-closed) if DFlux encounters an error or the administrator stops the service.

1. **Rust Management**: The `RoutingEngine` structure implements the `Drop` trait. This guarantees that, when destroyed (e.g., `Ctrl-C`, controlled main thread panic, or normal stop), the `.stop()` method is invoked.
2. **Atomic Cleanup**: The `stop()` method executes the explicit removal of everything created:
    - `nft delete table ip dflux`
    - `ip rule del fwmark 1 lookup 100`
    - `ip route del local ... table 100`
3. **Default Behavior**: When DFlux's rules disappear, Linux resumes the standard routing table and the user continues to exit via the ISP directly and uninterruptedly.

---

## Español

DFlux utiliza `nftables` de forma dinámica para establecer sus reglas de captura transparente.

Anteriormente se usaba `iptables REDIRECT`, lo que sobrescribía la IP de destino original en la cabecera del paquete (requiriendo consultar a `libc` por `SO_ORIGINAL_DST`).
Con la migración a `nftables TPROXY`:
- La tupla de red original se preserva completamente.
- El socket local (en el puerto 12345) de DFlux recibe los paquetes marcados como si su IP local fuera la del destino real de Internet.
- Al aceptar la conexión, `stream.local_addr()` entrega mágicamente la IP original requerida para la toma de decisiones.

### Reglas de nftables dinámicas

DFlux compila y carga de manera atómica el siguiente set de reglas interno:

```nftables
table ip dflux {
    chain prerouting {
        type filter hook prerouting priority mangle; policy accept;
        # Redirigimos TCP 80 y 443 al puerto TPROXY local 12345 y marcamos con 1
        tcp dport { 80, 443 } tproxy to :12345 meta mark set 1 accept
    }
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        # Hacemos masquerade en la interfaz direct (y remote si está configurada) para el forwarding NAT
        oifname "wlp14s0" masquerade
        # oifname "tun0" masquerade (se añade dinámicamente si hay un egress remoto configurado)
    }
}
```

Junto con el policy routing necesario:
```bash
ip rule add fwmark 1 lookup 100
ip route add local 0.0.0.0/0 dev lo table 100
```

### Rollback y Tolerancia a Fallos (Fail-Safe)

El diseño de DFlux requiere evitar por completo escenarios donde la red colapse (fail-closed) si DFlux sufre un error o el administrador detiene el servicio.

1. **Gestión en Rust**: La estructura `RoutingEngine` implementa el trait `Drop`. Esto garantiza que, al ser destruida (ej. `Ctrl-C`, pánico de hilo principal controlado, o parada normal), se invoque el método `.stop()`.
2. **Limpieza Atómica**: El método `stop()` ejecuta la eliminación explícita de todo lo creado:
    - `nft delete table ip dflux`
    - `ip rule del fwmark 1 lookup 100`
    - `ip route del local ... table 100`
3. **Comportamiento por defecto**: Al desaparecer las reglas de DFlux, Linux retoma la tabla de ruteo estándar y el usuario continúa saliendo por el ISP de forma directa e ininterrumpida.
