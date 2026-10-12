use crate::egress::EgressManager;
use anyhow::Result;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::net::TcpStream;

pub async fn connect(
    ip: IpAddr,
    port: u16,
    remote: bool,
    egress_mgr: Arc<EgressManager>,
) -> Result<TcpStream> {
    crate::outbound::connect_tcp(ip, port, remote, egress_mgr).await
}
