use std::net::IpAddr;
use tokio::net::TcpStream;
use anyhow::Result;
use std::sync::Arc;
use crate::egress::EgressManager;

pub async fn connect(ip: IpAddr, port: u16, remote: bool, egress_mgr: Arc<EgressManager>) -> Result<TcpStream> {
    crate::outbound::connect_tcp(ip, port, remote, egress_mgr).await
}
