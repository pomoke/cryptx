// Websocket based connection.

use anyhow::Result;
use futures_util::{SinkExt, StreamExt, TryFutureExt};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_tungstenite::{
    accept_async, client_async, connect_async,
    tungstenite::{handshake::client::Request, Message},
    WebSocketStream,
};

use crate::{aes::Aes, stream::streamenc::AesCtrHmac};
use log::{error, info, log, warn};

#[derive(Debug, Clone)]
enum ConnectionState {
    /// Server use, to wait for client message.
    WaitForClient,

    /// Client use, to wait for server message.
    WaitForServer,
    /// Send stream.
    Ok,
    Finished,
    Aborted,
}

pub struct WsConnection {
    enc_state: Option<AesCtrHmac>,

}

impl WsConnection {
    pub fn new(aes_key: &[u8; 16], mac_key: &[u8; 16], serial: u64) -> Self {
        Self {
            enc_state: Some(AesCtrHmac::new(aes_key, mac_key, serial)),
        }
    }
    pub async fn client_hello(&mut self) -> Result<()> {
        Ok(())
    }
    pub async fn server_hello(&mut self) -> Result<()> {
        Ok(())
    }

    pub async fn message_noncrypt(
        mut ws: WebSocketStream<TcpStream>,
        mut tcp: TcpStream,
    ) -> Result<()> {
        let mut buffer: Vec<u8> = vec![];
        buffer.resize(1024*1024,0);
        let (mut tx, mut rx) = ws.split();
        let (mut tcp_rx, mut tcp_tx) = tcp.into_split();
        let a = tokio::spawn(async move {
            loop {
                let msg = rx.next().await;
                // Send to tcp.
                if let Some(k) = msg {
                    match k {
                        Ok(Message::Binary(v)) => {
                            tcp_tx.write(&v).await.unwrap();
                        }
                        Ok(Message::Close(v)) => {
                            return;
                        }
                        Ok(_) => {}
                        Err(e) => {
                            println!("{}", e);
                        }
                    }
                }
            }
        });
        let b = tokio::spawn(async move {
            loop {
                let readable = tcp_rx.readable().await.unwrap();
                // Send to ws.
                let msglen = tcp_rx.read(buffer.as_mut_slice()).await.unwrap();
                println!("tcp msg len {}", msglen);
                tx.send(Message::Binary(buffer[..msglen].to_owned()))
                    .await
                    ?;
            }
            Ok::<(),anyhow::Error>(())
        });
        tokio::join!(a, b);
        Ok(())
    }

    pub async fn message_crypt(
        &mut self,
        mut ws: WebSocketStream<TcpStream>,
        mut tcp: TcpStream,
    ) -> Result<()> {
        let mut buffer: Vec<u8> = vec![];
        buffer.resize(1024*1024,0);
        let (mut tx, mut rx) = ws.split();
        let (mut tcp_rx, mut tcp_tx) = tcp.into_split();
        let mut state_recv = self.enc_state.as_ref().unwrap().clone();
        let mut state_send = self.enc_state.as_ref().unwrap().clone();
        let a = tokio::spawn(async move {
            loop {
                let msg = rx.next().await;
                // Send to tcp.
                if let Some(k) = msg {
                    match k {
                        Ok(Message::Binary(v)) => {
                            // Decrypt data.
                            match state_recv.decrypt_stream(&v) {
                                Ok(data) => {
                                    tcp_tx.write(&data).await.unwrap();
                                },
                                Err(e) => {println!("{}",e);}
                            }
                        }
                        Ok(Message::Close(_)) => {
                            return;
                        }
                        Ok(_) => {}
                        Err(e) => {
                            println!("{}", e);
                            panic!();
                        }
                    }
                }
            }
        });
        let b = tokio::spawn(async move {
            loop {
                let _ = tcp_rx.readable().await.unwrap();
                // Send to ws.
                let msglen = tcp_rx.read(buffer.as_mut_slice()).await.unwrap();
                let enc_data = state_send.encrypt_stream(&buffer[..msglen]);
                tx.send(Message::Binary(enc_data))
                    .await
                    .unwrap();
            }
        });
        tokio::join!(a, b).0.unwrap();
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct WsServer {
    local_endpoint: String,
    tcp_endpoint: String,
    certificate: Option<()>,
    identity_key: [u8; 32],
}

impl WsServer {
    async fn server_main_loop(&mut self) -> Result<()> {
        // Listen on ws endpoint
        let listener = TcpListener::bind(&self.tcp_endpoint).await?;
        while let Ok((tcp_stream, _remote_addr)) = listener.accept().await {
            // Accept ws link.
            let ws = accept_async(tcp_stream).await?;
            // Connect to local endpoint.
            let local_link = TcpStream::connect(&self.local_endpoint).await?;
            // Handover to WsConnection.
            tokio::spawn(async move {
                ws;
                local_link
            });
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct WsClient {
    remote_endpoint: String,
    tcp_endpoint: String,
    certificate: Option<()>,
    identity_key: [u8; 32],
    session_key: [u8; 32],
}

impl WsClient {
    async fn client_main_loop(&mut self) -> Result<()> {
        let listener = TcpListener::bind(&self.remote_endpoint).await?;
        while let Ok((tcp_stream, _remote_addr)) = listener.accept().await {
            // Accept TCP link.

            // Connect to remote endpoint.
            let remote_link = TcpStream::connect(&self.remote_endpoint).await?;
            let empty_filter = Request::default();
            // Make websocket from TCP link.
            let remote_ws = client_async(empty_filter, remote_link).await?;

            // Handover to WsConnection.
            tokio::spawn(async move {});
        }

        todo!()
    }
}

#[tokio::test]
async fn test_ws_tcp_bridge() -> Result<()> {
    let server_endpoint = "127.0.0.2:10800";
    let ws_server_tcp = TcpListener::bind("127.0.0.2:65001").await?;
    // Server
    let server = tokio::spawn(async move {
        let listener = ws_server_tcp;
        let conn = listener.accept().await.unwrap();
        let ws = accept_async(conn.0).await.unwrap();
        let conn_origin = TcpStream::connect(server_endpoint).await.unwrap();
        WsConnection::message_noncrypt(ws, conn_origin)
            .await
            .unwrap();
    });

    // Client
    let client = tokio::spawn(async {
        let client_bind = TcpListener::bind("127.0.0.2:65003").await.unwrap();
        let client_conn = client_bind.accept().await.unwrap();
        let ws_conn_tcp = TcpStream::connect("127.0.0.2:65001").await.unwrap();
        let ws_conn = client_async("ws://localhost/", ws_conn_tcp).await.unwrap();
        WsConnection::message_noncrypt(ws_conn.0, client_conn.0)
            .await
            .unwrap();
    });

    tokio::join!(server, client);
    Ok(())
}
