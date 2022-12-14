// Websocket based connection.

use std::fmt::Binary;

use anyhow::{anyhow, Result};
use futures_util::{SinkExt, StreamExt, TryFutureExt};
use hex::ToHex;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_tungstenite::{
    accept_async, client_async, connect_async,
    tungstenite::{handshake::client::Request, Message},
    WebSocketStream,
};

use crate::{
    aes::Aes,
    pke::mqv::FHMQV,
    stream::streamenc::AesCtrHmac,
    wire::{
        self,
        message::{Certificate, LinkMsg, Packet, StreamType, WireMessage},
    },
};
use log::{error, info, log, warn};
use postcard::{from_bytes, to_allocvec, to_vec};

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

    pub async fn message_noncrypt(
        mut ws: WebSocketStream<TcpStream>,
        mut tcp: TcpStream,
    ) -> Result<()> {
        let mut buffer: Vec<u8> = vec![];
        buffer.resize(1024 * 1024, 0);
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
                    .await?;
            }
            Ok::<(), anyhow::Error>(())
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
        buffer.resize(1024 * 1024, 0);
        let (mut tx, mut rx) = ws.split();
        let (mut tcp_rx, mut tcp_tx) = tcp.into_split();
        let mut state_recv = self.enc_state.as_ref().unwrap().clone();
        let mut state_send = self.enc_state.as_ref().unwrap().clone();
        let a = tokio::spawn(async move {
            let mut error_count = 0;
            loop {
                let msg = rx.next().await;
                // Send to tcp.
                if let Some(k) = msg {
                    match k {
                        Ok(Message::Binary(v)) => {
                            // Deencaplusate data.
                            let msg: Result<wire::message::Message, _> = from_bytes(&v);
                            if let Ok(wire::message::Message::Data(Packet {
                                payload: v,
                                stream: _,
                                stream_type: _,
                            })) = msg
                            {
                                // Decrypt data.
                                match state_recv.decrypt_stream(&v) {
                                    Ok(data) => {
                                        tcp_tx.write(&data).await.unwrap();
                                    }
                                    Err(e) => {
                                        error_count += 1;
                                        eprintln!("{}", e);
                                        if error_count > 5 {
                                            panic!("Too many integrity errors!")
                                        }
                                    }
                                }
                            } else {
                                eprintln!("format mismatch!");
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
                let enc_data = wire::message::Message::Data(Packet {
                    payload: enc_data,
                    stream: 0,
                    stream_type: StreamType::TCP,
                });
                let enc_data = to_allocvec(&enc_data).unwrap();
                tx.send(Message::Binary(enc_data)).await.unwrap();
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
    certificate: Option<Vec<Certificate>>,
    identity_key: [u8; 32],
    /// Expected identity of remote. If this exists, then will replace the pubkey given by client.
    remote_identity_key: Option<[u8; 32]>,
}

impl WsServer {
    pub fn new(
        local: String,
        tcp: String,
        cert: Option<Vec<Certificate>>,
        id: [u8; 32],
        remote_id: Option<[u8; 32]>,
    ) -> Self {
        Self {
            local_endpoint: local,
            tcp_endpoint: tcp,
            certificate: cert,
            identity_key: id,
            remote_identity_key: remote_id,
        }
    }
    pub async fn server_main_loop(&mut self) -> Result<()> {
        // Listen on ws endpoint
        let listener = TcpListener::bind(&self.local_endpoint).await?;
        let mut rng = ChaCha20Rng::from_entropy();
        while let Ok((tcp_stream, _remote_addr)) = listener.accept().await {
            // Accept ws link.
            let ws = accept_async(tcp_stream).await?;
            // Connect to local endpoint.
            let local_link = TcpStream::connect(&self.tcp_endpoint).await?;
            // Handover to WsConnection.
            let mut state = self.clone();
            let mut session_key = [0u8; 32];
            rng.fill_bytes(&mut session_key);
            tokio::spawn(async move {
                let session_key = session_key;
                let mut ws = ws;
                let mut local_link = local_link;
                let key = state
                    .server_hello(session_key, &mut ws, &mut local_link)
                    .await
                    .unwrap();

                println!("shared key {}", key.encode_hex::<String>());
                // Start stream.
                let mut conn_state = WsConnection::new(
                    key[0..16].try_into().unwrap(),
                    key[16..].try_into().unwrap(),
                    0,
                );
                conn_state.message_crypt(ws, local_link).await.unwrap();
            });
        }

        Ok(())
    }
    pub async fn server_hello(
        &mut self,
        session_key: [u8; 32],
        ws: &mut WebSocketStream<TcpStream>,
        tcp: &mut TcpStream,
    ) -> Result<[u8; 32]> {
        let mut mqv = FHMQV::new(self.identity_key, session_key);
        // Receive message.
        let client_hello = ws.next().await.transpose()?.ok_or(anyhow!("No message."))?;

        // Parse message.
        if let Message::Binary(k) = client_hello {
            // decode data.
            let mqv_msg: WireMessage = from_bytes(&k)?;
            if let WireMessage::Link {
                msg:
                    LinkMsg::FHMQVHandshake {
                        identity,
                        ephemeral_key,
                        certification,
                        mac,
                    },
            } = mqv_msg
            {
                mqv.set_remote_key(self.remote_identity_key.unwrap_or(identity), ephemeral_key)?;

                // Get key.
                let key = mqv.key_server()?;
                let key_send = mqv.send();

                // Generate message.
                let msg = WireMessage::Link {
                    msg: LinkMsg::FHMQVHandshake {
                        identity: key_send.0,
                        ephemeral_key: key_send.1,
                        certification: self.certificate.clone(),
                        mac: [0u8; 32],
                    },
                };
                // Send message.
                let msg_vec = to_allocvec(&msg)?;
                ws.send(Message::Binary(msg_vec)).await?;
                Ok(key)
            } else {
                return Err(anyhow!("invalid message!"));
            }
        } else {
            return Err(anyhow!("invalid message!"));
        }
    }
}

#[derive(Debug, Clone)]
pub struct WsClient {
    remote_endpoint: String,
    tcp_endpoint: String,
    certificate: Option<Vec<Certificate>>,
    identity_key: [u8; 32],
    session_key: [u8; 32],
    remote_key: Option<[u8; 32]>,
}

impl WsClient {
    pub fn new(
        remote: String,
        tcp: String,
        cert: Option<Vec<Certificate>>,
        id: [u8; 32],
        sk: [u8; 32],
        remote_id: Option<[u8; 32]>,
    ) -> Self {
        Self {
            remote_endpoint: remote,
            tcp_endpoint: tcp,
            certificate: cert,
            identity_key: id,
            remote_key: remote_id,
            session_key: sk,
        }
    }
    pub async fn client_main_loop(&mut self) -> Result<()> {
        let listener = TcpListener::bind(&self.tcp_endpoint).await?;
        while let Ok((tcp_stream, _remote_addr)) = listener.accept().await {
            // Accept TCP link.

            // Connect to remote endpoint.
            let remote_link = TcpStream::connect(&self.remote_endpoint).await?;
            let empty_filter = Request::default();
            // Make websocket from TCP link.
            let remote_ws = client_async("ws://localhost/", remote_link).await?;

            // Handover to WsConnection.
            let mut state = self.clone();
            let mut rng = ChaCha20Rng::from_entropy();
            let mut sk = [0u8; 32];
            rng.fill_bytes(&mut sk);
            tokio::spawn(async move {
                let mut remote_ws = remote_ws;
                let mut tcp_stream = tcp_stream;
                let key = state
                    .client_hello(&mut remote_ws.0, &mut tcp_stream, sk)
                    .await
                    .unwrap();
                // Start stream.
                println!("shared key {}", key.encode_hex::<String>());
                let mut conn_state = WsConnection::new(
                    key[0..16].try_into().unwrap(),
                    key[16..].try_into().unwrap(),
                    0,
                );
                conn_state
                    .message_crypt(remote_ws.0, tcp_stream)
                    .await
                    .unwrap();
            });
        }

        Ok(())
    }

    pub async fn client_hello(
        &mut self,
        ws: &mut WebSocketStream<TcpStream>,
        tcp: &mut TcpStream,
        sk: [u8; 32],
    ) -> Result<[u8; 32]> {
        let mut mqv = FHMQV::new(self.identity_key, sk);
        // Send client hello.
        let key_send = mqv.send();

        // Generate message.
        let msg = WireMessage::Link {
            msg: LinkMsg::FHMQVHandshake {
                identity: key_send.0,
                ephemeral_key: key_send.1,
                certification: self.certificate.clone(),
                mac: [0u8; 32],
            },
        };
        // Send message.
        let msg_vec = to_allocvec(&msg)?;
        ws.send(Message::Binary(msg_vec)).await?;
        // Receive message.
        let client_hello = ws.next().await.transpose()?.ok_or(anyhow!("No message."))?;

        // Parse message.
        if let Message::Binary(k) = client_hello {
            // decode data.
            let mqv_msg: WireMessage = from_bytes(&k)?;
            if let WireMessage::Link {
                msg:
                    LinkMsg::FHMQVHandshake {
                        identity,
                        ephemeral_key,
                        certification: _,
                        mac: _,
                    },
            } = mqv_msg
            {
                mqv.set_remote_key(self.remote_key.unwrap_or(identity), ephemeral_key)?;

                // Get key.
                let key = mqv.key_client()?;
                // Set key.
                return Ok(key);
            } else {
                return Err(anyhow!("invalid message!"));
            }
        } else {
            return Err(anyhow!("invalid message!"));
        }
    }
}

#[tokio::test]
#[ignore]
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
