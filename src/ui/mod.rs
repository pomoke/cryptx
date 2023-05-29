use std::fs;
use std::process::exit;
use std::sync::Arc;

use hex::{FromHex, ToHex};
use iced::alignment;
use iced::executor;
use iced::theme;
use iced::widget::button;
use iced::widget::{
    checkbox, column, container, horizontal_space, image, radio, row, scrollable, slider, text,
    text_input, toggler, vertical_space,
};
use iced::widget::{Button, Column, Container, Slider};
use iced::Application;
use iced::Command;
use iced::Theme;
use iced::{Color, Element, Length, Renderer, Sandbox, Settings};
use rand::RngCore;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use tokio::task::JoinHandle;

use crate::comm::ws::WsClient;
use crate::comm::ws::WsServer;
use crate::pke::ec25519::G;
use crate::pke::eddsa::Sr25519;
use crate::wire::message;

#[derive(Debug, Clone)]
pub enum SignCheckState {
    Wait,
    Valid,
    Invalid,
    Fail,
}

// GUI interface.
#[derive(Debug, Clone)]
pub enum UIMessage {
    TextChanged(String),
    HomePressed,
    ConnectPressed,
    ServerPressed,
    ManageKeyPressed,
    SignPressed,
    StartPressed,
    RemoteEndpointChanged(String),
    LocalEndpointChanged(String),
    KeyChanged(String),
    SignKeyChanged(String),
    SignMessageChanged(String),
    SignResultChanged(String),
    DoSignPressed,
    VerifyPressed,
    Noop,
    ExitPressed,
    Spawned(Arc<JoinHandle<Result<(), anyhow::Error>>>),
}

#[derive(Debug, Clone)]
pub enum UIPage {
    MainPage,
    Connect,
    Server,
    ManageKey,
    Help,
    Sign,
}
// GUI state
pub struct UI {
    page: UIPage,
    config_file_path: String,
    text: String,
    tcp_endpoint: String,
    ws_endpoint: String,
    check_key: String,
    key: [u8; 32],
    sign_key: [u8; 32],
    running: bool,
    last_error: Option<String>,
    last_success: Option<String>,
    rng: ChaCha20Rng,
    join_handler: Option<Arc<JoinHandle<Result<(), anyhow::Error>>>>,
    signature_state: SignCheckState,
    signature_check_key: String,
    signature_message: String,
    signature_value: String,
}

impl Application for UI {
    type Message = UIMessage;
    type Executor = executor::Default;
    type Theme = Theme;
    type Flags = ([u8; 32], [u8; 32]);
    fn new(privkey: Self::Flags) -> (Self, Command<Self::Message>) {
        (
            UI {
                page: UIPage::MainPage,
                config_file_path: "".to_owned(),
                text: "".to_owned(),
                tcp_endpoint: "".to_owned(),
                ws_endpoint: "".to_owned(),
                check_key: "".to_owned(),
                running: false,
                key: privkey.0,
                last_error: None,
                last_success: None,
                rng: ChaCha20Rng::from_entropy(),
                join_handler: None,
                sign_key: privkey.1,
                signature_state: SignCheckState::Wait,
                signature_check_key: "".to_owned(),
                signature_message: "".to_owned(),
                signature_value: "".to_owned(),
            },
            Command::none(),
        )
    }

    fn title(&self) -> String {
        "安全传输".to_owned()
    }

    fn update(&mut self, message: Self::Message) -> Command<Self::Message> {
        match message {
            UIMessage::TextChanged(k) => self.text = k,
            UIMessage::HomePressed => {
                self.page = UIPage::MainPage;
                self.last_error = None
            }
            UIMessage::ConnectPressed => self.page = UIPage::Connect,
            UIMessage::ServerPressed => self.page = UIPage::Server,
            UIMessage::ManageKeyPressed => self.page = UIPage::ManageKey,
            UIMessage::LocalEndpointChanged(k) => {
                self.tcp_endpoint = k;
            }
            UIMessage::RemoteEndpointChanged(k) => {
                self.ws_endpoint = k;
            }
            UIMessage::KeyChanged(k) => {
                self.check_key = k;
            }
            UIMessage::StartPressed => {
                let mut sk = [0u8; 32];
                self.rng.fill_bytes(&mut sk);
                if !self.running {
                    self.running = true;
                    let check_key = <[u8; 32]>::from_hex(&self.check_key).ok();
                    eprintln!("start pressed");
                    // Client or server?
                    match self.page {
                        UIPage::Connect => {
                            let mut client = WsClient::new(
                                self.ws_endpoint.clone(),
                                self.tcp_endpoint.clone(),
                                None,
                                self.key,
                                sk,
                                check_key,
                            );
                            return Command::perform(
                                async {
                                    tokio::spawn(async move {
                                        let mut client = client;
                                        client.client_main_loop().await.unwrap();
                                        Ok::<(), anyhow::Error>(())
                                    })
                                },
                                |x| UIMessage::Spawned(Arc::new(x)),
                            );
                        }
                        UIPage::Server => {
                            let mut server = WsServer::new(
                                self.ws_endpoint.clone(),
                                self.tcp_endpoint.clone(),
                                None,
                                self.key,
                                check_key,
                            );

                            return Command::perform(
                                async {
                                    tokio::spawn(async move {
                                        let mut server = server;
                                        server.server_main_loop().await.unwrap();
                                        Ok::<(), anyhow::Error>(())
                                    })
                                },
                                |x| UIMessage::Spawned(Arc::new(x)),
                            );
                        }
                        _ => {}
                    }
                } else {
                    self.running = false;
                    let mut handle = None;
                    std::mem::swap(&mut self.join_handler, &mut handle);
                    if let Some(join) = handle {
                        join.abort();
                    }
                }
            }
            UIMessage::SignPressed => {
                /*
                let file = FileDialog::new()
                    .set_location("~/Desktop")
                    .show_open_single_file();
                if let Ok(Some(path)) = file {
                    let file = fs::read(path);
                    if let Ok(content) = file {
                        // Try to decode.
                    }
                }
                */
                self.page = UIPage::Sign;
            }
            UIMessage::ExitPressed => {
                exit(0);
            }
            UIMessage::Spawned(k) => self.join_handler = Some(k),
            UIMessage::SignKeyChanged(x) => {
                self.signature_state = SignCheckState::Wait;
                self.signature_check_key = x;
                self.signature_value = "".to_owned();
            }
            UIMessage::SignMessageChanged(x) => {
                self.signature_state = SignCheckState::Wait;
                self.signature_message = x;
                self.signature_value = "".to_owned();
            }
            UIMessage::SignResultChanged(x) => {
                self.signature_state = SignCheckState::Wait;
                self.signature_value = x;
            }
            UIMessage::DoSignPressed => {
                let pubkey = self.sign_key * G;
                let pubkey = pubkey.encode_point();
                let pubkey = pubkey.encode_hex::<String>();
                self.signature_state = SignCheckState::Wait;
                let sig = Sr25519::sign(self.sign_key, self.signature_message.as_bytes());
                self.signature_value = format!(
                    "{}{}",
                    sig.0.encode_hex::<String>(),
                    sig.1.encode_hex::<String>()
                );
                self.signature_check_key = pubkey;
            }
            UIMessage::VerifyPressed => {
                self.signature_state = SignCheckState::Wait;
                if let (Ok(sig),Ok(pubkey)) = (<[u8;64]>::from_hex(&self.signature_value),<[u8;32]>::from_hex(&self.signature_check_key)) {
                    let mut a = [0u8;32];
                    let mut b = [0u8;32];
                    for i in 0..32 {
                        a[i] = sig[i];
                        b[i] = sig[i+32];
                    }
                    self.signature_state = if Sr25519::verify(pubkey, self.signature_message.as_bytes(), a, b).unwrap_or(false)
                    {SignCheckState::Valid} else {SignCheckState::Invalid};

                } else {
                    self.signature_state = SignCheckState::Fail;
                }
                
            }
            UIMessage::Noop => {}
        }
        Command::none()
    }

    fn view(&self) -> Element<Self::Message> {
        let mut window = column![];
        match self.page {
            UIPage::MainPage => {
                window = window.push(
                    text("Secure transport wrapper")
                        .size(48)
                        .horizontal_alignment(alignment::Horizontal::Center)
                        .vertical_alignment(alignment::Vertical::Top),
                );
                window = window.push(vertical_space(Length::Fill));
                window = window.push(
                    button(text("Client").horizontal_alignment(alignment::Horizontal::Center))
                        .on_press(UIMessage::ConnectPressed)
                        .style(theme::Button::Primary)
                        .padding(12)
                        .width(Length::Fill),
                );
                window = window.push(
                    button(text("Server").horizontal_alignment(alignment::Horizontal::Center))
                        .on_press(UIMessage::ServerPressed)
                        .style(theme::Button::Primary)
                        .padding(12)
                        .width(Length::Fill),
                );
                window = window.push(
                    button(text("Signature").horizontal_alignment(alignment::Horizontal::Center))
                        .on_press(UIMessage::SignPressed)
                        .style(theme::Button::Primary)
                        .padding(12)
                        .width(Length::Fill),
                );
                window = window.push(
                    button(text("Key manage").horizontal_alignment(alignment::Horizontal::Center))
                        .on_press(UIMessage::ManageKeyPressed)
                        .style(theme::Button::Positive)
                        .padding(12)
                        .width(Length::Fill),
                );
                window = window.push(
                    button(text("Exit").horizontal_alignment(alignment::Horizontal::Center))
                        .on_press(UIMessage::ExitPressed)
                        .style(theme::Button::Secondary)
                        .padding(12)
                        .width(Length::Fill),
                );
            }
            UIPage::Connect => {
                window = window.push(
                    text("Client config")
                        .horizontal_alignment(alignment::Horizontal::Left)
                        .size(48),
                );
                window = window.push(
                    text("Remote endpoint").horizontal_alignment(alignment::Horizontal::Left),
                );
                window = window.push(text_input(
                    "endpoint address and port",
                    &self.ws_endpoint,
                    |x| UIMessage::RemoteEndpointChanged(x),
                ));
                window = window
                    .push(text("Local endpoint").horizontal_alignment(alignment::Horizontal::Left));
                window = window.push(text_input(
                    "endpoint address and port",
                    &self.tcp_endpoint,
                    |x| UIMessage::LocalEndpointChanged(x),
                ));
                window = window.push(
                    text("Remote Key (optional)").horizontal_alignment(alignment::Horizontal::Left),
                );
                window = window.push(text_input("remote key in hex.", &self.check_key, |x| {
                    UIMessage::KeyChanged(x)
                }));
                window = window.push(vertical_space(Length::Fill));
                window = window.push(
                    button(
                        text(if self.running { "Stop" } else { "Connect" })
                            .horizontal_alignment(alignment::Horizontal::Center),
                    )
                    .on_press(UIMessage::StartPressed)
                    .style(if self.running {
                        theme::Button::Destructive
                    } else {
                        theme::Button::Primary
                    })
                    .padding(12)
                    .width(Length::Fill),
                );
                window = window.push(
                    button(text("Back").horizontal_alignment(alignment::Horizontal::Center))
                        .on_press(UIMessage::HomePressed)
                        .style(theme::Button::Secondary)
                        .padding(12)
                        .width(Length::Fill),
                );
            }
            UIPage::Server => {
                window = window.push(
                    text("Server config")
                        .horizontal_alignment(alignment::Horizontal::Left)
                        .size(48),
                );
                window = window.push(
                    text("Remote endpoint").horizontal_alignment(alignment::Horizontal::Left),
                );
                window = window.push(text_input(
                    "endpoint address and port",
                    &self.ws_endpoint,
                    |x| UIMessage::RemoteEndpointChanged(x),
                ));
                window = window
                    .push(text("Local endpoint").horizontal_alignment(alignment::Horizontal::Left));
                window = window.push(text_input(
                    "endpoint address and port",
                    &self.tcp_endpoint,
                    |x| UIMessage::LocalEndpointChanged(x),
                ));
                window = window.push(
                    text("Remote identity key (optional)")
                        .horizontal_alignment(alignment::Horizontal::Left),
                );
                window = window.push(text_input("remote public key", &self.check_key, |x| {
                    UIMessage::KeyChanged(x)
                }));
                window = window.push(vertical_space(Length::Fill));
                window = window.push(
                    button(
                        text(if self.running { "Stop" } else { "Serve" })
                            .horizontal_alignment(alignment::Horizontal::Center),
                    )
                    .on_press(UIMessage::StartPressed)
                    .style(if self.running {
                        theme::Button::Destructive
                    } else {
                        theme::Button::Primary
                    })
                    .padding(12)
                    .width(Length::Fill),
                );
                window = window.push(
                    button(text("Back").horizontal_alignment(alignment::Horizontal::Center))
                        .on_press(UIMessage::HomePressed)
                        .style(theme::Button::Secondary)
                        .padding(12)
                        .width(Length::Fill),
                );
            }
            UIPage::Sign => {
                window = window.push(text("Sign a message").size(48));
                window = window.push(text("Public Key"));
                window = window.push(text_input("", &self.signature_check_key, |x| UIMessage::SignKeyChanged(x)));
                window = window.push(text("Message for Sign"));
                window = window.push(text_input("", &self.signature_message, |x| {
                    UIMessage::SignMessageChanged(x)
                }));
                window = window.push(text("Signature"));
                window = window.push(text_input("", &self.signature_value, |x| UIMessage::SignResultChanged(x)));
                window = window.push(vertical_space(Length::Fill));
                window = window.push(
                    button(text("Sign").horizontal_alignment(alignment::Horizontal::Center))
                        .on_press(UIMessage::DoSignPressed)
                        .style(theme::Button::Primary)
                        .padding(12)
                        .width(Length::Fill),
                );
                window = window.push(
                    button(
                        text(match self.signature_state {
                            SignCheckState::Wait => "Verify",
                            SignCheckState::Valid => "Signature OK",
                            SignCheckState::Invalid => "Signature **INVALID**",
                            SignCheckState::Fail => "Error",
                        })
                        .horizontal_alignment(alignment::Horizontal::Center),
                    )
                    .on_press(UIMessage::VerifyPressed)
                    .style(match self.signature_state {
                        SignCheckState::Wait => theme::Button::Primary,
                        SignCheckState::Valid => theme::Button::Positive,
                        SignCheckState::Invalid => theme::Button::Destructive,
                        SignCheckState::Fail => theme::Button::Destructive,
                    })
                    .padding(12)
                    .width(Length::Fill),
                );
                window = window.push(
                    button(text("Exit").horizontal_alignment(alignment::Horizontal::Center))
                        .on_press(UIMessage::HomePressed)
                        .style(theme::Button::Secondary)
                        .padding(12)
                        .width(Length::Fill),
                );
            }
            UIPage::ManageKey => {
                let pubkey = self.key * G;
                let pubkey = pubkey.encode_point();
                let pubkey = pubkey.encode_hex::<String>();

                window = window.push(text("Key Management").size(48));
                // Show key.
                window = window.push(text("identity key"));
                window = window.push(text_input("", &pubkey, |x| UIMessage::Noop));
                window = window.push(text("Sign Key"));
                let pubkey = self.sign_key * G;
                let pubkey = pubkey.encode_point();
                let pubkey = pubkey.encode_hex::<String>();
                window = window.push(text_input("", &pubkey, |x| UIMessage::Noop));

                window = window.push(vertical_space(Length::Fill));
                /*
                window = window.push(
                    button(
                        text("Sign a certificate")
                            .horizontal_alignment(alignment::Horizontal::Center),
                    )
                    .on_press(UIMessage::SignPressed)
                    .style(theme::Button::Primary)
                    .padding(12)
                    .width(Length::Fill),
                );
                */
                window = window.push(
                    button(text("Confirm").horizontal_alignment(alignment::Horizontal::Center))
                        .on_press(UIMessage::HomePressed)
                        .style(theme::Button::Positive)
                        .padding(12)
                        .width(Length::Fill),
                );
                window = window.push(
                    button(text("Exit").horizontal_alignment(alignment::Horizontal::Center))
                        .on_press(UIMessage::HomePressed)
                        .style(theme::Button::Secondary)
                        .padding(12)
                        .width(Length::Fill),
                );
            }
            UIPage::Help => {
                window = window.push(text("Help"));
                window = window.push(scrollable(text(
                    "
Encrypt TCP tunnel.
",
                )))
            }
        }
        container(window.spacing(20))
            .width(Length::Fill)
            .padding(20)
            .into()
    }
}

#[test]
fn test_from_hex() {
    println!("{:?}", <[u8; 32]>::from_hex("0").unwrap_err());
}
