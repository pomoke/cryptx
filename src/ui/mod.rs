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
use iced_native::system::Action;
use native_dialog::{FileDialog, MessageDialog, MessageType};
use rand::RngCore;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use tokio::task::JoinHandle;

use crate::comm::ws::WsClient;
use crate::comm::ws::WsServer;
use crate::pke::ec25519::G;
use crate::wire::message;

// GUI interface.
#[derive(Debug, Clone)]
pub enum UIMessage {
    TextChanged(String),
    HomePressed,
    ConnectPressed,
    ServerPressed,
    ManageKeyPressed,
    StartPressed,
    RemoteEndpointChanged(String),
    LocalEndpointChanged(String),
    KeyChanged(String),
    SignPressed,
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
    running: bool,
    last_error: Option<String>,
    last_success: Option<String>,
    rng: ChaCha20Rng,
    join_handler: Option<Arc<JoinHandle<Result<(), anyhow::Error>>>>,
}

impl Application for UI {
    type Message = UIMessage;
    type Executor = executor::Default;
    type Theme = Theme;
    type Flags = [u8; 32];
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
                key: privkey,
                last_error: None,
                last_success: None,
                rng: ChaCha20Rng::from_entropy(),
                join_handler: None,
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
                let file = FileDialog::new()
                    .set_location("~/Desktop")
                    .show_open_single_file();
                if let Ok(Some(path)) = file {
                    let file = fs::read(path);
                    if let Ok(content) = file {
                        // Try to decode.
                    }
                }
            }
            UIMessage::ExitPressed => {
                exit(0);
            }
            UIMessage::Spawned(k) => self.join_handler = Some(k),
            _ => {}
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
            UIPage::ManageKey => {
                let pubkey = self.key * G;
                let pubkey = pubkey.encode_point();
                let pubkey = pubkey.encode_hex::<String>();
                window = window.push(text("Key Management").size(48));
                // Show key.
                window = window.push(text("Public Key"));
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
                window = window.push(text("帮助").size(48));
                window = window.push(scrollable(
                    text(
"
本系统可实现对于已有的明文传输的系统的保密传输，而不需要改变任何已有程序的代码，仅需在两台机器上运行这一程序，并且相应地修改程序所使用或者提供的的服务地址。
"
                )
                ))
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
    println!("{:?}", <[u8; 32]>::from_hex("0").unwrap());
}
