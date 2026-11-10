//! `msg`: a command-line client for Phase 0.
//!
//! Each `--dir` is one device. Try it with two terminals:
//!
//! ```text
//! msg --dir alice register --relay http://127.0.0.1:8080 --invite <code> --username alice
//! msg --dir alice invite                       # prints a code for bob
//! msg --dir bob   register --relay http://127.0.0.1:8080 --invite <code> --username bob
//! msg --dir alice new-chat bob                 # prints the chat id
//! msg --dir alice send <chat> "hi bob"
//! msg --dir bob   sync
//! ```

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use messenger_client::Client;
use messenger_core::Event;

#[derive(Parser)]
#[command(name = "msg", about = "End-to-end encrypted messenger, Phase 0 command-line client")]
struct Cli {
    /// Folder holding this device's encrypted state.
    #[arg(long, global = true, default_value = ".msg")]
    dir: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Sign up with an invite code and set this folder up as your device.
    Register {
        #[arg(long)]
        relay: String,
        #[arg(long)]
        invite: String,
        #[arg(long)]
        username: String,
    },
    /// Create an invite code for a friend.
    Invite,
    /// Start a chat with one or more friends.
    NewChat { usernames: Vec<String> },
    /// Add friends to a chat.
    Add { chat: String, usernames: Vec<String> },
    /// Remove friends from a chat.
    Remove { chat: String, usernames: Vec<String> },
    /// Replace this device's keys in a chat.
    Rotate { chat: String },
    /// Send a message.
    Send { chat: String, text: String },
    /// Fetch and decrypt everything waiting on the relay.
    Sync,
    /// List chats.
    Chats,
    /// Show a chat's messages.
    History { chat: String },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Register {
            relay,
            invite,
            username,
        } => {
            let client = Client::register(&relay, &cli.dir, &invite, &username).await?;
            println!("Registered as {}", client.identity()?);
        }
        Command::Invite => {
            let client = Client::open(&cli.dir)?;
            println!("{}", client.invite().await?);
        }
        Command::NewChat { usernames } => {
            let mut client = Client::open(&cli.dir)?;
            let names: Vec<&str> = usernames.iter().map(String::as_str).collect();
            let chat = client.create_chat(&names).await?;
            println!("{chat}");
        }
        Command::Add { chat, usernames } => {
            let mut client = Client::open(&cli.dir)?;
            let chat = client.resolve_chat(&chat)?;
            let names: Vec<&str> = usernames.iter().map(String::as_str).collect();
            client.add_members(&chat, &names).await?;
            println!("Added. Members: {}", client.members(&chat)?.join(", "));
        }
        Command::Remove { chat, usernames } => {
            let mut client = Client::open(&cli.dir)?;
            let chat = client.resolve_chat(&chat)?;
            let names: Vec<&str> = usernames.iter().map(String::as_str).collect();
            client.remove_members(&chat, &names).await?;
            println!("Removed. Members: {}", client.members(&chat)?.join(", "));
        }
        Command::Rotate { chat } => {
            let mut client = Client::open(&cli.dir)?;
            let chat = client.resolve_chat(&chat)?;
            client.rotate_keys(&chat).await?;
            println!("New keys in place (epoch {})", client.epoch(&chat)?);
        }
        Command::Send { chat, text } => {
            let mut client = Client::open(&cli.dir)?;
            let chat = client.resolve_chat(&chat)?;
            client.send(&chat, &text).await?;
            println!("Sent.");
        }
        Command::Sync => {
            let mut client = Client::open(&cli.dir)?;
            let events = client.sync().await?;
            if events.is_empty() {
                println!("Nothing new.");
            }
            for e in events {
                print_event(&e);
            }
        }
        Command::Chats => {
            let client = Client::open(&cli.dir)?;
            for c in client.chats() {
                let state = if c.active { "" } else { " (removed)" };
                let members = client.members(&c.chat_id).map(|m| m.join(", ")).unwrap_or_default();
                println!("{}{}  {}", c.chat_id, state, members);
            }
        }
        Command::History { chat } => {
            let client = Client::open(&cli.dir)?;
            let chat = client.resolve_chat(&chat)?;
            for m in client.history(&chat) {
                let who = if m.outgoing { "me" } else { m.sender.as_str() };
                println!("[{}] {}: {}", m.sent_at_ms, who, m.body);
            }
        }
    }
    Ok(())
}

fn short(id: &str) -> &str {
    &id[..id.len().min(8)]
}

fn print_event(e: &Event) {
    match e {
        Event::JoinedChat { chat_id, members } => {
            println!("Joined chat {} with {}", short(chat_id), members.join(", "))
        }
        Event::Message(m) => println!("[{}] {}: {}", short(&m.chat_id), m.sender, m.body),
        Event::MembersChanged {
            chat_id,
            by,
            added,
            removed,
            epoch,
        } => println!(
            "[{}] {} changed members (epoch {}): +[{}] -[{}]",
            short(chat_id),
            by,
            epoch,
            added.join(", "),
            removed.join(", ")
        ),
        Event::KeysUpdated { chat_id, by, epoch } => {
            println!("[{}] {} rotated keys (epoch {})", short(chat_id), by, epoch)
        }
        Event::RemovedFromChat { chat_id, by } => {
            println!("[{}] {} removed you from this chat", short(chat_id), by)
        }
        Event::Dropped { chat_id, reason } => {
            println!("[{}] couldn't process an item: {}", short(chat_id), reason)
        }
    }
}
