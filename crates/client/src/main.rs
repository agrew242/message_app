//! `msg`: a command-line client, mostly for testing the relay by hand.
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

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use messenger_client::{open, register, resolve_chat, Client, Event, ImageInfo, Notice, VerifyOutcome};

#[derive(Parser)]
#[command(name = "msg", about = "End-to-end encrypted messenger, command-line client")]
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
    /// Show who you are and your verification code.
    Whoami,
    /// Set the name friends see.
    Name { name: String },
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
    /// Send a photo.
    Photo {
        chat: String,
        path: PathBuf,
        #[arg(long)]
        caption: Option<String>,
    },
    /// Download and decrypt a photo from a chat's history.
    SavePhoto {
        chat: String,
        /// The start of the message id (shown by `history`).
        message: String,
        out: PathBuf,
    },
    /// Fetch and decrypt everything waiting on the relay.
    Sync,
    /// List chats.
    Chats,
    /// Show a chat's messages and mark them read.
    History { chat: String },
    /// List the people you've chatted with and whether they're verified.
    Contacts,
    /// Show the safety number you share with a friend.
    Safety { username: String },
    /// Verify a friend with the code from their `whoami`.
    Verify { code: String },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let dir = &cli.dir;
    match cli.command {
        Command::Register {
            relay,
            invite,
            username,
        } => {
            let client = register(&relay, dir, &invite, &username).await?;
            println!("Registered as {}", client.identity()?);
        }
        Command::Whoami => {
            let client = open(dir)?;
            println!("{} ({})", client.identity()?, client.name_of(client.username()));
            println!("Verification code: {}", client.engine().verification_code());
        }
        Command::Name { name } => {
            let mut client = open(dir)?;
            client.set_display_name(&name).await?;
            println!("You're now {name}.");
        }
        Command::Invite => {
            let client = open(dir)?;
            println!("{}", client.invite().await?);
        }
        Command::NewChat { usernames } => {
            let mut client = open(dir)?;
            let chat = client.create_chat(&usernames).await?;
            println!("{chat}");
        }
        Command::Add { chat, usernames } => {
            let mut client = open(dir)?;
            let chat = resolve_chat(&client, &chat)?;
            client.add_members(&chat, &usernames).await?;
            let events = client.take_events();
            print_events(&client, events);
            println!("Added. Members: {}", client.engine().members(&chat)?.join(", "));
        }
        Command::Remove { chat, usernames } => {
            let mut client = open(dir)?;
            let chat = resolve_chat(&client, &chat)?;
            client.remove_members(&chat, &usernames).await?;
            println!("Removed. Members: {}", client.engine().members(&chat)?.join(", "));
        }
        Command::Rotate { chat } => {
            let mut client = open(dir)?;
            let chat = resolve_chat(&client, &chat)?;
            client.rotate_keys(&chat).await?;
            println!("New keys in place (epoch {})", client.engine().epoch(&chat)?);
        }
        Command::Send { chat, text } => {
            let mut client = open(dir)?;
            let chat = resolve_chat(&client, &chat)?;
            client.send_text(&chat, &text).await?;
            println!("Sent.");
        }
        Command::Photo { chat, path, caption } => {
            let mut client = open(dir)?;
            let chat = resolve_chat(&client, &chat)?;
            let bytes = std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
            let mime = match path
                .extension()
                .and_then(|e| e.to_str())
                .map(str::to_ascii_lowercase)
                .as_deref()
            {
                Some("png") => "image/png",
                Some("gif") => "image/gif",
                Some("webp") => "image/webp",
                Some("heic") => "image/heic",
                _ => "image/jpeg",
            };
            let info = ImageInfo {
                mime: mime.into(),
                caption,
                ..Default::default()
            };
            client.send_image(&chat, &bytes, info).await?;
            println!("Sent.");
        }
        Command::SavePhoto { chat, message, out } => {
            let client = open(dir)?;
            let chat = resolve_chat(&client, &chat)?;
            let found: Vec<_> = client
                .engine()
                .history(&chat)
                .into_iter()
                .filter(|m| m.id.starts_with(&message) && m.attachment.is_some())
                .collect();
            let [msg] = found.as_slice() else {
                bail!("{message} doesn't match exactly one photo");
            };
            let bytes = client
                .fetch_attachment(msg.attachment.as_ref().expect("filtered"))
                .await?;
            std::fs::write(&out, bytes)?;
            println!("Saved to {}", out.display());
        }
        Command::Sync => {
            let mut client = open(dir)?;
            let events = client.sync().await?;
            if events.is_empty() {
                println!("Nothing new.");
            }
            print_events(&client, events);
        }
        Command::Chats => {
            let client = open(dir)?;
            for c in client.chat_list() {
                let state = if c.active { "" } else { " (removed)" };
                let unread = if c.unread > 0 {
                    format!(" [{} unread]", c.unread)
                } else {
                    String::new()
                };
                println!("{}  {}{}{}", c.chat_id, c.title, state, unread);
            }
        }
        Command::History { chat } => {
            let mut client = open(dir)?;
            let chat = resolve_chat(&client, &chat)?;
            for m in client.engine().history(&chat) {
                let id = &m.id[..8];
                let who = if m.outgoing {
                    "me".to_owned()
                } else {
                    client.name_of(messenger_client::username_of(&m.sender))
                };
                match (&m.notice, &m.attachment) {
                    (Some(notice), _) => println!("{id} -- {}", describe_notice(&client, &m.sender, notice)),
                    (None, Some(a)) => println!("{id} {who}: [photo, {} bytes] {}", a.size, m.body),
                    (None, None) => {
                        let ticks = if !m.outgoing {
                            ""
                        } else if !m.read_by.is_empty() {
                            "  (read)"
                        } else if !m.delivered_to.is_empty() {
                            "  (delivered)"
                        } else {
                            ""
                        };
                        println!("{id} {who}: {}{ticks}", m.body)
                    }
                }
            }
            client.mark_read(&chat).await?;
        }
        Command::Contacts => {
            let client = open(dir)?;
            for c in client.engine().contacts() {
                let mark = if c.verified { "verified" } else { "not verified" };
                println!("{} ({}) - {}", c.username, client.name_of(&c.username), mark);
            }
        }
        Command::Safety { username } => {
            let client = open(dir)?;
            println!("{}", client.engine().safety_number(&username)?);
        }
        Command::Verify { code } => {
            let mut client = open(dir)?;
            match client.verify_code(&code).await? {
                VerifyOutcome::Verified => println!("Verified."),
                VerifyOutcome::Mismatch => {
                    println!("That code does NOT match the key in your chats. Don't trust this contact until you've worked out why.")
                }
            }
        }
    }
    Ok(())
}

fn short(id: &str) -> &str {
    &id[..id.len().min(8)]
}

fn describe_notice(client: &Client, sender: &str, notice: &Notice) -> String {
    let who = client.name_of(messenger_client::username_of(sender));
    match notice {
        Notice::Joined { members } => format!("{who} added you. In this chat: {}", members.join(", ")),
        Notice::MembersChanged { added, removed } => {
            let mut parts = Vec::new();
            if !added.is_empty() {
                parts.push(format!("added {}", added.join(", ")));
            }
            if !removed.is_empty() {
                parts.push(format!("removed {}", removed.join(", ")));
            }
            format!("{who} {}", parts.join(" and "))
        }
        Notice::Removed => format!("{who} removed you"),
        Notice::IdentityChanged { username, was_verified } => {
            let extra = if *was_verified {
                " You had verified them: check with them in person."
            } else {
                ""
            };
            format!("{username}'s security code changed.{extra}")
        }
        Notice::NotYourDevice { member } => {
            format!("{member} uses your name but not your keys. Remove it unless it's an old install of yours.")
        }
        Notice::Undecryptable { reason } => format!("a message couldn't be read ({reason})"),
    }
}

fn print_events(client: &Client, events: Vec<Event>) {
    for e in events {
        match e {
            Event::Message(m) => {
                let who = client.name_of(messenger_client::username_of(&m.sender));
                match &m.attachment {
                    Some(_) => println!("[{}] {who}: [photo] {}", short(&m.chat_id), m.body),
                    None => println!("[{}] {who}: {}", short(&m.chat_id), m.body),
                }
            }
            Event::JoinedChat { chat_id, by, members } => {
                println!("[{}] {by} added you. Members: {}", short(&chat_id), members.join(", "))
            }
            Event::MembersChanged {
                chat_id,
                by,
                added,
                removed,
                epoch,
            } => println!(
                "[{}] {by} changed members (epoch {epoch}): +[{}] -[{}]",
                short(&chat_id),
                added.join(", "),
                removed.join(", ")
            ),
            Event::KeysUpdated { chat_id, by, epoch } => {
                println!("[{}] {by} rotated keys (epoch {epoch})", short(&chat_id))
            }
            Event::RemovedFromChat { chat_id, by } => {
                println!("[{}] {by} removed you from this chat", short(&chat_id))
            }
            Event::Receipt { .. } => {}
            Event::ProfileUpdated { username, display_name } => {
                println!("{username} is now called {display_name}")
            }
            Event::IdentityChanged {
                chat_id,
                username,
                was_verified,
            } => {
                let extra = if was_verified { " You had verified them!" } else { "" };
                println!(
                    "[{}] WARNING: {username}'s security code changed.{extra}",
                    short(&chat_id)
                )
            }
            Event::NotYourDevice { chat_id, member } => {
                println!(
                    "[{}] WARNING: {member} uses your name with someone else's key",
                    short(&chat_id)
                )
            }
            Event::Dropped { chat_id, reason } => {
                println!("[{}] couldn't process an item: {reason}", short(&chat_id))
            }
        }
    }
}
