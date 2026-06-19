//! Terminal dashboard. Owns the UI thread; three producer threads feed one
//! mpsc channel (input, periodic poll of status+content, WS activity stream).
//! The UI loop never blocks on the network. `ratatui::init()` installs a panic
//! hook that restores the terminal, so a crash won't leave the tty wrecked.

mod poller;
mod widgets;

use crate::client::NodeClient;
use crate::types::{ContentJson, Status};
use anyhow::Result;
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind};
use std::collections::VecDeque;
use std::sync::mpsc;
use std::time::Duration;

pub enum AppEvent {
    Key(KeyEvent),
    Status(Status),
    Content(ContentJson),
    Activity(String),
    Error(String),
}

#[derive(Clone, Copy, PartialEq)]
pub enum Focus {
    Peers,
    Content,
}

pub struct App {
    pub status: Option<Status>,
    pub content: Option<ContentJson>,
    pub activity: VecDeque<String>,
    pub last_error: Option<String>,
    pub focus: Focus,
    pub selected: usize,
    pub show_activity: bool,
    pub should_quit: bool,
}

impl App {
    fn new() -> Self {
        App {
            status: None,
            content: None,
            activity: VecDeque::new(),
            last_error: None,
            focus: Focus::Peers,
            selected: 0,
            show_activity: false,
            should_quit: false,
        }
    }
}

pub fn run(client: &NodeClient) -> Result<()> {
    let (tx, rx) = mpsc::channel::<AppEvent>();
    poller::spawn_input(tx.clone());
    poller::spawn_poller(client, tx.clone());
    poller::spawn_ws(client, tx);

    let mut terminal = ratatui::init();
    let mut app = App::new();
    let res = run_loop(&mut terminal, &mut app, &rx);
    ratatui::restore();
    res
}

fn run_loop(
    terminal: &mut ratatui::DefaultTerminal,
    app: &mut App,
    rx: &mpsc::Receiver<AppEvent>,
) -> Result<()> {
    loop {
        terminal.draw(|f| widgets::draw(f, app))?;
        match rx.recv_timeout(Duration::from_millis(250)) {
            Ok(ev) => handle(app, ev),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
        if app.should_quit {
            break;
        }
    }
    Ok(())
}

fn handle(app: &mut App, ev: AppEvent) {
    match ev {
        AppEvent::Key(k) => {
            if k.kind != KeyEventKind::Press {
                return;
            }
            match k.code {
                KeyCode::Char('q') | KeyCode::Esc => app.should_quit = true,
                KeyCode::Char('w') => app.show_activity = !app.show_activity,
                KeyCode::Tab => {
                    app.focus = match app.focus {
                        Focus::Peers => Focus::Content,
                        Focus::Content => Focus::Peers,
                    };
                    app.selected = 0;
                }
                KeyCode::Down | KeyCode::Char('j') => app.selected = app.selected.saturating_add(1),
                KeyCode::Up | KeyCode::Char('k') => app.selected = app.selected.saturating_sub(1),
                _ => {}
            }
        }
        AppEvent::Status(s) => app.status = Some(s),
        AppEvent::Content(c) => app.content = Some(c),
        AppEvent::Activity(line) => {
            app.activity.push_front(line);
            while app.activity.len() > 200 {
                app.activity.pop_back();
            }
        }
        AppEvent::Error(e) => app.last_error = Some(e),
    }
}
