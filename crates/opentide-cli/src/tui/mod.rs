//! `opentide tui` on ratatui (UC-3.6d, #951; `cli/tui_app.py`,
//! `cli/tui_tabs/`): the catalogue as a tree, each object as a page or as
//! its file with what the language server and the last validate run report
//! in place, ATT&CK coverage, the Results of the commands run from it, the
//! Visibility report and threat chaining, in a terminal UI drawn through
//! crossterm.
//!
//! - [`model`]: the snapshot the UI shows, built off the UI thread.
//! - [`actions`]: `validate`, `generate` and `deploy --dry-run` (deploys are
//!   dry runs only), each the command line itself run in this process, its
//!   output printed by the CLI's renderers.
//! - [`app`]: the UI's state, its keys and its drawing.
//! - [`configuration`]: the Configuration tab's content, every credential
//!   redacted.
//! - [`text`], [`detail`], [`panes`]: what it lays out.
//!
//! [`commands::tui`](crate::commands::tui) decides whether it can open.

pub mod actions;
pub mod app;
pub mod configuration;
pub mod detail;
pub mod model;
pub mod panes;
pub mod text;

use std::path::PathBuf;
use std::time::Duration;

use crate::env::Env;

/// What the UI needs of the run that opened it.
#[derive(Debug, Clone)]
pub struct Launch {
    /// `--repo`, as typed.
    pub repo: Option<String>,
    /// The run's environment.
    pub env: Env,
    /// The working directory.
    pub cwd: PathBuf,
    /// opentide's version.
    pub version: String,
}

/// The terminal while the UI owns it: raw, on the alternate screen, the
/// mouse reported. Dropping it gives the terminal back, also when the UI
/// thread unwinds. No panic hook does it: a command panicking on its worker
/// is reported in the UI, which stays up.
struct Screen;

impl Screen {
    fn enter() -> std::io::Result<Self> {
        use ratatui::crossterm::event::EnableMouseCapture;
        use ratatui::crossterm::execute;
        use ratatui::crossterm::terminal::{EnterAlternateScreen, enable_raw_mode};
        enable_raw_mode()?;
        let screen = Self;
        execute!(std::io::stdout(), EnterAlternateScreen, EnableMouseCapture)?;
        Ok(screen)
    }
}

impl Drop for Screen {
    fn drop(&mut self) {
        use ratatui::crossterm::cursor::Show;
        use ratatui::crossterm::event::DisableMouseCapture;
        use ratatui::crossterm::execute;
        use ratatui::crossterm::terminal::{LeaveAlternateScreen, disable_raw_mode};
        let _ = execute!(
            std::io::stdout(),
            DisableMouseCapture,
            LeaveAlternateScreen,
            Show
        );
        let _ = disable_raw_mode();
    }
}

/// Opens the UI on this process's terminal until it quits; the exit code.
///
/// # Errors
///
/// The terminal could not be set up, drawn on or read.
pub fn open(launch: &Launch) -> std::io::Result<i32> {
    let screen = Screen::enter()?;
    let mut terminal =
        ratatui::Terminal::new(ratatui::backend::CrosstermBackend::new(std::io::stdout()))?;
    let mut ui = app::App::new(launch.clone());
    ui.start_load();
    let result = event_loop(&mut terminal, &mut ui);
    drop(screen);
    result.map(|()| 0)
}

fn event_loop(
    terminal: &mut ratatui::Terminal<ratatui::backend::CrosstermBackend<std::io::Stdout>>,
    ui: &mut app::App,
) -> std::io::Result<()> {
    use ratatui::crossterm::event::{self, Event, KeyEventKind};
    loop {
        terminal.draw(|frame| ui.draw(frame))?;
        if ui.quit {
            return Ok(());
        }
        if event::poll(Duration::from_millis(100))? {
            match event::read()? {
                Event::Key(key) if key.kind != KeyEventKind::Release => ui.on_key(key),
                Event::Mouse(mouse) => ui.on_mouse(mouse),
                _ => {}
            }
        }
        ui.poll();
    }
}
