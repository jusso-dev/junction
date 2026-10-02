//! Ratatui catalog explorer. This crate never loads credentials: running an
//! operation is delegated to an optional runner supplied by the host.
use anyhow::{Result, bail};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use junction_core::JunctionOperation;
use junction_registry::{Registry, SearchOptions};
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Clear, List, ListItem, ListState, Paragraph, Tabs, Wrap},
};
use std::{io::IsTerminal, time::Duration};

const BACKGROUND: Color = Color::Rgb(13, 19, 29);
const PANEL: Color = Color::Rgb(20, 29, 42);
const TEXT: Color = Color::Rgb(215, 224, 235);
const MUTED: Color = Color::Rgb(126, 145, 166);
const ACCENT: Color = Color::Rgb(99, 217, 190);

/// Host-supplied execution for the selected operation and JSON input.
pub type Runner<'a> =
    Box<dyn FnMut(&JunctionOperation, serde_json::Value) -> Result<serde_json::Value> + 'a>;

/// Browse an already validated catalog with the caller's trusted risk overrides.
pub fn run(registry: &Registry, allow_preview: bool) -> Result<()> {
    run_with(registry, allow_preview, None)
}

/// Browse the catalog and, when a runner is supplied, run operations with `r`.
pub fn run_with<'a>(
    registry: &'a Registry,
    allow_preview: bool,
    runner: Option<Runner<'a>>,
) -> Result<()> {
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        bail!("Junction TUI requires an interactive terminal");
    }
    let mut app = App::new(registry, allow_preview)?;
    app.runner = runner;
    // Ratatui installs a panic hook that restores the terminal; ordinary errors
    // are restored explicitly before returning to the caller.
    let mut terminal = ratatui::init();
    let result = (|| -> Result<()> {
        terminal.draw(|frame| app.draw(frame))?;
        loop {
            if !event::poll(Duration::from_millis(200))? {
                continue;
            }
            match event::read()? {
                Event::Key(key) if key.kind == KeyEventKind::Press => {
                    if app.key(key)? {
                        break;
                    }
                }
                Event::Resize(_, _) => {}
                _ => continue,
            }
            terminal.draw(|frame| app.draw(frame))?;
        }
        Ok(())
    })();
    ratatui::restore();
    result
}

struct App<'a> {
    registry: &'a Registry,
    products: Vec<&'a str>,
    product: usize,
    services: Vec<&'a str>,
    service: usize,
    query: String,
    editing: bool,
    help: bool,
    preview: bool,
    matches: Vec<&'a JunctionOperation>,
    offset: usize,
    next: Option<usize>,
    selection: ListState,
    tab: usize,
    scroll: u16,
    runner: Option<Runner<'a>>,
    input: String,
    input_editing: bool,
    result: Option<String>,
}
const RESULT_LIMIT: usize = 64 * 1024;
impl<'a> App<'a> {
    fn new(registry: &'a Registry, preview: bool) -> Result<Self> {
        let mut app = Self {
            registry,
            products: registry.products(),
            product: 0,
            services: Vec::new(),
            service: 0,
            query: String::new(),
            editing: false,
            help: false,
            preview,
            matches: Vec::new(),
            offset: 0,
            next: None,
            selection: ListState::default(),
            tab: 0,
            scroll: 0,
            runner: None,
            input: String::new(),
            input_editing: false,
            result: None,
        };
        app.reset_services();
        app.refresh()?;
        Ok(app)
    }
    fn reset_services(&mut self) {
        let product = self
            .product
            .checked_sub(1)
            .map(|index| self.products[index]);
        self.services = self
            .registry
            .services(product)
            .into_iter()
            .map(|(_, service)| service)
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        self.service = 0;
    }
    fn refresh(&mut self) -> Result<()> {
        self.offset = 0;
        self.load_page()
    }
    fn load_page(&mut self) -> Result<()> {
        let options = SearchOptions {
            product: self
                .product
                .checked_sub(1)
                .map(|index| self.products[index]),
            service: self
                .service
                .checked_sub(1)
                .map(|index| self.services[index]),
            allow_preview: self.preview,
        };
        self.matches = if self.query.trim().is_empty() {
            let (operations, next) = self.registry.list_filtered(self.offset, 100, &options)?;
            self.next = next;
            operations
        } else {
            self.next = None;
            self.registry.search_filtered(&self.query, 100, &options)
        };
        self.selection = ListState::default().with_selected(if self.matches.is_empty() {
            None
        } else {
            Some(0)
        });
        self.scroll = 0;
        Ok(())
    }
    fn key(&mut self, key: KeyEvent) -> Result<bool> {
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            return Ok(true);
        }
        if self.help {
            match key.code {
                KeyCode::Char('q') => return Ok(true),
                KeyCode::Esc | KeyCode::Enter | KeyCode::Char('?') => self.help = false,
                _ => {}
            }
            return Ok(false);
        }
        if self.input_editing {
            match key.code {
                KeyCode::Esc => self.input_editing = false,
                KeyCode::Enter => {
                    self.input_editing = false;
                    self.run_selected();
                }
                KeyCode::Backspace => {
                    self.input.pop();
                }
                KeyCode::Char(character)
                    if !character.is_control()
                        && !key
                            .modifiers
                            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
                        && self.input.len() + character.len_utf8() <= 8192 =>
                {
                    self.input.push(character);
                }
                _ => {}
            }
            return Ok(false);
        }
        if self.editing {
            match key.code {
                KeyCode::Esc | KeyCode::Enter => self.editing = false,
                KeyCode::Backspace => {
                    self.query.pop();
                    self.refresh()?;
                }
                KeyCode::Char(character)
                    if !character.is_control()
                        && !key
                            .modifiers
                            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
                        && self.query.len() + character.len_utf8() <= 1024 =>
                {
                    self.query.push(character);
                    self.refresh()?;
                }
                _ => {}
            }
            return Ok(false);
        }
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => return Ok(true),
            KeyCode::Char('n') if self.query.trim().is_empty() && self.next.is_some() => {
                self.offset = self.next.expect("next page available");
                self.load_page()?;
            }
            KeyCode::Char('b') if self.query.trim().is_empty() && self.offset > 0 => {
                self.offset = self.offset.saturating_sub(100);
                self.load_page()?;
            }
            KeyCode::Char('?') => self.help = true,
            KeyCode::Char('/') => self.editing = true,
            KeyCode::Char('r') if self.selection.selected().is_some() => {
                if self.input.is_empty() {
                    self.input = "{}".into();
                }
                self.input_editing = true;
            }
            KeyCode::Char('x') => {
                self.query.clear();
                self.refresh()?;
            }
            KeyCode::Char('p') => {
                self.preview = !self.preview;
                self.refresh()?;
            }
            KeyCode::Char(']') => {
                self.product = (self.product + 1) % (self.products.len() + 1);
                self.reset_services();
                self.refresh()?;
            }
            KeyCode::Char('[') => {
                self.product = (self.product + self.products.len()) % (self.products.len() + 1);
                self.reset_services();
                self.refresh()?;
            }
            KeyCode::Char('}') => {
                self.service = (self.service + 1) % (self.services.len() + 1);
                self.refresh()?;
            }
            KeyCode::Char('{') => {
                self.service = (self.service + self.services.len()) % (self.services.len() + 1);
                self.refresh()?;
            }
            KeyCode::Down | KeyCode::Char('j') => self.move_selection(1),
            KeyCode::Up | KeyCode::Char('k') => self.move_selection(-1),
            KeyCode::Home if !self.matches.is_empty() => {
                self.selection.select(Some(0));
                self.scroll = 0;
            }
            KeyCode::End => {
                self.selection.select(self.matches.len().checked_sub(1));
                self.scroll = 0;
            }
            KeyCode::Tab => {
                self.tab = (self.tab + 1) % 4;
                self.scroll = 0;
            }
            KeyCode::BackTab => {
                self.tab = (self.tab + 3) % 4;
                self.scroll = 0;
            }
            KeyCode::PageDown => self.scroll = self.scroll.saturating_add(10),
            KeyCode::PageUp => self.scroll = self.scroll.saturating_sub(10),
            _ => {}
        }
        Ok(false)
    }
    fn move_selection(&mut self, direction: isize) {
        if self.matches.is_empty() {
            return;
        }
        let selected = self.selection.selected().unwrap_or(0);
        self.selection.select(Some(
            selected
                .saturating_add_signed(direction)
                .min(self.matches.len() - 1),
        ));
        self.scroll = 0;
    }
    /// Run the selected operation through the host runner and show the result.
    fn run_selected(&mut self) {
        self.tab = 3;
        self.scroll = 0;
        let Some(operation) = self
            .selection
            .selected()
            .and_then(|index| self.matches.get(index))
            .copied()
        else {
            return;
        };
        let input: serde_json::Value = match serde_json::from_str(&self.input) {
            Ok(value) => value,
            Err(_) => {
                self.result = Some("Input is not valid JSON.".into());
                return;
            }
        };
        let Some(runner) = self.runner.as_mut() else {
            self.result = Some(
                "Running needs an execution context. Start with\n  junction --context <name> tui\nOperations run under a read-only policy; use `junction execute` for changes."
                    .into(),
            );
            return;
        };
        let mut text = match runner(operation, input) {
            Ok(value) => serde_json::to_string_pretty(&value)
                .unwrap_or_else(|_| "Result could not be displayed.".into()),
            Err(error) => format!("Failed: {error}"),
        };
        if text.len() > RESULT_LIMIT {
            let mut end = RESULT_LIMIT;
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            text.truncate(end);
            text.push_str("\n… truncated");
        }
        self.result = Some(text);
    }
    fn detail(&self) -> String {
        if self.tab == 3 {
            return self.result.clone().unwrap_or_else(|| {
                "Press r to run the selected operation with JSON input.\nResults appear here."
                    .into()
            });
        }
        let Some(operation) = self
            .selection
            .selected()
            .and_then(|index| self.matches.get(index))
        else {
            return "No matching operations.\n\nPress / to change the search or [ ] to change product.".into();
        };
        let detail = match self.tab {
            1 => self
                .registry
                .input_schema(
                    &operation.id,
                    operation.api_version.as_deref(),
                    self.preview,
                )
                .and_then(|schema| Ok(serde_json::to_string_pretty(&schema)?))
                .unwrap_or_else(|_| "Input schema unavailable".into()),
            2 => self
                .registry
                .permissions(
                    &operation.id,
                    operation.api_version.as_deref(),
                    self.preview,
                )
                .and_then(|permissions| Ok(serde_json::to_string_pretty(&permissions)?))
                .unwrap_or_else(|_| "Permission metadata unavailable".into()),
            _ => format!(
                "{}\n\n{} {}\n\n{}\n\nProduct    {}\nService    {}\nVersion    {}\nMaturity   {:?}\nRisk       {:?}\n\nPagination\n{}\n\nAsynchronous operation\n{}\n\nEndpoint\n{}\n\nDocumentation\n{}\n\nSource\n{}",
                operation.id,
                operation.method,
                operation.path,
                operation.description,
                operation.product,
                operation.service,
                operation.api_version.as_deref().unwrap_or("unversioned"),
                operation.maturity,
                operation.risk,
                if let Some(token) = &operation.query_continuation {
                    format!(
                        "Query token: {}\nResponse field: {}\nContinuation method: {}",
                        token.query_parameter, token.response_pointer, operation.method
                    )
                } else if let Some(pageable) = &operation.pageable {
                    format!(
                        "Collection field: {}\nNext link: {}\nNext operation: {}",
                        pageable.item_name,
                        pageable
                            .next_link_name
                            .as_deref()
                            .unwrap_or("None declared"),
                        pageable
                            .operation_name
                            .as_deref()
                            .unwrap_or("GET continuation link")
                    )
                } else {
                    "No explicit pagination metadata".into()
                },
                if operation.long_running.is_some() {
                    "Polling declared; use operations get or wait"
                } else {
                    "Polling not declared"
                },
                operation.base_url,
                operation.documentation().unwrap_or("Unavailable"),
                operation.source.upstream,
            ),
        };
        safe_text(&detail)
    }
    fn draw(&mut self, frame: &mut Frame) {
        let area = frame.area();
        frame.render_widget(
            Block::default().style(Style::default().bg(BACKGROUND).fg(TEXT)),
            area,
        );
        if area.width < 70 || area.height < 16 {
            frame.render_widget(
                Paragraph::new("JUNCTION\n\nExpand terminal to at least 70 × 16.\nq / Ctrl+C quit")
                    .style(Style::default().fg(ACCENT)),
                area,
            );
            return;
        }
        let rows = Layout::vertical([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(6),
            Constraint::Length(2),
        ])
        .split(area);
        let stats = self.registry.stats();
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(
                    " JUNCTION ",
                    Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
                ),
                Span::styled("/ Microsoft API explorer", Style::default().fg(TEXT)),
                Span::styled(
                    format!(
                        "    {} operations · {} services",
                        stats.operations, stats.services
                    ),
                    Style::default().fg(MUTED),
                ),
            ]))
            .block(
                Block::bordered()
                    .border_type(BorderType::Rounded)
                    .border_style(Style::default().fg(MUTED)),
            ),
            rows[0],
        );
        let search = if self.input_editing {
            safe_text(&self.input)
        } else if self.query.is_empty() {
            "Search operations, resources, descriptions…".into()
        } else {
            safe_text(&self.query)
        };
        let typed_width = Line::from(format!(" {}", safe_text(&self.query))).width() as u16;
        let search_offset = if self.query.is_empty() {
            0
        } else {
            typed_width.saturating_sub(rows[1].width.saturating_sub(3))
        };
        frame.render_widget(
            Paragraph::new(format!(" {search}"))
                .scroll((0, search_offset))
                .style(Style::default().fg(if self.editing || self.input_editing {
                    ACCENT
                } else {
                    MUTED
                }))
                .block(panel(if self.input_editing {
                    " Run · JSON input · Enter run · Esc cancel "
                } else if self.editing {
                    " Search · typing "
                } else {
                    " Search · / "
                })),
            rows[1],
        );
        if self.editing {
            frame.set_cursor_position((
                rows[1].x + 1 + typed_width.saturating_sub(search_offset),
                rows[1].y + 1,
            ));
        }
        let columns = if area.width >= 110 {
            Layout::horizontal([
                Constraint::Length(20),
                Constraint::Percentage(40),
                Constraint::Min(30),
            ])
            .split(rows[2])
        } else {
            Layout::horizontal([
                Constraint::Length(0),
                Constraint::Percentage(45),
                Constraint::Min(28),
            ])
            .split(rows[2])
        };
        let products = std::iter::once("All products")
            .chain(self.products.iter().copied())
            .enumerate()
            .map(|(index, product)| {
                ListItem::new(format!(" {}", safe_text(product)))
                    .style(Style::default().fg(if index == self.product { ACCENT } else { MUTED }))
            });
        let sidebar =
            Layout::vertical([Constraint::Percentage(35), Constraint::Min(5)]).split(columns[0]);
        frame.render_stateful_widget(
            List::new(products).block(panel(" Products · [ ] ")),
            sidebar[0],
            &mut ListState::default().with_selected(Some(self.product)),
        );
        let services = std::iter::once("All services")
            .chain(self.services.iter().copied())
            .enumerate()
            .map(|(index, service)| {
                ListItem::new(format!(" {}", safe_text(service)))
                    .style(Style::default().fg(if index == self.service { ACCENT } else { MUTED }))
            });
        frame.render_stateful_widget(
            List::new(services).block(panel(" Services · { } ")),
            sidebar[1],
            &mut ListState::default().with_selected(Some(self.service)),
        );
        let items = self.matches.iter().map(|operation| {
            ListItem::new(vec![
                Line::from(Span::styled(
                    safe_text(&format!(
                        "{} / {}",
                        operation.resource.replace('_', " "),
                        operation.operation.replace('_', " ")
                    )),
                    Style::default().fg(TEXT),
                )),
                Line::from(Span::styled(
                    safe_text(&format!(
                        "{} · {} · {:?} · {}",
                        operation.service,
                        operation.method,
                        operation.risk,
                        operation.api_version.as_deref().unwrap_or("unversioned")
                    )),
                    Style::default().fg(MUTED),
                )),
                Line::from(""),
            ])
        });
        frame.render_stateful_widget(
            List::new(items)
                .block(panel(&format!(
                    " Operations · page {} · {} shown ",
                    self.offset / 100 + 1,
                    self.matches.len()
                )))
                .highlight_style(
                    Style::default()
                        .bg(Color::Rgb(33, 69, 76))
                        .add_modifier(Modifier::BOLD),
                )
                .highlight_symbol("▎ "),
            columns[1],
            &mut self.selection,
        );
        let detail_rows =
            Layout::vertical([Constraint::Length(3), Constraint::Min(1)]).split(columns[2]);
        frame.render_widget(
            Tabs::new(["Overview", "Input", "Permissions", "Result"])
                .select(self.tab)
                .style(Style::default().fg(MUTED))
                .highlight_style(Style::default().fg(ACCENT))
                .block(panel(" Inspect · Tab ")),
            detail_rows[0],
        );
        frame.render_widget(
            Paragraph::new(self.detail())
                .wrap(Wrap { trim: false })
                .scroll((self.scroll, 0))
                .block(panel(" Operation details ")),
            detail_rows[1],
        );
        let product = self
            .product
            .checked_sub(1)
            .map(|index| self.products[index])
            .unwrap_or("all");
        frame.render_widget(
            Paragraph::new(vec![
                Line::from(Span::styled(
                    " ? help   q quit   / search   ↑↓ browse   Tab details   r run   n/b pages",
                    Style::default().fg(MUTED),
                )),
                Line::from(Span::styled(
                    format!(
                        " Catalog inspection  ·  product: {}  ·  service: {}  ·  preview: {}",
                        safe_text(product),
                        safe_text(
                            self.service
                                .checked_sub(1)
                                .map(|index| self.services[index])
                                .unwrap_or("all")
                        ),
                        if self.preview { "enabled" } else { "off" }
                    ),
                    Style::default().fg(ACCENT),
                )),
            ]),
            rows[3],
        );
        if self.help {
            let width = area.width.min(68);
            let height = area.height.min(17);
            let popup = Rect::new(
                area.x + (area.width - width) / 2,
                area.y + (area.height - height) / 2,
                width,
                height,
            );
            frame.render_widget(Clear, popup);
            frame.render_widget(
                Paragraph::new(concat!(
                    " /                 Search catalog\n",
                    " Enter / Esc       Finish typing search\n",
                    " x                 Clear search\n",
                    " ↑ / ↓ or k / j    Browse operations\n",
                    " Home / End        First / last result\n",
                    " n / b             Next / previous catalog page\n",
                    " [ / ]             Previous / next product\n",
                    " { / }             Previous / next service\n",
                    " Tab / Shift+Tab   Cycle detail tabs\n",
                    " PageUp / PageDown Scroll details\n",
                    " p                 Toggle preview operations\n",
                    " r                 Run selected operation (read-only)\n",
                    " ? / Enter / Esc   Close help\n",
                    " q / Ctrl+C        Quit"
                ))
                .block(panel(" Keyboard help ")),
                popup,
            );
        }
    }
}
fn panel(title: &str) -> Block<'_> {
    Block::bordered()
        .title(title)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::Rgb(49, 65, 83)))
        .style(Style::default().bg(PANEL).fg(TEXT))
}
fn safe_text(text: &str) -> String {
    text.chars()
        .filter(|character| !character.is_control() || *character == '\n')
        .filter(
            |character| !matches!(*character, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'),
        )
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use junction_core::RegistryManifest;
    use ratatui::{Terminal, backend::TestBackend};
    fn registry() -> Registry {
        let operation = |id: &str, product: &str, maturity: &str| {
            serde_json::json!({
                "id":id,"product":product,"service":"users","resource":"users","operation":"list",
                "description":"List users safely","method":"GET","base_url":"https://graph.microsoft.com",
                "path":"/users","api_version":"v1.0","parameters":[],"request_body":null,
                "responses":{},"security":[],"risk":"read_only","preview":false,"maturity":maturity,
                "source":{"id":"official","upstream":"https://example.invalid","operation_id":"Users_List"}
            })
        };
        Registry::load(
            serde_json::from_value::<RegistryManifest>(serde_json::json!({
                "format_version":1,"schemas":{},"operations":[
                    operation("graph.users.list", "graph", "stable"),
                    operation("azure.users.list", "azure", "preview")
                ]
            }))
            .unwrap(),
        )
        .unwrap()
    }
    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }
    #[test]
    fn run_key_edits_json_and_shows_runner_results() {
        let registry = registry();
        let mut app = App::new(&registry, false).unwrap();
        // Without a runner the result tab explains how to enable running.
        app.key(key(KeyCode::Char('r'))).unwrap();
        assert!(app.input_editing);
        app.key(key(KeyCode::Enter)).unwrap();
        assert_eq!(app.tab, 3);
        assert!(app.result.as_deref().unwrap().contains("--context"));
        let calls = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let seen = calls.clone();
        app.runner = Some(Box::new(move |operation, input| {
            seen.borrow_mut()
                .push((operation.id.clone(), input.clone()));
            Ok(serde_json::json!({"status":200,"echo":input}))
        }));
        app.key(key(KeyCode::Char('r'))).unwrap();
        for _ in 0..2 {
            app.key(key(KeyCode::Backspace)).unwrap();
        }
        for character in "{\"parameters\":{}}".chars() {
            app.key(key(KeyCode::Char(character))).unwrap();
        }
        // While editing input, q types instead of quitting.
        app.key(key(KeyCode::Enter)).unwrap();
        assert_eq!(calls.borrow().len(), 1);
        assert_eq!(calls.borrow()[0].1, serde_json::json!({"parameters":{}}));
        assert!(app.result.as_deref().unwrap().contains("\"status\": 200"));
        app.key(key(KeyCode::Char('r'))).unwrap();
        app.key(key(KeyCode::Char('x'))).unwrap();
        app.key(key(KeyCode::Enter)).unwrap();
        assert_eq!(app.result.as_deref(), Some("Input is not valid JSON."));
        let mut terminal = Terminal::new(TestBackend::new(120, 30)).unwrap();
        terminal.draw(|frame| app.draw(frame)).unwrap();
    }
    #[test]
    fn keyboard_help_is_modal_and_fits_supported_terminals() {
        let registry = registry();
        let mut app = App::new(&registry, false).unwrap();
        app.key(key(KeyCode::Char('?'))).unwrap();
        for code in [KeyCode::Char('p'), KeyCode::Char(']'), KeyCode::Down] {
            assert!(!app.key(key(code)).unwrap());
        }
        assert!(!app.preview);
        assert_eq!(app.product, 0);
        assert_eq!(app.selection.selected(), Some(0));
        for (width, height) in [(140, 36), (80, 24), (70, 16)] {
            let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
            terminal.draw(|frame| app.draw(frame)).unwrap();
            let text: String = terminal
                .backend()
                .buffer()
                .content
                .iter()
                .map(|cell| cell.symbol())
                .collect();
            assert!(text.contains("Keyboard help"));
            assert!(text.contains("Toggle preview operations"));
            assert!(text.contains("Quit"));
        }
        assert!(!app.key(key(KeyCode::Esc)).unwrap());
        assert!(!app.help);
        app.key(key(KeyCode::Char('/'))).unwrap();
        app.key(key(KeyCode::Char('?'))).unwrap();
        assert_eq!(app.query, "?");
        assert!(!app.help);
    }
    #[test]
    fn navigation_search_and_preview_gate_share_registry_rules() {
        let registry = registry();
        let mut app = App::new(&registry, false).unwrap();
        assert_eq!(app.matches.len(), 1);
        app.key(key(KeyCode::Char('p'))).unwrap();
        assert_eq!(app.matches.len(), 2);
        app.key(key(KeyCode::End)).unwrap();
        assert_eq!(app.selection.selected(), Some(1));
        app.key(key(KeyCode::Char('/'))).unwrap();
        for character in "no-such-operation".chars() {
            app.key(key(KeyCode::Char(character))).unwrap();
        }
        assert!(app.matches.is_empty());
        assert_eq!(app.selection.selected(), None);
        // q is a search character while editing, rather than a quit command.
        assert!(!app.key(key(KeyCode::Char('q'))).unwrap());
        app.key(key(KeyCode::Esc)).unwrap();
        app.key(key(KeyCode::Char('x'))).unwrap();
        assert_eq!(app.matches.len(), 2);
        app.key(key(KeyCode::Char('p'))).unwrap();
        assert_eq!(app.matches.len(), 1);
        assert!(app.key(key(KeyCode::Char('q'))).unwrap());
    }
    #[test]
    fn responsive_render_and_detail_tabs_work_without_a_terminal() {
        let registry = registry();
        let mut app = App::new(&registry, false).unwrap();
        for (width, height) in [(140, 36), (80, 24), (40, 8), (1, 1)] {
            let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
            terminal.draw(|frame| app.draw(frame)).unwrap();
            if width >= 70 {
                let text: String = terminal
                    .backend()
                    .buffer()
                    .content
                    .iter()
                    .map(|cell| cell.symbol())
                    .collect();
                assert!(text.contains("JUNCTION"));
                assert!(text.contains("Overview"));
                assert!(text.contains("graph.users.list"));
            }
        }
        app.key(key(KeyCode::Tab)).unwrap();
        assert!(app.detail().contains("properties"));
        app.key(key(KeyCode::Tab)).unwrap();
        assert!(app.detail().contains("metadata_status"));
        app.key(key(KeyCode::PageDown)).unwrap();
        assert_eq!(app.scroll, 10);
        app.key(key(KeyCode::Tab)).unwrap();
        assert_eq!(app.scroll, 0);
    }
    #[test]
    fn long_ascii_and_wide_search_queries_keep_the_tail_and_cursor_visible() {
        let registry = registry();
        let mut app = App::new(&registry, false).unwrap();
        app.editing = true;
        for prefix in ["x".repeat(200), "界".repeat(100)] {
            app.query = format!("{prefix}endmarker");
            app.refresh().unwrap();
            let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
            terminal.draw(|frame| app.draw(frame)).unwrap();
            let row: String = (1..79)
                .map(|x| terminal.backend().buffer()[(x, 4)].symbol())
                .collect();
            assert!(row.contains("endmarker"));
            let cursor = terminal.get_cursor_position().unwrap();
            assert!(cursor.x < 79 && cursor.x > 1);
            assert_eq!(cursor.y, 4);
            app.key(key(KeyCode::Backspace)).unwrap();
            assert!(app.query.ends_with("endmarke"));
        }
    }
    #[test]
    fn service_filters_apply_to_listing_search_and_reset_after_product_change() {
        let source = registry();
        let original = source.resolve("graph.users.list", None, false).unwrap();
        let mut groups = original.clone();
        groups.id = "graph.groups.list".into();
        groups.service = "groups".into();
        let mut compute = original.clone();
        compute.id = "azure.compute.list".into();
        compute.product = "azure".into();
        compute.service = "compute".into();
        let registry = Registry::load(RegistryManifest {
            format_version: 1,
            operations: vec![original.clone(), groups, compute],
            schemas: serde_json::json!({}),
        })
        .unwrap();
        let mut app = App::new(&registry, false).unwrap();
        assert_eq!(app.services, ["compute", "groups", "users"]);
        app.key(key(KeyCode::Char('}'))).unwrap();
        assert_eq!(app.matches.len(), 1);
        assert_eq!(app.matches[0].product, "azure");
        app.key(key(KeyCode::Char('}'))).unwrap();
        assert_eq!(app.matches[0].id, "graph.groups.list");
        app.query = "list".into();
        app.refresh().unwrap();
        assert_eq!(app.matches.len(), 1);
        assert_eq!(app.matches[0].service, "groups");
        app.key(key(KeyCode::Char(']'))).unwrap();
        assert_eq!(app.service, 0);
        assert_eq!(app.services, ["compute"]);
        assert!(
            app.matches
                .iter()
                .all(|operation| operation.product == "azure")
        );
        app.key(key(KeyCode::Char('{'))).unwrap();
        assert_eq!(app.service, 1);
        assert_eq!(app.matches.len(), 1);
    }
    #[test]
    fn catalog_pages_reach_every_operation_and_filters_reset_position() {
        let source = registry();
        let original = source.resolve("graph.users.list", None, false).unwrap();
        let operations = (0..205)
            .map(|index| {
                let mut operation = original.clone();
                operation.id = format!("graph.users.item_{index:03}");
                operation
            })
            .collect();
        let registry = Registry::load(RegistryManifest {
            format_version: 1,
            operations,
            schemas: serde_json::json!({}),
        })
        .unwrap();
        let mut app = App::new(&registry, false).unwrap();
        let mut ids = Vec::new();
        for expected_size in [100, 100, 5] {
            assert_eq!(app.matches.len(), expected_size);
            ids.extend(app.matches.iter().map(|operation| operation.id.clone()));
            app.key(key(KeyCode::Char('n'))).unwrap();
        }
        assert_eq!(ids.len(), 205);
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), 205);
        assert_eq!(app.offset, 200);
        assert_eq!(app.next, None);
        app.key(key(KeyCode::Char('b'))).unwrap();
        assert_eq!(app.offset, 100);
        app.key(key(KeyCode::Char(']'))).unwrap();
        assert_eq!(app.offset, 0);
        app.key(key(KeyCode::Char('/'))).unwrap();
        for character in "item_204".chars() {
            app.key(key(KeyCode::Char(character))).unwrap();
        }
        assert_eq!(app.matches.len(), 1);
        assert_eq!(app.matches[0].id, "graph.users.item_204");
    }
    #[test]
    fn imported_method_and_version_controls_are_removed_from_rendered_rows() {
        let source = registry();
        let mut operation = source
            .resolve("graph.users.list", None, false)
            .unwrap()
            .clone();
        operation.api_version = Some("v1\u{1b}[2J".into());
        operation.method = "GET\u{7}".into();
        let registry = Registry::load(RegistryManifest {
            format_version: 1,
            operations: vec![operation],
            schemas: serde_json::json!({}),
        })
        .unwrap();
        let mut app = App::new(&registry, false).unwrap();
        let mut terminal = Terminal::new(TestBackend::new(140, 36)).unwrap();
        terminal.draw(|frame| app.draw(frame)).unwrap();
        let text: String = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect();
        assert!(!text.contains('\u{1b}'));
        assert!(!text.contains('\u{7}'));
        assert!(text.contains("GET"));
    }
    #[test]
    fn untrusted_metadata_cannot_inject_terminal_controls() {
        assert_eq!(
            safe_text("hello\u{1b}[2J\u{7}\u{202e}world\n"),
            "hello[2Jworld\n"
        );
    }
}
