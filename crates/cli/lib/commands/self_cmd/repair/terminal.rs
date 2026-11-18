//! Focused repair prompts that redraw only their own terminal rows.

use std::io;

use console::{Key, Term, measure_text_width, truncate_str};
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, is_raw_mode_enabled};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A sandbox label and provisional inspection result for the repair picker.
pub(super) struct Target {
    pub name: String,
    pub status: String,
    pub ready: bool,
}

/// Owns the temporary command area, without switching screens or clearing terminal history.
pub(super) struct Screen {
    term: Term,
    lines: usize,
}

struct InputGuard {
    term: Term,
    restore_mode: bool,
}

struct Picker {
    selected: Vec<bool>,
    visible: Vec<usize>,
    cursor: usize,
    show_ready: bool,
}

#[derive(Debug, PartialEq)]
enum Navigation {
    Continue,
    Accept,
    Cancel,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Screen {
    pub(super) fn new() -> io::Result<Self> {
        let term = Term::stderr();
        if !term.is_term() {
            return Err(io::Error::other("interactive repair requires a terminal"));
        }
        Ok(Self { term, lines: 0 })
    }

    /// Select any number of the explicitly inventoried sandboxes. Ready entries start hidden.
    pub(super) fn choose_targets(&mut self, targets: &[Target]) -> io::Result<Option<Vec<usize>>> {
        let _input = InputGuard::acquire(&self.term)?;
        let mut picker = Picker::new(targets);
        loop {
            let (height, width) = self.dimensions()?;
            let lines = picker.frame(targets, height, width);
            self.draw(&lines)?;
            match picker.navigate(self.read_key()?, targets) {
                Navigation::Continue => {}
                Navigation::Cancel => {
                    self.clear()?;
                    return Ok(None);
                }
                Navigation::Accept => {
                    self.clear()?;
                    return Ok(Some(picker.selection()));
                }
            }
        }
    }

    /// Ask for one consequential action. Enter defaults to refusal; only explicit consent accepts.
    pub(super) fn confirm_choice(
        &mut self,
        title: &str,
        context: &[String],
        question: &str,
    ) -> io::Result<Option<bool>> {
        let mut context = context.to_vec();
        context.push(String::new());
        context.push(question.to_owned());
        Ok(self
            .menu(title, &context, &["Yes", "No"], 1, true)?
            .map(|choice| choice == 0))
    }

    /// Display a focused decision. Escape and Ctrl-C return to the caller without selecting.
    pub(super) fn choose_action(
        &mut self,
        title: &str,
        context: &[String],
        choices: &[&str],
    ) -> io::Result<Option<usize>> {
        self.menu(title, context, choices, 0, false)
    }

    /// Clear before code that may print independently, so later redraws never erase its output.
    pub(super) fn clear(&mut self) -> io::Result<()> {
        // Each written line is shorter than the terminal width. After a resize, erase at
        // most the known rows still on screen; never guess at reflow into previous history.
        let available = usize::from(self.term.size().0).saturating_sub(1);
        let lines = self.lines.min(available);
        self.lines = 0;
        self.term.clear_last_lines(lines)
    }

    /// Leave the cursor and command area ready for the caller's persistent final summary.
    pub(super) fn finish(&mut self) -> io::Result<()> {
        let result = self.clear();
        let cursor = self.term.show_cursor();
        result.and(cursor)
    }

    fn menu(
        &mut self,
        title: &str,
        context: &[String],
        choices: &[&str],
        mut cursor: usize,
        confirmation: bool,
    ) -> io::Result<Option<usize>> {
        if choices.is_empty() {
            return Err(io::Error::other("interactive repair menu has no actions"));
        }
        let _input = InputGuard::acquire(&self.term)?;
        let mut offset = 0;
        loop {
            let (height, width) = self.dimensions()?;
            let (lines, last_offset) =
                menu_frame(title, context, choices, cursor, offset, (height, width));
            offset = offset.min(last_offset);
            self.draw(&lines)?;
            let key = self.read_key()?;
            let action = match key {
                Key::PageUp => {
                    offset = offset.saturating_sub(1);
                    Navigation::Continue
                }
                Key::PageDown => {
                    offset = (offset + 1).min(last_offset);
                    Navigation::Continue
                }
                _ => navigate_menu(&key, &mut cursor, choices.len(), confirmation),
            };
            match action {
                Navigation::Continue => {}
                Navigation::Cancel => {
                    self.clear()?;
                    return Ok(None);
                }
                Navigation::Accept => {
                    self.clear()?;
                    return Ok(Some(cursor));
                }
            }
        }
    }

    fn dimensions(&self) -> io::Result<(usize, usize)> {
        let (rows, columns) = self.term.size();
        if rows < 10 || columns < 30 {
            return Err(io::Error::other(
                "enlarge the terminal to at least 30 columns and 10 rows, then retry repair",
            ));
        }
        // Keep one column and row spare: wrapping/scrolling would make row ownership ambiguous.
        Ok((usize::from(rows) - 1, usize::from(columns) - 1))
    }

    fn draw(&mut self, lines: &[String]) -> io::Result<()> {
        self.clear()?;
        for line in lines {
            // Raw input mode also disables newline translation on Unix. An explicit CR
            // keeps the frame in column zero on both Unix terminals and Windows consoles.
            self.term.write_line(&format!("{line}\r"))?;
            self.lines += 1;
        }
        self.term.flush()
    }

    fn read_key(&self) -> io::Result<Key> {
        loop {
            match event::read()? {
                Event::Key(key) if key.kind != KeyEventKind::Release => {
                    return Ok(match key.code {
                        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            Key::CtrlC
                        }
                        KeyCode::Char(character) => Key::Char(character),
                        KeyCode::Up => Key::ArrowUp,
                        KeyCode::Down => Key::ArrowDown,
                        KeyCode::PageUp => Key::PageUp,
                        KeyCode::PageDown => Key::PageDown,
                        KeyCode::Enter => Key::Enter,
                        KeyCode::Esc => Key::Escape,
                        _ => Key::Unknown,
                    });
                }
                Event::Resize(..) => return Ok(Key::Unknown),
                _ => {}
            }
        }
    }
}

impl InputGuard {
    fn acquire(term: &Term) -> io::Result<Self> {
        let restore_mode = !is_raw_mode_enabled()?;
        if restore_mode {
            enable_raw_mode()?;
        }
        let guard = Self {
            term: term.clone(),
            restore_mode,
        };
        guard.term.hide_cursor()?;
        // Keep raw mode for the entire decision, including redraws. Toggling it around
        // individual reads lets fast input echo newlines and invalidate owned-row counts.
        Ok(guard)
    }
}

impl Picker {
    fn new(targets: &[Target]) -> Self {
        Self {
            selected: vec![false; targets.len()],
            visible: targets
                .iter()
                .enumerate()
                .filter_map(|(i, t)| (!t.ready).then_some(i))
                .collect(),
            cursor: 0,
            show_ready: false,
        }
    }

    fn selection(&self) -> Vec<usize> {
        self.visible
            .iter()
            .copied()
            .filter(|&i| self.selected[i])
            .collect()
    }

    fn navigate(&mut self, key: Key, targets: &[Target]) -> Navigation {
        match key {
            Key::ArrowUp | Key::Char('k') => self.cursor = self.cursor.saturating_sub(1),
            Key::ArrowDown | Key::Char('j') => {
                self.cursor = (self.cursor + 1).min(self.visible.len())
            }
            Key::Char(' ') if self.cursor == 0 => {
                let select = !self.visible.iter().all(|&i| self.selected[i]);
                for &i in &self.visible {
                    self.selected[i] = select;
                }
            }
            Key::Char(' ') => self.selected[self.visible[self.cursor - 1]] ^= true,
            Key::Char('r') | Key::Char('R') => {
                self.show_ready = !self.show_ready;
                self.visible = targets
                    .iter()
                    .enumerate()
                    .filter_map(|(i, target)| {
                        if self.show_ready || !target.ready {
                            Some(i)
                        } else {
                            // Hidden selections must not be silently submitted as part of a batch.
                            self.selected[i] = false;
                            None
                        }
                    })
                    .collect();
                self.cursor = 0;
            }
            Key::Enter => return Navigation::Accept,
            Key::Escape | Key::CtrlC => return Navigation::Cancel,
            _ => {}
        }
        Navigation::Continue
    }

    fn frame(&self, targets: &[Target], height: usize, width: usize) -> Vec<String> {
        let count = self.visible.len() + 1;
        let capacity = height.saturating_sub(5).max(1);
        let start = window_start(self.cursor, count, capacity);
        let mut lines = vec!["Choose sandboxes to repair".into(), String::new()];
        for position in start..(start + capacity).min(count) {
            let checked = if position == 0 {
                !self.visible.is_empty() && self.visible.iter().all(|&i| self.selected[i])
            } else {
                self.selected[self.visible[position - 1]]
            };
            let label = if position == 0 {
                "All listed".to_owned()
            } else {
                let target = &targets[self.visible[position - 1]];
                format!("{} — {}", target.name, target.status)
            };
            let pointer = if position == self.cursor { '>' } else { ' ' };
            let mark = if checked { 'x' } else { ' ' };
            lines.push(safe_line(&format!("  {pointer} [{mark}] {label}"), width));
        }
        let ready = targets.iter().filter(|target| target.ready).count();
        let visibility = if self.show_ready { "hide" } else { "show" };
        lines.push(safe_line(
            &format!(
                "{} selected · r {visibility} {ready} ready · {} listed",
                self.selection().len(),
                self.visible.len()
            ),
            width,
        ));
        lines.push(String::new());
        lines.push(safe_line(
            "↑↓ navigate · space select · enter confirm · esc cancel",
            width,
        ));
        lines
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Drop for Screen {
    fn drop(&mut self) {
        let _ = self.finish();
    }
}

impl Drop for InputGuard {
    fn drop(&mut self) {
        let _ = self.term.show_cursor();
        if self.restore_mode {
            let _ = disable_raw_mode();
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn navigate_menu(key: &Key, cursor: &mut usize, count: usize, confirmation: bool) -> Navigation {
    match key {
        Key::ArrowUp | Key::Char('k') => *cursor = cursor.saturating_sub(1),
        Key::ArrowDown | Key::Char('j') => *cursor = (*cursor + 1).min(count - 1),
        Key::Char('y') | Key::Char('Y') if confirmation => {
            *cursor = 0;
            return Navigation::Accept;
        }
        Key::Char('n') | Key::Char('N') if confirmation => {
            // Refusing this action may still permit independent repairs in the batch.
            // Only Escape/Ctrl-C cancels the remaining interaction.
            *cursor = 1;
            return Navigation::Accept;
        }
        Key::Enter => return Navigation::Accept,
        Key::Escape | Key::CtrlC => return Navigation::Cancel,
        _ => {}
    }
    Navigation::Continue
}

fn menu_frame(
    title: &str,
    context: &[String],
    choices: &[&str],
    cursor: usize,
    offset: usize,
    (height, width): (usize, usize),
) -> (Vec<String>, usize) {
    let body = wrapped_lines(context, width);
    let choice_rows = choices.len().min((height.saturating_sub(6) / 2).max(1));
    let body_rows = height.saturating_sub(5 + choice_rows).max(1);
    let last_offset = body.len().saturating_sub(body_rows);
    let offset = offset.min(last_offset);
    let mut lines = vec![safe_line(title, width), String::new()];
    lines.extend(body.into_iter().skip(offset).take(body_rows));
    lines.push(String::new());
    let start = window_start(cursor, choices.len(), choice_rows);
    for (index, choice) in choices.iter().enumerate().skip(start).take(choice_rows) {
        lines.push(safe_line(
            &format!("  {} {choice}", if index == cursor { ">" } else { " " }),
            width,
        ));
    }
    lines.push(String::new());
    let help = if last_offset == 0 {
        "↑↓ navigate · enter select · esc back".to_owned()
    } else {
        format!(
            "↑↓ choose · pgup/pgdn details {}/{} · enter select · esc back",
            offset + 1,
            last_offset + 1
        )
    };
    lines.push(safe_line(&help, width));
    (lines, last_offset)
}

fn window_start(cursor: usize, count: usize, capacity: usize) -> usize {
    cursor
        .saturating_sub(capacity - 1)
        .min(count.saturating_sub(capacity))
}

fn safe_line(line: &str, width: usize) -> String {
    let escaped = escaped_text(line);
    truncate_str(&escaped, width, "…").into_owned()
}

fn escaped_text(text: &str) -> String {
    let mut escaped = String::new();
    for character in text.chars() {
        // Quotes are ordinary terminal text, while control and formatting characters
        // must remain visible rather than changing the screen or impersonating prompts.
        if matches!(character, '\'' | '"') {
            escaped.push(character);
        } else {
            escaped.extend(character.escape_debug());
        }
    }
    escaped
}

fn wrapped_lines(lines: &[String], width: usize) -> Vec<String> {
    let mut wrapped = Vec::new();
    for line in lines {
        let escaped = escaped_text(line);
        let mut part = String::new();
        let mut used = 0;
        for character in escaped.chars() {
            let size = measure_text_width(&character.to_string());
            if used + size > width && !part.is_empty() {
                wrapped.push(std::mem::take(&mut part));
                used = 0;
            }
            part.push(character);
            used += size;
        }
        wrapped.push(part);
    }
    wrapped
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn targets() -> Vec<Target> {
        vec![
            Target {
                name: "app".into(),
                status: "repairable".into(),
                ready: false,
            },
            Target {
                name: "ready".into(),
                status: "ready".into(),
                ready: true,
            },
            Target {
                name: "unknown".into(),
                status: "needs investigation".into(),
                ready: false,
            },
        ]
    }

    #[test]
    fn all_listed_never_selects_hidden_ready_sandboxes() {
        let targets = targets();
        let mut picker = Picker::new(&targets);
        picker.navigate(Key::Char(' '), &targets);
        assert_eq!(picker.selection(), vec![0, 2]);

        picker.navigate(Key::Char('r'), &targets);
        assert_eq!(picker.selection(), vec![0, 2]);
        picker.navigate(Key::Char(' '), &targets);
        assert_eq!(picker.selection(), vec![0, 1, 2]);

        picker.navigate(Key::Char('r'), &targets);
        picker.navigate(Key::Char('r'), &targets);
        assert_eq!(picker.selection(), vec![0, 2]);
    }

    #[test]
    fn picker_keeps_unknown_entries_and_all_tracks_individual_toggles() {
        let targets = targets();
        let mut picker = Picker::new(&targets);
        picker.navigate(Key::ArrowDown, &targets);
        picker.navigate(Key::Char(' '), &targets);
        picker.navigate(Key::ArrowDown, &targets);
        picker.navigate(Key::Char(' '), &targets);
        assert_eq!(picker.selection(), vec![0, 2]);
        assert!(
            picker
                .frame(&targets, 20, 80)
                .iter()
                .any(|line| line.contains("[x] All listed"))
        );

        picker.navigate(Key::Char(' '), &targets);
        assert_eq!(picker.selection(), vec![0]);
        assert!(
            picker
                .frame(&targets, 20, 80)
                .iter()
                .any(|line| line.contains("[ ] All listed"))
        );
        assert_eq!(picker.navigate(Key::Escape, &targets), Navigation::Cancel);
    }

    #[test]
    fn consent_defaults_to_no_and_ctrl_c_returns_without_accepting() {
        let mut cursor = 1;
        assert_eq!(
            navigate_menu(&Key::Enter, &mut cursor, 2, true),
            Navigation::Accept
        );
        assert_eq!(cursor, 1);
        assert_eq!(
            navigate_menu(&Key::CtrlC, &mut cursor, 2, true),
            Navigation::Cancel
        );
        assert_eq!(
            navigate_menu(&Key::Char('y'), &mut cursor, 2, true),
            Navigation::Accept
        );
        assert_eq!(cursor, 0);
        assert_eq!(
            navigate_menu(&Key::Char('n'), &mut cursor, 2, true),
            Navigation::Accept
        );
        assert_eq!(cursor, 1);
        assert_eq!(
            navigate_menu(&Key::Escape, &mut cursor, 2, true),
            Navigation::Cancel
        );
    }

    #[test]
    fn frames_fit_owned_area_and_escape_control_sequences() {
        let context = vec!["warning\x1b[2J\r\n".repeat(12), "safe consequence".into()];
        let (lines, last) = menu_frame("repair", &context, &["yes", "no"], 1, 0, (9, 29));
        assert!(last > 0);
        assert!(lines.len() <= 9);
        assert!(lines.iter().all(|line| measure_text_width(line) <= 29));
        assert!(
            lines
                .iter()
                .all(|line| !line.contains(['\x1b', '\r', '\n']))
        );

        let (last_page, _) = menu_frame("repair", &context, &["yes", "no"], 1, usize::MAX, (9, 29));
        assert!(last_page.iter().any(|line| line == "safe consequence"));
        assert!(last_page.iter().any(|line| line == "  > no"));
        assert_eq!(
            safe_line("Couldn't repair 'app'.", 80),
            "Couldn't repair 'app'."
        );
    }

    #[test]
    fn picker_scrolls_without_exceeding_the_command_area() {
        let targets: Vec<_> = (0..100)
            .map(|i| Target {
                name: format!("app-{i}"),
                status: "repairable".into(),
                ready: false,
            })
            .collect();
        let mut picker = Picker::new(&targets);
        for _ in 0..100 {
            picker.navigate(Key::ArrowDown, &targets);
        }
        let frame = picker.frame(&targets, 9, 29);
        assert!(frame.len() <= 9);
        assert!(frame.iter().any(|line| line.contains("app-99")));
        assert!(frame.iter().all(|line| measure_text_width(line) <= 29));
    }
}
