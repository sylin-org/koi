//! Generic CLI ceremony render loop.
//!
//! A dumb render loop that drives a [`CeremonyHost`]. The loop:
//!
//! 1. Sends a ceremony request (new or continue).
//! 2. Renders messages (info, QR codes, summaries, errors).
//! 3. Displays prompts and collects user input.
//! 4. Merges input into a new request and repeats.
//! 5. Returns the final `result_data` bag when the ceremony completes.
//!
//! This is the **golden example** of how to consume the ceremony protocol
//! from a terminal client. Every aspect of the user experience - messages,
//! options, validation errors - is driven by the ceremony response.

use koi_common::ceremony::{
    CeremonyHost, CeremonyRequest, CeremonyResponse, CeremonyRules, InputType, Message,
    MessageKind, Prompt, QrFormat, RenderHints,
};

// ── Color helpers (reused from certmesh module) ─────────────────────

mod color {
    use std::io::IsTerminal;

    fn enabled() -> bool {
        static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *ENABLED.get_or_init(|| {
            if std::env::var_os("NO_COLOR").is_some() {
                return false;
            }
            if std::env::var("TERM")
                .map(|t| t.eq_ignore_ascii_case("dumb"))
                .unwrap_or(false)
            {
                return false;
            }
            std::io::stdout().is_terminal()
        })
    }

    fn wrap(code: &str, text: &str) -> String {
        if enabled() {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }

    pub fn cyan(text: &str) -> String {
        wrap("36", text)
    }
    pub fn cyan_bold(text: &str) -> String {
        wrap("1;36", text)
    }
    pub fn green(text: &str) -> String {
        wrap("32", text)
    }
    pub fn yellow(text: &str) -> String {
        wrap("33", text)
    }
    pub fn red(text: &str) -> String {
        wrap("31", text)
    }
    pub fn dim(text: &str) -> String {
        wrap("2", text)
    }
}

// ── Box drawing ─────────────────────────────────────────────────────

fn visible_width(s: &str) -> usize {
    let mut width = 0usize;
    let mut in_escape = false;
    for ch in s.chars() {
        if in_escape {
            if ch == 'm' {
                in_escape = false;
            }
        } else if ch == '\x1b' {
            in_escape = true;
        } else {
            width += 1;
        }
    }
    width
}

fn pad_visible(s: &str, target: usize) -> String {
    let vw = visible_width(s);
    if vw >= target {
        s.to_string()
    } else {
        format!("{}{}", s, " ".repeat(target - vw))
    }
}

fn print_box(indent: &str, title: Option<&str>, lines: &[String]) {
    let max_content = lines.iter().map(|l| visible_width(l)).max().unwrap_or(0);
    let title_width = title.map(|t| visible_width(t) + 6).unwrap_or(0);
    let inner = max_content.max(title_width).max(20) + 2;

    if let Some(t) = title {
        let label = format!("── {t} ");
        let label_vw = visible_width(&label);
        let remaining = if inner + 2 > label_vw {
            inner + 2 - label_vw
        } else {
            1
        };
        println!("{indent}╭{label}{}╮", "─".repeat(remaining));
    } else {
        println!("{indent}╭{}╮", "─".repeat(inner + 2));
    }

    for line in lines {
        let padded = pad_visible(line, inner);
        println!("{indent}│ {padded} │");
    }

    println!("{indent}╰{}╯", "─".repeat(inner + 2));
}

// ── Prompt line ─────────────────────────────────────────────────────

fn prompt_line(prompt: &str) -> anyhow::Result<String> {
    use std::io::Write;
    print!("{prompt}");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(line.trim_end().to_string())
}

// ── Public API ──────────────────────────────────────────────────────

/// Run a ceremony to completion via an in-process [`CeremonyHost`].
///
/// This is the golden-example CLI render loop. The host drives all
/// branching, validation, and content - this function just renders
/// and collects.
///
/// Returns the final bag contents on successful completion.
pub fn run_ceremony<R: CeremonyRules>(
    host: &CeremonyHost<R>,
    ceremony: &str,
    initial_data: serde_json::Map<String, serde_json::Value>,
) -> anyhow::Result<serde_json::Map<String, serde_json::Value>> {
    let render_hints = RenderHints {
        qr: Some(QrFormat::Utf8),
    };

    // First request - start the ceremony
    let request = CeremonyRequest {
        session_id: None,
        ceremony: Some(ceremony.into()),
        data: initial_data,
        render: Some(render_hints.clone()),
    };

    let mut response = host.step(request).map_err(|e| anyhow::anyhow!("{e}"))?;

    loop {
        // Render the response
        render_response(&response)?;

        // Check completion
        if response.complete {
            if let Some(err) = &response.error {
                anyhow::bail!("{err}");
            }
            return Ok(response.result_data.unwrap_or_default());
        }

        // Collect input from prompts
        let data = collect_prompts(&response.prompts)?;

        // Next step
        response = host
            .step(CeremonyRequest {
                session_id: Some(response.session_id),
                ceremony: None,
                data,
                render: Some(render_hints.clone()),
            })
            .map_err(|e| anyhow::anyhow!("{e}"))?;
    }
}

// ── Rendering ───────────────────────────────────────────────────────

fn render_response(response: &CeremonyResponse) -> anyhow::Result<()> {
    // Show error if present
    if let Some(err) = &response.error {
        println!("\n  {} {}", color::red("✗"), err);
    }

    // Render messages
    for msg in &response.messages {
        render_message(msg);
    }

    Ok(())
}

fn render_message(msg: &Message) {
    println!();
    match msg.kind {
        MessageKind::Info => {
            if msg.title.starts_with('⚠') {
                // Warning-style info message
                println!("  {}", color::yellow(&msg.title));
                for line in msg.content.lines() {
                    println!("  {}", color::yellow(line));
                }
            } else {
                println!("  {}", color::dim(&msg.title));
                for line in msg.content.lines() {
                    println!("  {}", color::dim(line));
                }
            }
        }
        MessageKind::QrCode => {
            println!("  {}\n", msg.title);
            // QR content is pre-rendered UTF-8 art or base64 PNG
            if msg.content.contains('█') || msg.content.contains('▄') {
                // UTF-8 QR art - print as-is
                println!("{}", msg.content);
            } else if msg.content.starts_with("otpauth://") {
                // URI-only mode - show the raw URI
                println!("  {}\n", color::cyan_bold(&msg.content));
            } else {
                // Base64 PNG - show as data URI hint
                println!("  {}", color::dim("(QR image available as base64 PNG)"));
            }
        }
        MessageKind::Summary => {
            let mut lines: Vec<String> = Vec::new();
            lines.push(String::new());
            for line in msg.content.lines() {
                lines.push(line.to_string());
            }
            lines.push(String::new());
            print_box("  ", Some(&color::green(&msg.title)), &lines);
        }
        MessageKind::Error => {
            println!("  {} {}", color::red("✗"), color::red(&msg.title));
            for line in msg.content.lines() {
                println!("    {}", color::red(line));
            }
        }
    }
}

// ── Input collection ────────────────────────────────────────────────

fn collect_prompts(
    prompts: &[Prompt],
) -> anyhow::Result<serde_json::Map<String, serde_json::Value>> {
    let mut data = serde_json::Map::new();

    for prompt in prompts {
        let value = collect_single_prompt(prompt)?;
        data.insert(prompt.key.clone(), serde_json::Value::String(value));
    }

    Ok(data)
}

fn collect_single_prompt(prompt: &Prompt) -> anyhow::Result<String> {
    match prompt.input_type {
        InputType::SelectOne => collect_select_one(prompt),
        InputType::Text => collect_text(prompt),
        InputType::Secret => collect_secret(prompt),
        InputType::SecretConfirm => collect_secret_confirm(prompt),
        InputType::Code => collect_code(prompt),
        InputType::Entropy => collect_entropy(prompt),
        InputType::Fido2 => {
            anyhow::bail!("FIDO2 hardware key input is not yet supported in this CLI.");
        }
        InputType::SelectMany => {
            // SelectMany not yet needed; fall back to text
            collect_text(prompt)
        }
    }
}

fn collect_select_one(prompt: &Prompt) -> anyhow::Result<String> {
    println!();
    println!("  {}\n", prompt.prompt);

    for (i, opt) in prompt.options.iter().enumerate() {
        let num = i + 1;
        let default_marker = if num == 1 { " (default)" } else { "" };
        println!(
            "  [{}] {}{}",
            if num == 1 {
                color::cyan(&num.to_string())
            } else {
                num.to_string()
            },
            opt.label,
            color::dim(default_marker)
        );
        if let Some(desc) = &opt.description {
            // Wrap description at ~60 chars
            for line in textwrap_simple(desc, 60) {
                println!("      {}", color::dim(&line));
            }
        }
        println!();
    }

    loop {
        let line = prompt_line(&format!(
            "  Choose [1-{}, {}=1, esc={}]: ",
            prompt.options.len(),
            color::cyan("Enter"),
            color::dim("cancel"),
        ))?;

        let trimmed = line.trim().to_ascii_lowercase();

        if trimmed == "esc" {
            anyhow::bail!("Canceled. No changes made.");
        }

        // Default (Enter)
        if trimmed.is_empty() {
            let value = &prompt.options[0].value;
            println!("  {} {}\n", color::green("✓"), prompt.options[0].label);
            return Ok(value.clone());
        }

        // Numeric selection
        if let Ok(n) = trimmed.parse::<usize>() {
            if n >= 1 && n <= prompt.options.len() {
                let opt = &prompt.options[n - 1];
                println!("  {} {}\n", color::green("✓"), opt.label);
                return Ok(opt.value.clone());
            }
        }

        // Match by value or label
        for opt in &prompt.options {
            if trimmed == opt.value.to_ascii_lowercase()
                || trimmed == opt.label.to_ascii_lowercase()
            {
                println!("  {} {}\n", color::green("✓"), opt.label);
                return Ok(opt.value.clone());
            }
        }

        println!(
            "  {} Pick a number from 1 to {}.",
            color::red("✗"),
            prompt.options.len()
        );
    }
}

fn collect_text(prompt: &Prompt) -> anyhow::Result<String> {
    println!();
    let value = prompt_line(&format!("  {}: ", prompt.prompt))?;
    if value.trim().is_empty() && prompt.required {
        println!("  {} This field is required.", color::red("✗"));
        return collect_text(prompt);
    }
    println!("  {} {}\n", color::green("✓"), prompt.prompt);
    Ok(value.trim().to_string())
}

fn collect_secret(prompt: &Prompt) -> anyhow::Result<String> {
    println!();
    let value = prompt_line(&format!("  {}: ", prompt.prompt))?;
    if value.is_empty() && prompt.required {
        println!("  {} This field is required.", color::red("✗"));
        return collect_secret(prompt);
    }
    println!("  {} {}\n", color::green("✓"), color::dim("Set"));
    Ok(value)
}

fn collect_secret_confirm(prompt: &Prompt) -> anyhow::Result<String> {
    println!();
    let first = prompt_line(&format!("  {}: ", prompt.prompt))?;
    if first.is_empty() && prompt.required {
        println!("  {} This field is required.", color::red("✗"));
        return collect_secret_confirm(prompt);
    }
    let confirm = prompt_line("  Confirm: ")?;
    if first != confirm {
        println!("  {} Values do not match. Try again.", color::red("✗"));
        return collect_secret_confirm(prompt);
    }
    println!("  {} {}\n", color::green("✓"), color::dim("Set"));
    Ok(first)
}

fn collect_code(prompt: &Prompt) -> anyhow::Result<String> {
    println!();
    let code = prompt_line(&format!(
        "  {} ",
        color::cyan(&format!("{}:", prompt.prompt))
    ))?;
    let cleaned = code.trim().replace(' ', "");
    if cleaned.is_empty() {
        println!("  {} Code cannot be empty.", color::red("✗"));
        return collect_code(prompt);
    }
    Ok(cleaned)
}

fn collect_entropy(prompt: &Prompt) -> anyhow::Result<String> {
    println!();
    println!("  {}", prompt.prompt);
    println!(
        "  {}",
        color::dim("Type random characters and press Enter when done:")
    );
    let entropy = prompt_line("  > ")?;
    if entropy.trim().is_empty() {
        // Even empty input is valid - we have server entropy.
        // But let's encourage participation.
        println!("  {} Using server entropy only.", color::dim("→"));
        return Ok("_server_only".to_string());
    }
    println!(
        "  {} Entropy collected ({} bytes)\n",
        color::green("✓"),
        entropy.len()
    );
    Ok(entropy)
}

// ── Text wrapping helper ────────────────────────────────────────────

fn textwrap_simple(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();

    for word in text.split_whitespace() {
        if current.is_empty() {
            current = word.to_string();
        } else if current.len() + 1 + word.len() <= width {
            current.push(' ');
            current.push_str(word);
        } else {
            lines.push(current);
            current = word.to_string();
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }

    if lines.is_empty() {
        lines.push(String::new());
    }

    lines
}
