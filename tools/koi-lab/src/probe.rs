use std::process::{Child, Command, Stdio};

use anyhow::{bail, Context, Result};

/// A bounded curl-backed SSE capture used by physical scenarios.
pub(crate) struct SseCapture {
    child: Option<Child>,
    label: String,
}

impl SseCapture {
    pub(crate) fn start(
        url: &str,
        token: Option<&str>,
        timeout_secs: u64,
        label: &str,
    ) -> Result<Self> {
        let mut command = Command::new("curl.exe");
        command.args([
            "--silent",
            "--show-error",
            "--no-buffer",
            "--max-time",
            &timeout_secs.to_string(),
            url,
        ]);
        if let Some(token) = token {
            command.args(["--header", &format!("x-koi-token: {token}")]);
        }
        let child = command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("failed to start {label} SSE capture"))?;
        Ok(Self {
            child: Some(child),
            label: label.to_owned(),
        })
    }

    pub(crate) fn finish(mut self) -> Result<String> {
        self.finish_allowing(&[28])
    }

    /// Finish a stream whose server was deliberately restarted. Curl reports
    /// exit 18 when chunked SSE closes without its terminating chunk.
    pub(crate) fn finish_after_server_restart(mut self) -> Result<String> {
        self.finish_allowing(&[18])
    }

    fn finish_allowing(&mut self, allowed_exit_codes: &[i32]) -> Result<String> {
        let child = self
            .child
            .take()
            .context("SSE capture was already consumed")?;
        let output = child
            .wait_with_output()
            .with_context(|| format!("failed to wait for {} SSE capture", self.label))?;
        if !output.status.success()
            && !output
                .status
                .code()
                .is_some_and(|code| allowed_exit_codes.contains(&code))
        {
            bail!(
                "{} SSE capture failed (exit {}): {}",
                self.label,
                output.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        String::from_utf8(output.stdout)
            .with_context(|| format!("{} SSE capture returned non-UTF-8 data", self.label))
    }
}

impl Drop for SseCapture {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
