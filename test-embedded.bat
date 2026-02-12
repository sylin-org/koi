@echo off
setlocal

REM Run the embedded integration example (supports optional args after --).
cargo run -p koi-embedded --example embedded-integration -- %*

endlocal
