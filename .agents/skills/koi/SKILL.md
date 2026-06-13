```markdown
# koi Development Patterns

> Auto-generated skill from repository analysis

## Overview

This skill teaches the core development patterns, coding conventions, and maintenance workflows for the `koi` Rust codebase. You'll learn how to structure code, follow commit and file naming conventions, manage dependencies securely, and run or write tests in alignment with the repository's standards.

## Coding Conventions

- **File Naming:**  
  Use PascalCase for files and modules.  
  _Example:_  
  ```
  MyModule.rs
  SomeUtility.rs
  ```

- **Import Style:**  
  Prefer relative imports within the crate.  
  _Example:_  
  ```rust
  use super::MyModule;
  use crate::utils::SomeUtility;
  ```

- **Export Style:**  
  Use named exports for public items.  
  _Example:_  
  ```rust
  pub struct MyStruct { /* ... */ }
  pub fn my_function() { /* ... */ }
  ```

- **Commit Patterns:**  
  Use [Conventional Commits](https://www.conventionalcommits.org/), with prefixes like `fix` and `refactor`.  
  _Example:_  
  ```
  fix: handle edge case in connection pooling
  refactor: extract parsing logic into separate module
  ```

## Workflows

### Dependency Update and Security Audit
**Trigger:** When you need to resolve security advisories or update dependencies for security/maintenance.  
**Command:** `/update-deps-security`

1. **Run Security Audit:**  
   Use `cargo audit` to identify vulnerabilities and unmaintained dependencies.
   ```sh
   cargo audit
   ```
2. **Update Dependencies:**  
   Edit `Cargo.toml` and/or `Cargo.lock` to bump or remove affected dependencies.
   ```sh
   cargo update -p vulnerable-crate
   ```
3. **Refactor if Needed:**  
   If a dependency is deprecated or unmaintained, refactor code to migrate away from it.
   ```rust
   // Replace usage of old_crate with new_crate
   use new_crate::SomeFeature;
   ```
4. **Update CI Configuration:**  
   Adjust `.github/workflows/ci.yml` as needed to reflect new audit status (e.g., add/remove ignores).
5. **Document Changes:**  
   If a significant dependency change is made, add notes in `docs/assessment/*.md`.
6. **Verify Everything:**  
   Run the following to ensure the codebase is clean:
   ```sh
   cargo audit
   cargo build
   cargo clippy --all-targets --all-features -- -D warnings
   cargo fmt -- --check
   cargo test
   ```

**Files Involved:**
- `Cargo.toml`
- `Cargo.lock`
- `.github/workflows/ci.yml`
- `crates/*/Cargo.toml`
- `crates/*/src/**/*.rs`
- `docs/assessment/*.md`

**Frequency:** ~2x/month

## Testing Patterns

- **Test File Pattern:**  
  Test files use the `*.test.*` naming convention.  
  _Example:_  
  ```
  MyModule.test.rs
  ```
- **Framework:**  
  The specific test framework is not detected, but standard Rust testing patterns apply.
  _Example:_  
  ```rust
  #[cfg(test)]
  mod tests {
      use super::*;

      #[test]
      fn test_feature() {
          assert_eq!(my_function(), expected_value);
      }
  }
  ```

## Commands

| Command               | Purpose                                                      |
|-----------------------|--------------------------------------------------------------|
| /update-deps-security | Run the dependency update and security audit workflow         |
```
