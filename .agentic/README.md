# Agentic Context - Tool-Agnostic AI Rules

This directory contains tool-agnostic context for AI coding assistants (Claude, Cursor, Copilot, etc.).

## Structure

```
.agentic/
├── CONTEXT.md              # Root context (always loaded)
├── README.md               # This file
├── rules/                  # Domain-specific rules (loaded on-demand)
│   ├── http-adapter.md     # HTTP endpoint patterns (Axum)
│   └── mdns-boundary.md    # mdns-sd isolation rules
└── reference/              # Lookup tables (don't reinvent)
    ├── api-endpoints.md    # HTTP + pipe + CLI protocol reference
    └── utilities.md        # Existing constants & types
```

## How It Works

Tool-specific configurations bootstrap from this directory:

| Tool                   | Config File                       |
| ---------------------- | --------------------------------- |
| **GitHub Copilot**     | `.github/copilot-instructions.md` |
| **Claude Code**        | `CLAUDE.md`                       |
| **Cursor**             | `.cursorrules`                    |
| **Windsurf**           | `.windsurfrules`                  |
| **Cline**              | `.clinerules`                     |
| **Aider**              | `CONVENTIONS.md`                  |
| **Cody (Sourcegraph)** | `.sourcegraph/cody.md`            |
| **CodeGPT**            | `.codegpt/instructions.md`        |
| **Amazon Q**           | `.amazonq/rules.md`               |

All bootstrappers point to this `.agentic/` directory as the single source of truth.

## Adding New Rules

Create a new file in `rules/` with frontmatter:

```markdown
---
globs: src/adapters/**/*.rs
alwaysApply: false
---

# Rule Name

[Your rules here]
```

The `globs` pattern helps AI assistants understand when to apply the rules.

## Maintenance

- Keep `CONTEXT.md` concise (<100 lines of actionable rules)
- Add domain-specific rules to `rules/` subdirectory
- Review periodically: if AI already does something correctly, remove the rule

## User-Facing Documentation

User-facing docs live in `docs/` (not here). The structure:

```
docs/
├── guides/       # Tutorials per capability (mentor voice)
├── reference/    # Authoritative specs (precise, code-validated)
├── adr/          # Architecture Decision Records (historical)
├── qa/           # Test plans, validation suites
├── research/     # Investigations (FIDO2, etc.)
├── proposals/    # Open proposals, implemented/ subdirectory
└── archive/      # Retired docs (IMPLEMENTATION.md, TECHNICAL.md, koi-spec.md)
```

When editing docs, follow three voices:

- **Guides**: wise mentor - walk beside the reader, anticipate confusion
- **Reference**: precise technician - exact shapes, validated against code
- **ADRs**: honest historian - context, decision, consequences
