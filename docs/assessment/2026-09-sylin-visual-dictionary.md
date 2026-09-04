# Koi visual dictionary from the Sylin source

Date: 2026-09-04. This note derives Koi's interface language from the current
Ghostlight and Koi desktop stylesheets. It replaces screenshot imitation as the
design reference for the proposed Koi 1.0 surface.

## Source finding

The family language already exists in code. Ghostlight defines it in
`browser-mcp/crates/orchestrator/ui/styles.css`. Koi desktop carries that base in
`koi-desktop/ui/styles.css`, then changes the project accent and adds Koi-specific
views. The Koi stylesheet says this explicitly: its blue accent is the intended
delta from Ghostlight's teal and the preceding rules are the family system.

At the reviewed snapshot, Ghostlight's stylesheet is 744 lines and Koi's is 937.
The diff is 202 additions and 9 removals. The shared base differs in three visible
ways before Koi's feature rules begin:

- Ghostlight uses teal (`#5eead4`); Koi uses blue (`#60a5fa`, light
  `#93c5fd`).
- Koi omits one Ghostlight-only page-heading action helper.
- Koi corrects the mascot sizes for the shipped 100 by 100 pixel sprite.

The rest of the difference is mostly Koi-specific presentation for discovery,
DNS, status, browser rows, trust, and capability views. This means the next Koi
surface should reuse the source dictionary directly. It does not need a new
look inspired by Ghostlight screenshots.

## Foundations

| Source token | Current value | Meaning in the family |
|---|---:|---|
| `--bg` | `#0f0e12` | Night-garden ground |
| `--bg-2` | `#0d0c10` | Deeper ground |
| `--ink` | `#f4f4f5` | Primary text and decisive labels |
| `--ink-2` | `#c9c9d1` | Ordinary readable text |
| `--ink-3` | `#a1a1aa` | Supporting text |
| `--muted` | `#71717a` | Metadata and secondary explanation |
| `--faint` | `#52525b` | Inactive or low-priority instrumentation |
| `--line` | white at 6% | Quiet boundaries and row dividers |
| `--line-2` | white at 10% | Stronger interactive boundaries |
| `--panel` | white at 2.2% | Hovered or slightly raised wash |
| `--panel-2` | white at 1.2% | Resting surface wash |
| `--a` | `#60a5fa` in Koi | Koi acting, selected, or owned |
| `--al` | `#93c5fd` in Koi | Light Koi accent for readable emphasis |
| `--argb` | `96, 165, 250` in Koi | Alpha-composed Koi glow |
| `--ok` | `#4ade80` | A positive fact established by evidence |
| `--amber` / `--held` | `#fbbf24` | Waiting, held, or attention-worthy state |
| `--danger` | `#f87171` | Failure, refusal, or destructive action |
| `--mono` | Cascadia / JetBrains / system monospace | Machine facts, counts, addresses, and compact labels |
| `--sans` | Segoe UI / system sans | Human language and controls |

These colors carry meaning. Blue should not decorate every service. Green must
mean Koi has evidence of a good state. A service being announced is not enough
evidence for green reachability, and certmesh membership is not enough evidence
for green HTTPS validation.

## Shape and spacing vocabulary

| Source component | Source geometry | Koi use |
|---|---|---|
| `lampband` | 58 px persistent band, 16 px horizontal padding, 18 px gaps | Global state, concise facts, Home/Devices/Settings/About, and the one applicable global action |
| `lamp` | 38 px field with an 11 px illuminated core | Background service state; it may breathe only while work is genuinely ongoing |
| `tabs` / `tab` | 30 px high, 13 px horizontal padding, 7 px radius | The four top-menu modules; quiet wash for the active module |
| `view` | maximum width 1180 px | Shared readable content measure |
| `kicker` | 9 px mono, 0.18 em tracking, uppercase | A small orientation cue, used sparingly |
| `page-heading` | 25 px light heading, 12.5 px muted explanation | One direct question or promise per destination |
| `row` | 42 px high, hairline bottom edge, 3 px semantic left edge | Dense repeatable services, devices, and events |
| `med-mini` | 22 px field with a 15 px line icon | Compact row identity or condition |
| `tile` | 15-16 px padding, 11 px radius, faint wash | A small set of peer choices or setup targets |
| `card` | 16 px padding, 11 px radius, faint wash | Explanations and grouped state that need more room than a row |
| `strip` | 16 px padding, 11 px radius, 22 px separation | One useful prompt spanning the view, such as a detected local service |
| `ghost-button` | 30 px high, quiet 10% edge | Ordinary secondary action |
| `primary-button` | 30 px high, blue edge and wash | The single next action in a focused workflow |
| `danger-button` | 30 px high, red edge and wash | Reversible stop/remove action after its scope is clear |
| `toast` | Bottom-right, 9 px radius, readable opaque ground | Short confirmation or problem after an action |
| `dialog` | Centered, bounded, blurred neutral backdrop | A decision that must interrupt the current flow |
| `about` | Flexible card plus copy, 42 px gap | Product identity and useful product facts |
| `tcg` | 300 by 478 px, 18 px radius | The original Koi mascot card, intact and first-class on About |

Rows are the family default for a changing catalog. Tiles are useful when a
person is choosing among a small number of setup options. The trading card is a
signature object, not a template for every service.

## Motion vocabulary

The source already names motion by meaning:

| Token | Duration | Use |
|---|---:|---|
| `--beat-glance` | 150 ms | Tiny response and stagger unit |
| `--beat-arrive` | 320 ms | A view or confirmation appearing |
| `--beat-settle` | 420 ms | A row or object landing in place |
| `--beat-wait` | 1050 ms | A real waiting state |
| `--beat-key` | 1150 ms | Keyboard signature |
| `--beat-particle` | 1300 ms | Workwheel particles |
| `--beat-scan` | 1450 ms | Read scan |
| `--beat-capture` | 1500 ms | Capture signature |
| `--beat-wheel` | 2400 ms | Workwheel rotation |
| `--beat-breathe` | 4000 ms | State whose scope remains active |

Koi should retain the shared spring (`cubic-bezier(.22,1,.36,1)`) and calm curve
(`cubic-bezier(.4,0,.2,1)`). Motion confirms a transition or communicates real
ongoing state. It should not make an idle network look busy. Reduced-motion
handling is part of the component, including the card foil and halo.

## Product-language mapping

The source gives Koi a visual vocabulary. The proposed product model supplies
the nouns and actions shown with it.

| User meaning | Visual treatment | Plain language |
|---|---|---|
| Koi is participating normally | Blue lamp, neutral band text | Connected |
| A service can be used from here | Neutral row, evidence-backed condition, direct action | Responding; Open |
| A service was observed but not checked | Neutral row, muted condition | Found on the network |
| An application is becoming ready | Amber condition with bounded progress | Starting |
| A favorite stopped answering | Red condition and one relevant recovery action | Not responding |
| Koi found a local service that is private to this machine | Full-width `strip` with a blue edge | Ollama is running on this computer; Share... |
| A share is being created | Focused detail/card with one primary action | Share Ollama |
| A share is active but unverified by another device | Blue ownership with explicit pending copy | Shared; checking from another device |
| Another device verified the shared service | Green evidence state | Available from Office PC |
| Expert protocol evidence | Progressive detail using mono facts and compact rows | Technical details |

Do not turn `Calm`, `posture`, `family`, `pond`, or protocol record types into
required navigation concepts. Sylin character comes from the night-garden
surface, light, motion, precision, and card. The task language remains literal.

## Applying the dictionary to the four modules

- **Home** uses the lamp band, a page heading, search, one optional local-service
  strip, and a row catalog. Service details use a card or side panel with one
  primary action and progressive technical facts.
- **Devices** uses the same rows and conditions, grouped by machine. A device
  detail can expose hosted services and compare what two machines can see.
- **Settings** uses tiles or cards for the small set of setup areas, then rows
  for precise managed items. DNS records, raw mDNS, certificates, and logs live
  under clearly named advanced tools.
- **About** uses the exact `about` and `tcg` composition. Koi keeps its blue
  accent and the 100 px source sprite rendered at clean integer multiples.

The visual system does not preserve the old information architecture. Discover,
Browser, Glance, Diff, Trust, DNS, and Status can be recomposed into these four
destinations while retaining the same source-owned components and visual
meaning.

## Implementation recommendation

Treat the family base as a versioned source asset instead of manually
reconstructing it in each design or feature. The safest near-term approach is a
small shared base stylesheet with product tokens supplied separately, plus a
conformance check that catches accidental drift between Ghostlight and Koi.
Koi-specific rules should begin after that base and name the product concept
they present.

The Rust presentation layer should own the state and component vocabulary it
renders: service condition, evidence tone, available action, and progress. CSS
should render those meanings. It should not infer product truth from class-name
combinations. This keeps the portability mandate and prevents a future shared
frontend from becoming a second network or trust authority.

The existing Koi stylesheet is the immediate authority for the study. Any
subsequent component extraction should preserve its observable geometry, focus
behavior, reduced-motion rules, mascot treatment, and Koi accent unless a
deliberate design decision changes them.
