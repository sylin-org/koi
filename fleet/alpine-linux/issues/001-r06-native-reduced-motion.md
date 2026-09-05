# Issue 001 — Alpine packaged renderer does not visibly honor native reduced motion

**Opened:** 2026-09-05 during `R06/alpine-packaged-renderer`
**Status:** open — return to the CachyOS R06 renderer owner
**Machine:** test-03 (Alpine Linux, Plasma Wayland)
**Run:** `r06-native-c497b3b-alpine-20260905`
**Desktop source:** `c497b3bc6ca2f99799b2f5e268a841f5c4d36d77`

## Observed

The signed native APK installed and rendered the real catalog row, navigation and
original Koi card through WebKitGTK. The live GTK/XSettings preference could also be
changed safely and restored exactly. It did not visibly suppress the card halo:

- with `Gtk/EnableAnimations=0` in the active `xsettingsd` source and
  `gtk-enable-animations=false`, `dump_xsettings` reported the live value `0`;
- two active-window captures still differed within a 272 by 272 region around the
  card halo, with ImageMagick normalized RMSE `0.00366419`;
- the two captures hash to
  `44774ee254edeb05bac50205be807e6a44a8e3f42b8f833978cdeb4f2f31c2c6` and
  `446152f2c86ec77ad904c07c9ae9ed1c768c6db46d1d04a6b63a509102806913`.

Changing only GNOME's `org.gnome.desktop.interface enable-animations` setting did
not change the live GTK XSetting on this Plasma session, so it is not evidence for
the native journey. The run used the actual XSettings provider instead.

## Impact

R06 requires the selected native renderer to honor an OS-native reduced-motion
preference where it is safely controllable. This Alpine lane cannot pass while the
most visible continuous motion remains active after the live native setting changes.
The candidate deployment was therefore rejected and the exact prior APK deployment
restored.

## Acceptance

- Identify the lowest shared WebKit/Tauri/CSS boundary that maps a supported native
  reduced-motion preference into the renderer.
- Add a focused automated check for the mapping or for the resulting motion-safe
  style; do not add an Alpine-only preference imitation.
- Re-run the packaged native journey with the live XSetting at `1`, then `0`, and
  visibly prove that the card halo becomes static while the rest of the card remains
  intact.
- Restore both preference files byte-for-byte and return the installed service and
  workbench to their accepted final state.

## Evidence and restoration

Ignored host-local captures are retained under
`tools/koi-ui-spike/target/native/r06-alpine-c497b3b/captures/`. The corresponding
Alpine journal entry records source/package hashes, commands, the separate keyboard
infrastructure limitation, and exact rollback. The live preference files were
restored to SHA-256
`52a303e711ece1fd940a7507f587acf276a30661c1d16edd640091f26145209b` and
`2ef10e0c8bc32c47b5960d7be9bb4d4ef01eafc2733a668f39ac539cd1498662`;
the final XSetting is `Gtk/EnableAnimations=1`, matching the baseline.
