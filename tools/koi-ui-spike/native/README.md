# Fixture-specific native helpers

The scripts in this directory contain explicit host/package/window baselines. They are not a reusable fleet installer or a current product acceptance runbook. Review their actual paths, expected hashes, service scope and restoration behavior before any use. If those assumptions do not match, stop using that helper and choose a compatible reviewed procedure.

Recovery archives can contain identity material. Keep them private, preserve ownership/modes, verify integrity and restrict restoration to the captured target. Restoration must be armed before a disruptive check and must remain available until the real native service/workbench and host preferences are verified. A failed recovery invalidates the run.

Window geometry/input helpers act on a specifically selected native window and must be unloaded or allowed to release their resources after the check. Existing desktop/input permissions remain the boundary. Motion observers read the actual GTK/GDK backend; a setting from a different backend is not proof of the installed window's behavior.

Use [the current helper entry point](../../koi-ui-native/README.md) and [the fleet contract](../../../fleet/CONTRACT.md). Validate visible focus, geometry and motion with current captures. Do not promote a baseline-specific observation into current launch evidence without identifying the exact candidate and repeating the relevant assertion.
