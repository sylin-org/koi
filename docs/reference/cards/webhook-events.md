# Webhook events

Configured sinks receive HMAC-signed event envelopes through outbound HTTP POST. Each sink owns bounded delivery/retry behavior; consumers verify signatures and handle duplicates/failures.

## Use and verify

Use the [integration guide](../../guides/integrations.md) and configure only the event consumers needed by the application. Keep sink secrets out of repository configuration and diagnostic captures.

## Boundaries

Delivery is not a durable general-purpose message queue. Domain audit state and event consumers have separate responsibilities. An existing sink demonstration does not certify a different tool/version.

See [the integration guide](../../guides/integrations.md), [security model](../security-model.md) and [launch readiness](../../launch/README.md). Current acceptance evidence belongs in the launch ledger; this reference card does not inherit proof from an older build.
