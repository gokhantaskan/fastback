## Why

During local development, sending actual emails via Resend is unnecessary and wastes API calls. The debug `print()` statements already log OOB codes and URLs to the console, which is sufficient for testing auth flows locally.

## What Changes

- Add `ENABLE_RESEND` environment variable (defaults to `true`)
- Skip `resend.Emails.send()` calls when `ENABLE_RESEND=false`
- Keep all existing debug logging so URLs are still visible in console

## Capabilities

### New Capabilities

_None—this is a configuration enhancement, not a new capability._

### Modified Capabilities

_None—no spec-level behavior changes. This is an implementation detail for local development convenience._

## Impact

- **Code**: `app/core/settings.py` (new setting), `app/core/email.py` (conditional send)
- **Config**: `.env.example` updated with new variable
- **Behavior**: No change in production (default enabled). Local dev can disable email sending.
