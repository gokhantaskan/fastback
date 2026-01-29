## Context

Email sending via Resend is currently always-on. During local development, this wastes API calls and clutters Resend logs. Debug `print()` statements already output OOB codes and URLs to the console, providing sufficient visibility for testing auth flows.

## Goals / Non-Goals

**Goals:**
- Add `ENABLE_RESEND` env toggle to skip actual email sending
- Preserve existing debug logging regardless of toggle state
- Default to enabled (no behavior change unless explicitly disabled)

**Non-Goals:**
- Queueing or storing unsent emails
- Different email backends (e.g., SMTP fallback)
- Conditional logging based on toggle

## Decisions

### 1. Setting location and default

Add `enable_resend: bool` to `Settings` class with `ENABLE_RESEND` alias, defaulting to `True`.

**Rationale**: Follows existing pattern for optional features (e.g., `resend_api_key`). Default `True` ensures no behavior change in production.

### 2. Guard placement

Add early return in each `send_*` function after debug logging, before `resend.Emails.send()`.

**Alternatives considered:**
- Wrapper function: Adds indirection for minimal benefit
- Decorator: Overkill for 3 functions with identical check

**Rationale**: Simple inline check is readable and explicit. Each function already has `settings = get_settings()` call.

## Risks / Trade-offs

**[Silent skip]** → Mitigated by existing debug logging. Developers see URLs in console even when emails don't send.

**[Accidental disable in prod]** → Low risk. Requires explicit `ENABLE_RESEND=false` in env. Document in `.env.example`.
