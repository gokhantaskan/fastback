## 1. Configuration

- [x] 1.1 Add `enable_resend: bool` field to `Settings` class in `app/core/settings.py` with alias `ENABLE_RESEND`, default `True`
- [x] 1.2 Add `ENABLE_RESEND` to `.env.example` with comment explaining usage

## 2. Email Functions

- [x] 2.1 Add early return in `send_password_reset_email` when `enable_resend` is `False` (after debug logging)
- [x] 2.2 Add early return in `send_email_verification_email` when `enable_resend` is `False` (after debug logging)
- [x] 2.3 Add early return in `send_email_change_verification_email` when `enable_resend` is `False` (after debug logging)
