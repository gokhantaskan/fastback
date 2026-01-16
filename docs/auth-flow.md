# Authentication & User Flow

## Overview

FastBack uses Firebase Authentication for identity management with a local database for user data storage. The backend supports two authentication methods:

1. **Session Cookie** (preferred for web apps) - Client logs in via `/auth/login` with email/password, backend sets an HttpOnly session cookie
2. **Bearer Token** (for API clients, mobile apps) - Client authenticates with Firebase directly, sends ID token in Authorization header

## Authentication Flow

Session cookie authentication takes priority when both methods are present.

```mermaid
sequenceDiagram
    participant Client
    participant Backend
    participant Firebase
    participant Database

    Note over Client,Database: Option 1: Session Cookie (Web Apps)
    Client->>Backend: Request with session cookie
    Backend->>Firebase: verify_session_cookie(cookie)
    Firebase-->>Backend: Claims (uid)
    Backend->>Database: Query user by external_id
    Database-->>Backend: User record
    Backend-->>Client: Response

    Note over Client,Database: Option 2: Bearer Token (API/Mobile)
    Client->>Backend: Request + Bearer Token
    Backend->>Firebase: verify_id_token(token)
    Firebase-->>Backend: Claims (uid)
    Backend->>Database: Query user by external_id
    Database-->>Backend: User record
    Backend-->>Client: Response
```

## Registration Flow

```mermaid
sequenceDiagram
    participant Client
    participant Backend
    participant Firebase
    participant Database

    Client->>Backend: POST /auth/register<br/>{email, password}

    Backend->>Database: Check existing email
    alt Email exists in DB
        Backend-->>Client: 409 Conflict
    else Email doesn't exist
        Backend->>Firebase: create_user(email, password)
        alt Firebase user exists
            Firebase-->>Backend: EMAIL_EXISTS error
            Backend-->>Client: 409 Conflict
        else Weak password
            Firebase-->>Backend: WEAK_PASSWORD error
            Backend-->>Client: 400 Bad Request
        else Success
            Firebase-->>Backend: Firebase User (uid)
            Backend->>Database: Create user record
            Database-->>Backend: New user
            Backend-->>Client: 201 Created + UserRead
        end
    end
```

## Login Flow

```mermaid
sequenceDiagram
    participant Client
    participant Backend
    participant Firebase
    participant Database

    Client->>Backend: POST /auth/login<br/>{email, password}

    Backend->>Firebase: Identity Toolkit API<br/>signInWithPassword(email, password)
    alt Invalid credentials
        Firebase-->>Backend: INVALID_CREDENTIALS
        Backend-->>Client: 401 Unauthorized
    else User disabled in Firebase
        Firebase-->>Backend: USER_DISABLED
        Backend-->>Client: 403 Forbidden
    else Rate limited
        Firebase-->>Backend: TOO_MANY_ATTEMPTS
        Backend-->>Client: 429 Too Many Requests
    else Success
        Firebase-->>Backend: {uid, email, idToken}

        Backend->>Firebase: create_session_cookie(idToken)
        Firebase-->>Backend: Session cookie

        Backend->>Database: Query user by external_id
        alt User exists
            alt User active
                Backend-->>Client: 200 OK + AuthLogin<br/>Set-Cookie: session
            else User inactive
                Backend-->>Client: 403 Forbidden
            end
        else User doesn't exist
            Backend->>Database: Auto-create user
            Database-->>Backend: New user
            Backend-->>Client: 200 OK + AuthLogin<br/>Set-Cookie: session
        end
    end
```

## Logout Flow

```mermaid
sequenceDiagram
    participant Client
    participant Backend
    participant Firebase

    Client->>Backend: POST /auth/logout<br/>Cookie: session

    alt No session cookie
        Backend-->>Client: 401 Unauthorized
    else Session cookie present
        Backend->>Firebase: verify_session_cookie(cookie)
        Backend->>Firebase: revoke_refresh_tokens(uid)
        Note over Backend: Best-effort revocation<br/>(continues even if verification fails)
        Backend-->>Client: 200 OK + Clear cookie
    end

    Note over Client,Firebase: All sessions invalidated
```

## Protected Route Flow

```mermaid
sequenceDiagram
    participant Client
    participant Backend
    participant Firebase
    participant Database

    Client->>Backend: GET /auth/me<br/>Cookie: session OR Bearer Token

    alt No auth provided
        Backend-->>Client: 401 Unauthorized
    else Session cookie present (Priority 1)
        Backend->>Firebase: verify_session_cookie(cookie, check_revoked=True)
        alt Invalid/revoked cookie
            Backend-->>Client: 401 Unauthorized
        else Valid cookie
            Note over Backend: Extract external_id from claims
        end
    else Bearer token present (Priority 2)
        Backend->>Firebase: verify_id_token(token)
        alt Invalid token
            Backend-->>Client: 401 Unauthorized
        else Valid token
            Note over Backend: Extract external_id from claims
        end
    end

    Backend->>Database: Query user by external_id
    alt User not found
        Backend-->>Client: 404 Not Found
    else User inactive
        Backend-->>Client: 403 Forbidden
    else User active
        Backend-->>Client: 200 OK + User data
    end
```

## Password Reset Flow

```mermaid
sequenceDiagram
    participant Client
    participant Backend
    participant Firebase
    participant Resend

    Note over Client,Resend: Step 1: Request Reset Link
    Client->>Backend: POST /auth/request-password-reset<br/>{email}
    Backend->>Firebase: generate_password_reset_link(email)
    Firebase-->>Backend: Reset link with oobCode
    Backend->>Resend: send_password_reset_email(email, link)
    Resend-->>Backend: Email sent
    Backend-->>Client: 200 OK (always, for security)

    Note over Client,Resend: Step 2: User clicks email link
    Client->>Backend: POST /auth/confirm-password-reset<br/>{oob_code, new_password}
    Backend->>Firebase: Identity Toolkit API<br/>resetPassword(oobCode, newPassword)
    alt Valid oobCode
        Firebase-->>Backend: Success
        Backend-->>Client: 200 OK
    else Expired oobCode
        Firebase-->>Backend: EXPIRED_OOB_CODE
        Backend-->>Client: 400 Bad Request
    else Invalid oobCode
        Firebase-->>Backend: INVALID_OOB_CODE
        Backend-->>Client: 400 Bad Request
    else Weak password
        Firebase-->>Backend: WEAK_PASSWORD
        Backend-->>Client: 400 Bad Request
    end
```

## Token Revocation Flow

```mermaid
sequenceDiagram
    participant Client
    participant Backend
    participant Firebase

    Client->>Backend: POST /auth/revoke-tokens<br/>Cookie: session OR Bearer Token
    Backend->>Firebase: Verify auth (see Protected Route Flow)
    Backend->>Firebase: revoke_refresh_tokens(uid)
    Backend-->>Client: 200 OK

    Note over Client,Firebase: All refresh tokens invalidated
```

## API Endpoints Summary

| Endpoint                       | Method | Auth   | Description                                      |
| ------------------------------ | ------ | ------ | ------------------------------------------------ |
| `/auth/register`               | POST   | None   | Create Firebase and local user (signup)          |
| `/auth/login`                  | POST   | None   | Login with email/password, sets session cookie   |
| `/auth/logout`                 | POST   | Cookie | Clear session cookie and revoke refresh tokens   |
| `/auth/request-password-reset` | POST   | None   | Send password reset email via Resend             |
| `/auth/confirm-password-reset` | POST   | None   | Complete reset with oobCode and new password     |
| `/auth/me`                     | GET    | User   | Get current user                                 |
| `/auth/revoke-tokens`          | POST   | User   | Revoke all refresh tokens (sign out all devices) |
| `/user/me`                     | PATCH  | User   | Update current user                              |
| `/user/me`                     | DELETE | User   | Delete current user                              |
| `/user/`                       | GET    | User   | List all users                                   |
| `/user/{id}`                   | GET    | User   | Get user by ID                                   |

## Response Schemas

### AuthLogin

Response schema returned by `/auth/login`:

```json
{
  "id": "uuid",
  "email": "user@example.com",
  "first_name": "John",
  "last_name": "Doe",
  "email_verified": false
}
```

**Fields:**

- `id` (UUID): User's unique identifier
- `email` (string): User's email address
- `first_name` (string): User's first name
- `last_name` (string): User's last name
- `email_verified` (boolean): Whether the user's email is verified (default: `false`)

## Auth Levels

- **None**: No authentication required
- **Cookie**: Requires valid session cookie (from `/auth/login`)
- **User**: Requires valid session cookie OR Bearer token + user must exist in database + user must be active

## Error Responses

| Status | Meaning                             |
| ------ | ----------------------------------- |
| 401    | Missing or invalid authentication   |
| 403    | User is inactive or disabled        |
| 404    | User not found in database          |
| 409    | Conflict (duplicate registration)   |
| 429    | Too many requests (rate limited)    |
| 502    | Authentication provider unavailable |
