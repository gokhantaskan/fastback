from typing import Literal, NotRequired, TypedDict

# Constants
IDENTITY_TOOLKIT_ENDPOINT_PATHS: dict[str, str] = {
    "signInWithPassword": "v1/accounts:signInWithPassword",
    "sendOobCode": "v1/accounts:sendOobCode",
    "update": "v1/accounts:update",
    "resetPassword": "v1/accounts:resetPassword",
}
# Backward-compatible alias for existing code
IDENTITY_TOOLKIT_ENDPOINTS = IDENTITY_TOOLKIT_ENDPOINT_PATHS


# Request schemas
class SignInWithPasswordRequest(TypedDict, total=False):
    """Request schema for signInWithPassword endpoint.

    https://cloud.google.com/identity-platform/docs/reference/rest/v1/accounts/signInWithPassword
    """

    email: str
    password: str
    returnSecureToken: bool
    # Optional fields
    pendingIdToken: NotRequired[str]
    captchaChallenge: NotRequired[str]
    captchaResponse: NotRequired[str]
    instanceId: NotRequired[str]
    delegatedProjectNumber: NotRequired[str]
    idToken: NotRequired[str]
    tenantId: NotRequired[str]
    clientType: NotRequired[
        Literal[
            "CLIENT_TYPE_UNSPECIFIED",
            "CLIENT_TYPE_WEB",
            "CLIENT_TYPE_ANDROID",
            "CLIENT_TYPE_IOS",
        ]
    ]
    recaptchaVersion: NotRequired[
        Literal["RECAPTCHA_VERSION_UNSPECIFIED", "RECAPTCHA_ENTERPRISE"]
    ]


# Response schemas
class SignInWithPasswordResponse(TypedDict, total=False):
    """Response schema for signInWithPassword endpoint."""

    kind: str
    localId: str  # The UID of the authenticated user
    email: str
    displayName: str
    idToken: str  # Firebase ID token for the authenticated user
    registered: bool
    refreshToken: str
    expiresIn: str  # Token expiration time in seconds


class SendOobCodeRequest(TypedDict, total=False):
    """Request schema for sendOobCode endpoint.

    https://cloud.google.com/identity-platform/docs/reference/rest/v1/accounts/sendOobCode
    """

    # Required fields
    requestType: Literal[
        "PASSWORD_RESET",
        "EMAIL_SIGNIN",
        "VERIFY_EMAIL",
        "VERIFY_AND_CHANGE_EMAIL",
    ]
    email: NotRequired[str]  # Required for PASSWORD_RESET, EMAIL_SIGNIN, VERIFY_EMAIL
    # Optional fields
    challenge: NotRequired[str]  # Deprecated
    captchaResp: NotRequired[str]  # reCAPTCHA response for PASSWORD_RESET
    userIp: NotRequired[str]  # Required for PASSWORD_RESET
    newEmail: NotRequired[str]  # Required for VERIFY_AND_CHANGE_EMAIL
    idToken: NotRequired[str]  # Required for VERIFY_AND_CHANGE_EMAIL and VERIFY_EMAIL
    # (unless returnOobLink=true)
    continueUrl: NotRequired[str]
    iOSBundleId: NotRequired[str]
    iOSAppStoreId: NotRequired[str]
    androidPackageName: NotRequired[str]
    androidInstallApp: NotRequired[bool]
    androidMinimumVersion: NotRequired[str]
    canHandleCodeInApp: NotRequired[bool]
    tenantId: NotRequired[str]
    targetProjectId: NotRequired[str]
    dynamicLinkDomain: NotRequired[str]
    returnOobLink: NotRequired[bool]
    clientType: NotRequired[
        Literal[
            "CLIENT_TYPE_UNSPECIFIED",
            "CLIENT_TYPE_WEB",
            "CLIENT_TYPE_ANDROID",
            "CLIENT_TYPE_IOS",
        ]
    ]
    recaptchaVersion: NotRequired[
        Literal["RECAPTCHA_VERSION_UNSPECIFIED", "RECAPTCHA_ENTERPRISE"]
    ]
    linkDomain: NotRequired[str]


class SendOobCodeResponse(TypedDict, total=False):
    oobCode: str
    email: str
    oobLink: str


class UpdateAccountRequest(TypedDict, total=False):
    """Request schema for accounts:update endpoint.

    https://cloud.google.com/identity-platform/docs/reference/rest/v1/accounts/update
    """

    idToken: str  # Required for authenticated updates
    oobCode: NotRequired[str]  # For email verification confirmation
    password: NotRequired[str]  # New password
    email: NotRequired[str]  # New email
    displayName: NotRequired[str]
    photoUrl: NotRequired[str]
    deleteAttribute: NotRequired[list[str]]
    returnSecureToken: NotRequired[bool]
    validSince: NotRequired[str]
    disableUser: NotRequired[bool]
    localId: NotRequired[str]
    emailVerified: NotRequired[bool]


class UpdateAccountResponse(TypedDict, total=False):
    """Response schema for accounts:update endpoint."""

    kind: str
    localId: str
    email: str
    displayName: str
    photoUrl: str
    passwordHash: str
    emailVerified: bool
    idToken: str  # New ID token (if returnSecureToken=true)
    refreshToken: str
    expiresIn: str


class ResetPasswordRequest(TypedDict, total=False):
    """Request schema for resetPassword endpoint.

    https://cloud.google.com/identity-platform/docs/reference/rest/v1/accounts/resetPassword
    """

    oobCode: str  # Out-of-band code from password reset email
    newPassword: str
    tenantId: NotRequired[str]


class ResetPasswordResponse(TypedDict, total=False):
    """Response schema for resetPassword endpoint."""

    kind: str
    email: str
    requestType: str
