from firebase_admin import get_app, initialize_app


def init_firebase() -> None:
    """Initialize Firebase Admin SDK (idempotent).

    Uses GOOGLE_APPLICATION_CREDENTIALS environment variable for credentials.
    """
    try:
        get_app()
    except ValueError:
        initialize_app()
