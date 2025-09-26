import os
import json
from firebase_admin import credentials, firestore, initialize_app, storage


def get_firebase_credentials():
    """
    Get Firebase credentials from environment variables.
    
    Returns:
        credentials.Certificate: Firebase credentials object
    """
    if os.path.exists("firebase.json"):
        return credentials.Certificate("firebase.json")
    else:
        service_account_info = {
            "type": "service_account",
            "project_id": os.getenv("FIREBASE_PROJECT_ID"),
            "private_key_id": os.getenv("FIREBASE_PRIVATE_KEY_ID"),
            "private_key": os.getenv("FIREBASE_PRIVATE_KEY").replace('\\n', '\n') if os.getenv("FIREBASE_PRIVATE_KEY") else None,
            "client_email": os.getenv("FIREBASE_CLIENT_EMAIL"),
            "client_id": os.getenv("FIREBASE_CLIENT_ID"),
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
            "client_x509_cert_url": os.getenv("FIREBASE_CLIENT_X509_CERT_URL")
        }
        
        # Validate required fields
        required_fields = [
            "project_id", "private_key_id", "private_key", 
            "client_email", "client_id", "client_x509_cert_url"
        ]
        
        missing_fields = [field for field in required_fields if not service_account_info.get(field)]
        if missing_fields:
            raise RuntimeError(f"Missing Firebase environment variables: {missing_fields}")
        
        return credentials.Certificate(service_account_info)


def initialize_firebase():
    """
    Initialize Firebase with appropriate credentials.
    
    Returns:
        firestore.Client: Firestore database client
    """
    try:
        # Get credentials
        creds = get_firebase_credentials()
        
        # Initialize Firebase app
        initialize_app(creds, {
            "storageBucket": os.getenv("FIREBASE_STORAGE"),
        })
        
        # Return Firestore client
        return firestore.client()
        
    except Exception as e:
        print(f"Error initializing Firebase: {e}")
        raise


def check_emulator_mode():
    """
    Check if we're running in Firebase emulator mode.
    
    Returns:
        bool: True if running in emulator mode
    """
    return (
        os.getenv("USE_EMULATOR", "").lower() == "true" or
        os.getenv("FIRESTORE_EMULATOR_HOST") is not None
    )
