"""
OAuth 2.0 Authentication Module
Supports: Google, Facebook, Phone+OTP
"""

import os
import json
import secrets
from datetime import datetime, timedelta
from functools import wraps
from urllib.parse import urlencode, quote
import sqlite3

import requests
from flask import session, request, redirect, url_for, current_app, jsonify

# OAuth Configuration
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "").strip()
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "").strip()
GOOGLE_REDIRECT_URI = os.environ.get("GOOGLE_REDIRECT_URI", "").strip()

FACEBOOK_APP_ID = os.environ.get("FACEBOOK_APP_ID", "").strip()
FACEBOOK_APP_SECRET = os.environ.get("FACEBOOK_APP_SECRET", "").strip()
FACEBOOK_REDIRECT_URI = os.environ.get("FACEBOOK_REDIRECT_URI", "").strip()

SITE_URL = os.environ.get("JOBBOARD_SITE_URL", "https://jobboard-ai-app.onrender.com").rstrip("/")


class OAuthProvider:
    """Base class for OAuth providers"""
    
    def __init__(self, client_id, client_secret, redirect_uri):
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
    
    def get_auth_url(self, state):
        raise NotImplementedError
    
    def exchange_code(self, code):
        raise NotImplementedError
    
    def get_user_info(self, access_token):
        raise NotImplementedError


class GoogleOAuth(OAuthProvider):
    """Google OAuth 2.0 Implementation"""
    
    AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
    TOKEN_URL = "https://oauth2.googleapis.com/token"
    USERINFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo"
    
    def get_auth_url(self, state):
        params = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "response_type": "code",
            "scope": "openid email profile",
            "state": state,
            "access_type": "offline",
            "prompt": "consent",
        }
        return f"{self.AUTH_URL}?{urlencode(params)}"
    
    def exchange_code(self, code):
        """Exchange authorization code for access token"""
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": self.redirect_uri,
        }
        
        try:
            response = requests.post(self.TOKEN_URL, data=data, timeout=10)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"Google token exchange error: {e}")
            return None
    
    def get_user_info(self, access_token):
        """Get user information from access token"""
        headers = {"Authorization": f"Bearer {access_token}"}
        
        try:
            response = requests.get(self.USERINFO_URL, headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json()
            return {
                "provider": "google",
                "id": data.get("id"),
                "email": data.get("email"),
                "name": data.get("name"),
                "picture": data.get("picture"),
            }
        except Exception as e:
            print(f"Google userinfo error: {e}")
            return None


class FacebookOAuth(OAuthProvider):
    """Facebook OAuth 2.0 Implementation"""
    
    AUTH_URL = "https://www.facebook.com/v18.0/dialog/oauth"
    TOKEN_URL = "https://graph.instagram.com/v18.0/oauth/access_token"
    USERINFO_URL = "https://graph.instagram.com/me"
    
    def get_auth_url(self, state):
        params = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "response_type": "code",
            "scope": "public_profile,email",
            "state": state,
        }
        return f"{self.AUTH_URL}?{urlencode(params)}"
    
    def exchange_code(self, code):
        """Exchange authorization code for access token"""
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code": code,
            "redirect_uri": self.redirect_uri,
        }
        
        try:
            response = requests.get(self.TOKEN_URL, params=data, timeout=10)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"Facebook token exchange error: {e}")
            return None
    
    def get_user_info(self, access_token):
        """Get user information from access token"""
        params = {
            "fields": "id,name,email,picture",
            "access_token": access_token,
        }
        
        try:
            response = requests.get(self.USERINFO_URL, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()
            picture_url = data.get("picture", {}).get("data", {}).get("url", "")
            return {
                "provider": "facebook",
                "id": data.get("id"),
                "email": data.get("email"),
                "name": data.get("name"),
                "picture": picture_url,
            }
        except Exception as e:
            print(f"Facebook userinfo error: {e}")
            return None


def init_oauth_providers():
    """Initialize OAuth providers"""
    providers = {}
    
    if GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET and GOOGLE_REDIRECT_URI:
        providers["google"] = GoogleOAuth(
            GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI
        )
    
    if FACEBOOK_APP_ID and FACEBOOK_APP_SECRET and FACEBOOK_REDIRECT_URI:
        providers["facebook"] = FacebookOAuth(
            FACEBOOK_APP_ID, FACEBOOK_APP_SECRET, FACEBOOK_REDIRECT_URI
        )
    
    return providers


def generate_oauth_state():
    """Generate secure state for OAuth flow"""
    return secrets.token_urlsafe(32)


def store_oauth_state(state, expires_in=600):
    """Store OAuth state in session (expires in 10 minutes by default)"""
    session[f"oauth_state_{state}"] = {
        "created_at": datetime.now().isoformat(),
        "expires_at": (datetime.now() + timedelta(seconds=expires_in)).isoformat(),
    }


def verify_oauth_state(state):
    """Verify OAuth state and remove it"""
    key = f"oauth_state_{state}"
    if key not in session:
        return False
    
    state_data = session.pop(key)
    expires_at = datetime.fromisoformat(state_data["expires_at"])
    
    if datetime.now() > expires_at:
        return False
    
    return True


def store_oauth_callback(user_data, auth_method):
    """Store OAuth callback data temporarily"""
    callback_key = secrets.token_urlsafe(16)
    session[f"oauth_callback_{callback_key}"] = {
        "user_data": user_data,
        "auth_method": auth_method,
        "created_at": datetime.now().isoformat(),
        "expires_at": (datetime.now() + timedelta(minutes=15)).isoformat(),
    }
    return callback_key


def get_oauth_callback(callback_key):
    """Get and remove OAuth callback data"""
    key = f"oauth_callback_{callback_key}"
    if key not in session:
        return None
    
    callback_data = session.pop(key)
    expires_at = datetime.fromisoformat(callback_data["expires_at"])
    
    if datetime.now() > expires_at:
        return None
    
    return callback_data
