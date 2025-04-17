#!/usr/bin/env python3
# ADONIS User Manager

import os
import logging
import json
import hashlib
import secrets
import base64
from typing import Dict, List, Any, Optional

class User:
    """User class representing an ADONIS user."""
    
    def __init__(self, username, display_name=None, email=None, is_admin=False):
        """
        Initialize a user.
        
        Args:
            username: Unique username
            display_name: User's display name (defaults to username if None)
            email: User's email address
            is_admin: Whether the user has administrator privileges
        """
        self.username = username
        self.display_name = display_name or username
        self.email = email
        self.is_admin = is_admin
        self.roles = ["user"]
        if is_admin:
            self.roles.append("admin")
        self.preferences = {}
        self.api_keys = {}
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert user to dictionary."""
        return {
            "username": self.username,
            "display_name": self.display_name,
            "email": self.email,
            "is_admin": self.is_admin,
            "roles": self.roles,
            "preferences": self.preferences
        }
    
    @classmethod
    def from_dict(cls, data):
        """Create user from dictionary."""
        user = cls(
            username=data["username"],
            display_name=data["display_name"],
            email=data.get("email"),
            is_admin=data.get("is_admin", False)
        )
        user.roles = data.get("roles", ["user"])
        user.preferences = data.get("preferences", {})
        return user

class UserManager:
    """
    Manages users, authentication, and permissions.
    """
    
    def __init__(self, app):
        """
        Initialize the user manager.
        
        Args:
            app: Main application instance
        """
        self.app = app
        self.logger = logging.getLogger("adonis.core.user_manager")
        self.users = {}
        self.sessions = {}
        self.data_path = os.path.expanduser(
            app.config.get("system.paths.data_dir", "~/.adonis/data") + "/users"
        )
        self.current_user = None
    
    def initialize(self) -> bool:
        """
        Initialize the user manager.
        
        Returns:
            True if initialization was successful
        """
        try:
            self.logger.info("Initializing user manager")
            
            # Create users directory if it doesn't exist
            os.makedirs(self.data_path, exist_ok=True)
            os.makedirs(os.path.join(self.data_path, "profiles"), exist_ok=True)
            
            # Load users
            self._load_users()
            
            # Create default admin user if no users exist
            if not self.users:
                self._create_default_user()
            
            # Load sessions
            self._load_sessions()
            
            return True
        except Exception as e:
            self.logger.error(f"Failed to initialize user manager: {str(e)}")
            return False
    
    def _load_users(self) -> None:
        """Load users from disk."""
        users_file = os.path.join(self.data_path, "users.json")
        if not os.path.exists(users_file):
            self.logger.info("Users file not found. Starting with empty user list.")
            return
        
        try:
            with open(users_file, "r") as f:
                users_data = json.load(f)
                
            for username, user_data in users_data.items():
                self.users[username] = User.from_dict(user_data)
                
            self.logger.info(f"Loaded {len(self.users)} users")
            
        except Exception as e:
            self.logger.error(f"Error loading users: {str(e)}")
    
    def _save_users(self) -> bool:
        """Save users to disk."""
        users_file = os.path.join(self.data_path, "users.json")
        
        try:
            users_data = {}
            for username, user in self.users.items():
                users_data[username] = user.to_dict()
                
            with open(users_file, "w") as f:
                json.dump(users_data, f, indent=2)
                
            return True
            
        except Exception as e:
            self.logger.error(f"Error saving users: {str(e)}")
            return False
    
    def _create_default_user(self) -> None:
        """Create default admin user."""
        admin_user = User(
            username="admin",
            display_name="Administrator",
            is_admin=True
        )
        
        # Generate a random password for the admin user
        password = secrets.token_urlsafe(12)
        
        self.users["admin"] = admin_user
        self._set_password("admin", password)
        self._save_users()
        
        # Display the password in the log (only for initial setup)
        self.logger.info("Created default admin user")
        self.logger.info(f"Username: admin, Password: {password}")
        self.logger.info("Please change this password after first login!")
    
    def _load_sessions(self) -> None:
        """Load active sessions from disk."""
        sessions_file = os.path.join(self.data_path, "sessions.json")
        if not os.path.exists(sessions_file):
            return
        
        try:
            with open(sessions_file, "r") as f:
                self.sessions = json.load(f)
                
            # Clean up expired sessions
            self._cleanup_sessions()
            
        except Exception as e:
            self.logger.error(f"Error loading sessions: {str(e)}")
            self.sessions = {}
    
    def _save_sessions(self) -> bool:
        """Save active sessions to disk."""
        sessions_file = os.path.join(self.data_path, "sessions.json")
        
        try:
            with open(sessions_file, "w") as f:
                json.dump(self.sessions, f)
                
            return True
            
        except Exception as e:
            self.logger.error(f"Error saving sessions: {str(e)}")
            return False
    
    def _cleanup_sessions(self) -> None:
        """Clean up expired sessions."""
        import time
        
        current_time = time.time()
        session_timeout = self.app.config.get("system.security.session_timeout_minutes", 30) * 60
        
        expired_sessions = [
            token for token, session in self.sessions.items()
            if current_time - session.get("last_active", 0) > session_timeout
        ]
        
        for token in expired_sessions:
            del self.sessions[token]
            
        if expired_sessions:
            self.logger.debug(f"Cleaned up {len(expired_sessions)} expired sessions")
            self._save_sessions()
    
    def authenticate(self, username: str, password: str) -> Optional[str]:
        """
        Authenticate a user with username and password.
        
        Args:
            username: Username
            password: Password
            
        Returns:
            Session token if authentication successful, None otherwise
        """
        if username not in self.users:
            self.logger.warning(f"Authentication failed: User '{username}' does not exist")
            return None
        
        # Verify password
        if not self._verify_password(username, password):
            self.logger.warning(f"Authentication failed: Invalid password for user '{username}'")
            return None
        
        # Create session
        import time
        token = secrets.token_urlsafe(32)
        self.sessions[token] = {
            "username": username,
            "created": time.time(),
            "last_active": time.time(),
            "ip_address": "127.0.0.1"  # This would be replaced with actual client IP
        }
        
        self._save_sessions()
        self.logger.info(f"User '{username}' authenticated successfully")
        
        return token
    
    def validate_session(self, token: str) -> bool:
        """
        Validate a session token.
        
        Args:
            token: Session token
            
        Returns:
            True if the session is valid
        """
        if token not in self.sessions:
            return False
        
        # Check session expiration
        import time
        current_time = time.time()
        session = self.sessions[token]
        session_timeout = self.app.config.get("system.security.session_timeout_minutes", 30) * 60
        
        if current_time - session.get("last_active", 0) > session_timeout:
            del self.sessions[token]
            self._save_sessions()
            return False
        
        # Update last active time
        session["last_active"] = current_time
        
        return True
    
    def get_user(self, username: str) -> Optional[User]:
        """
        Get user by username.
        
        Args:
            username: Username
            
        Returns:
            User object if found, None otherwise
        """
        return self.users.get(username)
    
    def get_current_user(self) -> Optional[User]:
        """
        Get the currently authenticated user.
        
        Returns:
            Current user object if authenticated, None otherwise
        """
        return self.current_user
    
    def set_current_user(self, username: str) -> bool:
        """
        Set the current user.
        
        Args:
            username: Username
            
        Returns:
            True if the user was set successfully
        """
        if username in self.users:
            self.current_user = self.users[username]
            return True
        return False
    
    def create_user(self, username: str, password: str, display_name: str = None, 
                   email: str = None, is_admin: bool = False) -> bool:
        """
        Create a new user.
        
        Args:
            username: Username
            password: Password
            display_name: Display name
            email: Email address
            is_admin: Whether the user is an admin
            
        Returns:
            True if the user was created successfully
        """
        if username in self.users:
            self.logger.warning(f"Cannot create user: Username '{username}' already exists")
            return False
        
        # Create user
        user = User(
            username=username,
            display_name=display_name,
            email=email,
            is_admin=is_admin
        )
        
        self.users[username] = user
        
        # Set password
        self._set_password(username, password)
        
        # Save users
        self._save_users()
        
        self.logger.info(f"Created user '{username}'")
        
        return True
    
    def update_user(self, username: str, display_name: str = None, 
                   email: str = None, is_admin: bool = None) -> bool:
        """
        Update user information.
        
        Args:
            username: Username
            display_name: Display name
            email: Email address
            is_admin: Whether the user is an admin
            
        Returns:
            True if the user was updated successfully
        """
        if username not in self.users:
            self.logger.warning(f"Cannot update user: User '{username}' does not exist")
            return False
        
        user = self.users[username]
        
        if display_name is not None:
            user.display_name = display_name
            
        if email is not None:
            user.email = email
            
        if is_admin is not None:
            user.is_admin = is_admin
            if is_admin and "admin" not in user.roles:
                user.roles.append("admin")
            elif not is_admin and "admin" in user.roles:
                user.roles.remove("admin")
        
        # Save users
        self._save_users()
        
        self.logger.info(f"Updated user '{username}'")
        
        return True
    
    def delete_user(self, username: str) -> bool:
        """
        Delete a user.
        
        Args:
            username: Username
            
        Returns:
            True if the user was deleted successfully
        """
        if username not in self.users:
            self.logger.warning(f"Cannot delete user: User '{username}' does not exist")
            return False
        
        # Check if this is the last admin user
        if self.users[username].is_admin:
            admin_count = sum(1 for user in self.users.values() if user.is_admin)
            if admin_count <= 1:
                self.logger.warning("Cannot delete the last admin user")
                return False
        
        # Delete password file
        self._delete_password_file(username)
        
        # Delete user
        del self.users[username]
        
        # Invalidate any active sessions for this user
        for token, session in list(self.sessions.items()):
            if session.get("username") == username:
                del self.sessions[token]
        
        # Save changes
        self._save_users()
        self._save_sessions()
        
        self.logger.info(f"Deleted user '{username}'")
        
        return True
    
    def change_password(self, username: str, current_password: str, new_password: str) -> bool:
        """
        Change a user's password.
        
        Args:
            username: Username
            current_password: Current password
            new_password: New password
            
        Returns:
            True if the password was changed successfully
        """
        if username not in self.users:
            self.logger.warning(f"Cannot change password: User '{username}' does not exist")
            return False
        
        # Verify current password
        if not self._verify_password(username, current_password):
            self.logger.warning(f"Cannot change password: Invalid current password for user '{username}'")
            return False
        
        # Set new password
        self._set_password(username, new_password)
        
        self.logger.info(f"Changed password for user '{username}'")
        
        return True
    
    def _set_password(self, username: str, password: str) -> bool:
        """
        Set a user's password (internal method).
        
        Args:
            username: Username
            password: New password
            
        Returns:
            True if the password was set successfully
        """
        if username not in self.users:
            return False
        
        # Generate salt
        salt = secrets.token_bytes(16)
        
        # Hash password with salt
        password_hash = self._hash_password(password, salt)
        
        # Save to file
        password_file = os.path.join(self.data_path, "profiles", f"{username}.pwd")
        
        try:
            with open(password_file, "wb") as f:
                f.write(salt)
                f.write(password_hash)
                
            # Set secure permissions
            os.chmod(password_file, 0o600)
                
            return True
            
        except Exception as e:
            self.logger.error(f"Error setting password for user '{username}': {str(e)}")
            return False
    
    def _verify_password(self, username: str, password: str) -> bool:
        """
        Verify a user's password (internal method).
        
        Args:
            username: Username
            password: Password to verify
            
        Returns:
            True if the password is correct
        """
        if username not in self.users:
            return False
        
        password_file = os.path.join(self.data_path, "profiles", f"{username}.pwd")
        
        if not os.path.exists(password_file):
            self.logger.error(f"Password file for user '{username}' not found")
            return False
        
        try:
            with open(password_file, "rb") as f:
                data = f.read()
                
            # Extract salt (first 16 bytes) and stored hash
            salt = data[:16]
            stored_hash = data[16:]
            
            # Hash password with the same salt
            password_hash = self._hash_password(password, salt)
            
            # Compare hashes
            return password_hash == stored_hash
            
        except Exception as e:
            self.logger.error(f"Error verifying password for user '{username}': {str(e)}")
            return False
    
    def _hash_password(self, password: str, salt: bytes) -> bytes:
        """
        Hash a password with salt using PBKDF2.
        
        Args:
            password: Password to hash
            salt: Salt bytes
            
        Returns:
            Password hash
        """
        import hashlib
        
        # Use PBKDF2 with SHA-256 and 100,000 iterations
        key = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            100000
        )
        
        return key
    
    def _delete_password_file(self, username: str) -> bool:
        """
        Delete a user's password file.
        
        Args:
            username: Username
            
        Returns:
            True if the file was deleted
        """
        password_file = os.path.join(self.data_path, "profiles", f"{username}.pwd")
        
        if os.path.exists(password_file):
            try:
                os.remove(password_file)
                return True
            except Exception as e:
                self.logger.error(f"Error deleting password file for user '{username}': {str(e)}")
                
        return False