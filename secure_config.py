#!/usr/bin/env python3
"""
Secure Configuration Management for GitHub MCP Server
Prevents API key exposure to AI assistants and chat logs
Based on Kevin's revolutionary keyring architecture
"""

import os
import keyring
from typing import Optional
from pydantic_settings import BaseSettings
from pydantic import SecretStr
from functools import lru_cache

class SecureSettings(BaseSettings):
    """Secure settings that never expose API keys in logs or to AI assistants"""
    
    # Public settings (safe to log)
    app_name: str = "Secure GitHub MCP Server"
    debug: bool = False
    api_timeout: int = 30
    github_base_url: str = "https://api.github.com"
    
    # Secret settings (loaded securely, never logged)
    _github_token: Optional[SecretStr] = None
    
    class Config:
        env_file = None  # Disable .env file loading for security
        
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Load secrets from secure storage
        self._load_secrets_from_keyring()
    
    def _load_secrets_from_keyring(self):
        """Load API keys from OS keyring (encrypted local storage)"""
        try:
            # Try to load from keyring first (most secure)
            github_token = keyring.get_password("github-mcp-server", "github-token")
            if github_token:
                self._github_token = SecretStr(github_token)
                
        except Exception as e:
            print(f"Warning: Could not load from keyring: {e}")
            # Fallback to environment variables (less secure but compatible)
            self._load_from_env()
    
    def _load_from_env(self):
        """Fallback: Load from environment variables"""
        github_token = os.getenv("GITHUB_TOKEN")
        if github_token:
            self._github_token = SecretStr(github_token)
    
    @property
    def github_token(self) -> str:
        """Get GitHub API token (never logged or exposed)"""
        if self._github_token:
            return self._github_token.get_secret_value()
        return ""
    
    @property
    def has_github_token(self) -> bool:
        """Check if GitHub token is available"""
        return bool(self._github_token)

@lru_cache()
def get_secure_settings() -> SecureSettings:
    """Get cached secure settings instance"""
    return SecureSettings()

def setup_api_keys():
    """Interactive setup for API keys (stores in OS keyring)"""
    print("🔐 Secure GitHub MCP Server - API Key Setup")
    print("Keys will be stored encrypted in your OS keyring")
    print("They will NOT be visible to AI assistants or in logs")
    print("-" * 60)
    
    # GitHub Token
    print("📝 GitHub Personal Access Token Setup:")
    print("   1. Go to https://github.com/settings/tokens")
    print("   2. Generate new token (classic)")
    print("   3. Select 'repo' scope for full repository access")
    print("   4. Copy the token and paste below")
    print()
    
    github_token = input("Enter GitHub Personal Access Token: ").strip()
    if github_token:
        if github_token.startswith("ghp_") or github_token.startswith("github_pat_"):
            keyring.set_password("github-mcp-server", "github-token", github_token)
            print("✅ GitHub token stored securely in OS keyring")
        else:
            print("⚠️  Warning: Token doesn't look like a GitHub token")
            confirm = input("Store anyway? (y/N): ").strip().lower()
            if confirm == 'y':
                keyring.set_password("github-mcp-server", "github-token", github_token)
                print("✅ GitHub token stored securely")
            else:
                print("❌ Token not saved")
    else:
        print("❌ No GitHub token provided - MCP server will fail")
    
    print("\n🎉 Setup complete! Your GitHub token is now stored securely.")
    print("Start your MCP server normally - the token will be loaded automatically.")
    print("\n🔧 Usage:")
    print("   python github_mcp_server.py  # Start MCP server")
    print("   python secure_config.py test # Test configuration")

def clear_api_keys():
    """Clear stored API keys"""
    try:
        keyring.delete_password("github-mcp-server", "github-token")
        print("✅ GitHub token cleared from keyring")
    except keyring.errors.PasswordDeleteError:
        print("ℹ️  No GitHub token found in keyring")
    
    print("🧹 All API keys cleared from secure storage")

def test_configuration():
    """Test the current configuration"""
    settings = get_secure_settings()
    print("🔑 GitHub MCP Server Configuration:")
    print(f"   GitHub Token: {'✅ Configured' if settings.has_github_token else '❌ Missing'}")
    print(f"   API Endpoint: {settings.github_base_url}")
    print(f"   Timeout: {settings.api_timeout}s")
    
    if settings.has_github_token:
        token = settings.github_token
        print(f"   Token Preview: {token[:8]}...{token[-4:] if len(token) > 12 else '***'}")
    else:
        print("\n⚠️  No GitHub token configured!")
        print("   Run: python secure_config.py setup")

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        if sys.argv[1] == "setup":
            setup_api_keys()
        elif sys.argv[1] == "clear":
            clear_api_keys()
        elif sys.argv[1] == "test":
            test_configuration()
    else:
        print("🔐 Secure GitHub MCP Server Configuration")
        print()
        print("Usage:")
        print("  python secure_config.py setup  # Setup GitHub token securely")
        print("  python secure_config.py test   # Test current configuration")
        print("  python secure_config.py clear  # Clear all stored tokens")
        print()
        print("🔒 Security Features:")
        print("  • OS keyring encrypted storage (Windows/macOS/Linux)")
        print("  • Zero token exposure to AI assistants")
        print("  • No plaintext token storage")
        print("  • Enterprise-grade credential management")
