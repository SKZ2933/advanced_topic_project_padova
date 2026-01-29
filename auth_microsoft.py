"""
Microsoft/Mojang Authentication Module
Handles the OAuth flow: Microsoft -> Xbox Live -> XSTS -> Minecraft Token

Flow:
1. Device Code Flow (user opens browser, enters code)
2. Exchange Microsoft token for Xbox Live token
3. Exchange Xbox Live token for XSTS token
4. Exchange XSTS token for Minecraft access token
5. Get player profile (UUID, username)
"""

import requests
import json
import os
import time
import webbrowser

# Token cache file (avoids re-authentication each time)
TOKEN_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mc_token.json")

# Azure client ID (Prism Launcher's public client ID, approved by Microsoft)
MICROSOFT_CLIENT_ID = "c36a9fb6-4f2a-41ff-90bd-ae7cc92031eb"


class MinecraftAuth:
    """Handles the complete Microsoft -> Minecraft authentication flow."""

    def __init__(self):
        self.microsoft_token = None
        self.xbox_token = None
        self.xbox_user_hash = None
        self.xsts_token = None
        self.minecraft_token = None
        self.uuid = None
        self.username = None

    def authenticate(self, force_refresh=False):
        """
        Authenticate and return session data.
        
        Args:
            force_refresh: If True, ignore cached token
            
        Returns:
            dict: {'access_token', 'uuid', 'username'}
        """
        # Try loading cached token first
        if not force_refresh and self._load_cached_token():
            print("[AUTH] Token loaded from cache")
            if self._validate_token():
                return self._get_result()
            print("[AUTH] Token expired, re-authenticating...")

        print("\n" + "=" * 50)
        print("MICROSOFT AUTHENTICATION")
        print("=" * 50)

        self._step1_microsoft_oauth()
        self._step2_xbox_live()
        self._step3_xsts()
        self._step4_minecraft()
        self._step5_profile()
        self._save_token()

        print(f"\n[OK] Authentication successful!")
        print(f"    Player: {self.username}")
        print(f"    UUID: {self.uuid}")
        print("=" * 50 + "\n")

        return self._get_result()

    def _get_result(self):
        return {
            'access_token': self.minecraft_token,
            'uuid': self.uuid,
            'username': self.username
        }

    # =========================================================================
    # AUTHENTICATION STEPS
    # =========================================================================

    def _step1_microsoft_oauth(self):
        """Step 1: Microsoft Device Code Flow."""
        print("\n[1/5] Microsoft OAuth...")

        # Request device code
        response = requests.post(
            "https://login.microsoftonline.com/consumers/oauth2/v2.0/devicecode",
            data={
                "client_id": MICROSOFT_CLIENT_ID,
                "scope": "XboxLive.signin offline_access"
            }
        )
        if response.status_code != 200:
            raise Exception(f"OAuth error: {response.text}")

        data = response.json()
        device_code = data["device_code"]
        user_code = data["user_code"]
        verification_uri = data["verification_uri"]
        expires_in = data["expires_in"]
        interval = data.get("interval", 5)

        print(f"\n>>> Open: {verification_uri}")
        print(f">>> Enter code: {user_code}\n")
        webbrowser.open(verification_uri)
        print("[*] Waiting for authentication...")

        # Poll for completion
        start_time = time.time()
        while time.time() - start_time < expires_in:
            time.sleep(interval)
            response = requests.post(
                "https://login.microsoftonline.com/consumers/oauth2/v2.0/token",
                data={
                    "client_id": MICROSOFT_CLIENT_ID,
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                    "device_code": device_code
                }
            )
            data = response.json()

            if "access_token" in data:
                self.microsoft_token = data["access_token"]
                print("[OK] Microsoft authentication successful!")
                return

            if data.get("error") == "authorization_declined":
                raise Exception("Authentication declined by user")
            if data.get("error") not in ["authorization_pending", "slow_down"]:
                raise Exception(f"OAuth error: {data}")

        raise Exception("Timeout: authentication took too long")

    def _step2_xbox_live(self):
        """Step 2: Exchange Microsoft token for Xbox Live token."""
        print("[2/5] Xbox Live authentication...")

        response = requests.post(
            "https://user.auth.xboxlive.com/user/authenticate",
            json={
                "Properties": {
                    "AuthMethod": "RPS",
                    "SiteName": "user.auth.xboxlive.com",
                    "RpsTicket": f"d={self.microsoft_token}"
                },
                "RelyingParty": "http://auth.xboxlive.com",
                "TokenType": "JWT"
            },
            headers={"Content-Type": "application/json", "Accept": "application/json"}
        )
        if response.status_code != 200:
            raise Exception(f"Xbox Live error: {response.text}")

        data = response.json()
        self.xbox_token = data["Token"]
        self.xbox_user_hash = data["DisplayClaims"]["xui"][0]["uhs"]
        print("[OK] Xbox Live token obtained")

    def _step3_xsts(self):
        """Step 3: Exchange Xbox Live token for XSTS token."""
        print("[3/5] XSTS authentication...")

        response = requests.post(
            "https://xsts.auth.xboxlive.com/xsts/authorize",
            json={
                "Properties": {
                    "SandboxId": "RETAIL",
                    "UserTokens": [self.xbox_token]
                },
                "RelyingParty": "rp://api.minecraftservices.com/",
                "TokenType": "JWT"
            },
            headers={"Content-Type": "application/json", "Accept": "application/json"}
        )
        if response.status_code != 200:
            error = response.json()
            if error.get("XErr") == 2148916233:
                raise Exception("No Xbox profile. Create one at xbox.com")
            if error.get("XErr") == 2148916238:
                raise Exception("Child account: needs adult to add to Microsoft Family")
            raise Exception(f"XSTS error: {response.text}")

        self.xsts_token = response.json()["Token"]
        print("[OK] XSTS token obtained")

    def _step4_minecraft(self):
        """Step 4: Exchange XSTS token for Minecraft token."""
        print("[4/5] Minecraft authentication...")

        response = requests.post(
            "https://api.minecraftservices.com/authentication/login_with_xbox",
            json={
                "identityToken": f"XBL3.0 x={self.xbox_user_hash};{self.xsts_token}"
            },
            headers={"Content-Type": "application/json"}
        )
        if response.status_code != 200:
            raise Exception(f"Minecraft auth error: {response.text}")

        self.minecraft_token = response.json()["access_token"]
        print("[OK] Minecraft token obtained")

    def _step5_profile(self):
        """Step 5: Get Minecraft profile (UUID, username)."""
        print("[5/5] Getting profile...")

        response = requests.get(
            "https://api.minecraftservices.com/minecraft/profile",
            headers={"Authorization": f"Bearer {self.minecraft_token}"}
        )
        if response.status_code == 404:
            raise Exception("This Microsoft account doesn't own Minecraft!")
        if response.status_code != 200:
            raise Exception(f"Profile error: {response.text}")

        data = response.json()
        self.uuid = data["id"]
        self.username = data["name"]
        print(f"[OK] Profile: {self.username} ({self.uuid})")

    # =========================================================================
    # TOKEN CACHING
    # =========================================================================

    def _validate_token(self):
        """Check if cached Minecraft token is still valid."""
        try:
            response = requests.get(
                "https://api.minecraftservices.com/minecraft/profile",
                headers={"Authorization": f"Bearer {self.minecraft_token}"},
                timeout=5
            )
            return response.status_code == 200
        except:
            return False

    def _save_token(self):
        """Save token to cache file."""
        try:
            with open(TOKEN_FILE, 'w') as f:
                json.dump({
                    'minecraft_token': self.minecraft_token,
                    'uuid': self.uuid,
                    'username': self.username,
                    'timestamp': time.time()
                }, f)
            print(f"[*] Token saved to {TOKEN_FILE}")
        except Exception as e:
            print(f"[!] Could not save token: {e}")

    def _load_cached_token(self):
        """Load token from cache file if valid (less than 24h old)."""
        try:
            if os.path.exists(TOKEN_FILE):
                with open(TOKEN_FILE, 'r') as f:
                    data = json.load(f)
                    # Token valid for 24 hours
                    if time.time() - data.get('timestamp', 0) < 86400:
                        self.minecraft_token = data['minecraft_token']
                        self.uuid = data['uuid']
                        self.username = data['username']
                        return True
        except:
            pass
        return False


# =============================================================================
# STANDALONE TEST
# =============================================================================

def main():
    """Test authentication flow."""
    auth = MinecraftAuth()
    try:
        result = auth.authenticate()
        print(f"\n=== RESULT ===")
        print(f"Username: {result['username']}")
        print(f"UUID: {result['uuid']}")
        access_token: str = result['access_token']
        print(f"Token: {access_token[:50]}...")
    except Exception as e:
        print(f"\n[ERROR] {e}")


if __name__ == "__main__":
    main()
