"""
AUTHENTIFICATION MICROSOFT/MOJANG
==================================
Gère l'authentification OAuth pour obtenir un token Minecraft valide.

Flux d'authentification:
1. Microsoft OAuth (Device Code Flow)
2. Xbox Live Token
3. XSTS Token  
4. Minecraft Token

Usage:
    from auth_microsoft import MinecraftAuth
    
    auth = MinecraftAuth()
    token_data = auth.authenticate()  # Ouvre navigateur + affiche code
    print(token_data['access_token'])
    print(token_data['uuid'])
    print(token_data['username'])
"""

import requests
import json
import os
import time
import webbrowser

# Fichier pour stocker le token (évite de se reconnecter à chaque fois)
TOKEN_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mc_token.json")

# Client ID Azure pour l'authentification Minecraft
# Utilise le client ID public de Prism Launcher (open source, approuvé par Microsoft)
MICROSOFT_CLIENT_ID = "c36a9fb6-4f2a-41ff-90bd-ae7cc92031eb"

class MinecraftAuth:
    """
    Authentification Microsoft → Minecraft
    """
    
    def __init__(self):
        self.microsoft_token = None
        self.xbox_token = None
        self.xsts_token = None
        self.minecraft_token = None
        self.uuid = None
        self.username = None
    
    def authenticate(self, force_refresh=False):
        """
        Authentifie l'utilisateur et retourne les informations de session.
        
        Args:
            force_refresh: Si True, ignore le token sauvegardé
            
        Returns:
            dict: {access_token, uuid, username}
        """
        # Essayer de charger un token existant
        if not force_refresh and self._load_cached_token():
            print("[AUTH] Token Minecraft chargé depuis le cache")
            if self._validate_minecraft_token():
                return {
                    'access_token': self.minecraft_token,
                    'uuid': self.uuid,
                    'username': self.username
                }
            print("[AUTH] Token expiré, re-authentification...")
        
        # Authentification complète
        print("\n" + "=" * 50)
        print("AUTHENTIFICATION MICROSOFT")
        print("=" * 50)
        
        # Étape 1: Microsoft OAuth
        self._microsoft_oauth()
        
        # Étape 2: Xbox Live
        self._xbox_live_auth()
        
        # Étape 3: XSTS
        self._xsts_auth()
        
        # Étape 4: Minecraft
        self._minecraft_auth()
        
        # Étape 5: Profil Minecraft
        self._get_minecraft_profile()
        
        # Sauvegarder le token
        self._save_token()
        
        print("\n[OK] Authentification réussie!")
        print(f"    Joueur: {self.username}")
        print(f"    UUID: {self.uuid}")
        print("=" * 50 + "\n")
        
        return {
            'access_token': self.minecraft_token,
            'uuid': self.uuid,
            'username': self.username
        }
    
    def _microsoft_oauth(self):
        """Étape 1: Device Code Flow OAuth Microsoft"""
        print("\n[1/5] Authentification Microsoft...")
        
        # Demander un device code
        response = requests.post(
            "https://login.microsoftonline.com/consumers/oauth2/v2.0/devicecode",
            data={
                "client_id": MICROSOFT_CLIENT_ID,
                "scope": "XboxLive.signin offline_access"
            }
        )
        
        if response.status_code != 200:
            raise Exception(f"Erreur OAuth: {response.text}")
        
        data = response.json()
        device_code = data["device_code"]
        user_code = data["user_code"]
        verification_uri = data["verification_uri"]
        expires_in = data["expires_in"]
        interval = data.get("interval", 5)
        
        print(f"\n>>> Ouvrez votre navigateur et allez sur: {verification_uri}")
        print(f">>> Entrez le code: {user_code}")
        print()
        
        # Ouvrir le navigateur automatiquement
        webbrowser.open(verification_uri)
        
        # Attendre que l'utilisateur s'authentifie
        print("[*] En attente de l'authentification...")
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
                print("[OK] Authentification Microsoft réussie!")
                return
            
            if data.get("error") == "authorization_declined":
                raise Exception("Authentification refusée par l'utilisateur")
            
            if data.get("error") not in ["authorization_pending", "slow_down"]:
                raise Exception(f"Erreur OAuth: {data}")
        
        raise Exception("Timeout: l'authentification a pris trop de temps")
    
    def _xbox_live_auth(self):
        """Étape 2: Échange token Microsoft → Xbox Live"""
        print("[2/5] Authentification Xbox Live...")
        
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
            raise Exception(f"Erreur Xbox Live: {response.text}")
        
        data = response.json()
        self.xbox_token = data["Token"]
        self.xbox_user_hash = data["DisplayClaims"]["xui"][0]["uhs"]
        print("[OK] Token Xbox Live obtenu")
    
    def _xsts_auth(self):
        """Étape 3: Échange Xbox Live → XSTS"""
        print("[3/5] Authentification XSTS...")
        
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
                raise Exception("Ce compte Microsoft n'a pas de profil Xbox. Créez-en un sur xbox.com")
            if error.get("XErr") == 2148916238:
                raise Exception("Compte enfant: demandez à un adulte d'ajouter ce compte à une famille Microsoft")
            raise Exception(f"Erreur XSTS: {response.text}")
        
        data = response.json()
        self.xsts_token = data["Token"]
        print("[OK] Token XSTS obtenu")
    
    def _minecraft_auth(self):
        """Étape 4: Échange XSTS → Token Minecraft"""
        print("[4/5] Authentification Minecraft...")
        
        response = requests.post(
            "https://api.minecraftservices.com/authentication/login_with_xbox",
            json={
                "identityToken": f"XBL3.0 x={self.xbox_user_hash};{self.xsts_token}"
            },
            headers={"Content-Type": "application/json"}
        )
        
        if response.status_code != 200:
            raise Exception(f"Erreur Minecraft Auth: {response.text}")
        
        data = response.json()
        self.minecraft_token = data["access_token"]
        print("[OK] Token Minecraft obtenu")
    
    def _get_minecraft_profile(self):
        """Étape 5: Récupérer le profil Minecraft (UUID, username)"""
        print("[5/5] Récupération du profil...")
        
        response = requests.get(
            "https://api.minecraftservices.com/minecraft/profile",
            headers={"Authorization": f"Bearer {self.minecraft_token}"}
        )
        
        if response.status_code == 404:
            raise Exception("Ce compte Microsoft ne possède pas Minecraft!")
        
        if response.status_code != 200:
            raise Exception(f"Erreur profil: {response.text}")
        
        data = response.json()
        self.uuid = data["id"]
        self.username = data["name"]
        print(f"[OK] Profil: {self.username} ({self.uuid})")
    
    def _validate_minecraft_token(self):
        """Vérifie si le token Minecraft est encore valide"""
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
        """Sauvegarde le token dans un fichier"""
        try:
            with open(TOKEN_FILE, 'w') as f:
                json.dump({
                    'minecraft_token': self.minecraft_token,
                    'uuid': self.uuid,
                    'username': self.username,
                    'timestamp': time.time()
                }, f)
            print(f"[*] Token sauvegardé dans {TOKEN_FILE}")
        except Exception as e:
            print(f"[!] Impossible de sauvegarder le token: {e}")
    
    def _load_cached_token(self):
        """Charge le token depuis le cache"""
        try:
            if os.path.exists(TOKEN_FILE):
                with open(TOKEN_FILE, 'r') as f:
                    data = json.load(f)
                    # Vérifier si le token n'est pas trop vieux (24h max)
                    if time.time() - data.get('timestamp', 0) < 86400:
                        self.minecraft_token = data['minecraft_token']
                        self.uuid = data['uuid']
                        self.username = data['username']
                        return True
        except:
            pass
        return False


def main():
    """Test de l'authentification"""
    auth = MinecraftAuth()
    try:
        result = auth.authenticate()
        print("\n=== RÉSULTAT ===")
        print(f"Username: {result['username']}")
        print(f"UUID: {result['uuid']}")
        print(f"Token: {result['access_token'][:50]}...")
    except Exception as e:
        print(f"\n[ERREUR] {e}")


if __name__ == "__main__":
    main()
