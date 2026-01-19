"""
AIMBOT PYTHON - CONTRÔLE SOURIS
===============================
Utilise les positions des joueurs capturées par mc_proxy.py
pour orienter automatiquement la caméra vers un joueur cible.

Basé sur la logique de AimLogic.java du projet AimbotMC.

Raccourcis:
- F6 : Activer/Désactiver l'aimbot
- F7 : Changer de cible (joueur suivant)
- ESC : Quitter
"""

import math
import time
import threading
import sys
import random

# Import Windows API pour contrôle souris
try:
    import win32api
    import win32con
except ImportError:
    print("[ERREUR] pywin32 non installé. Exécutez: pip install pywin32")
    sys.exit(1)

# Import clavier pour les raccourcis
try:
    import keyboard
except ImportError:
    print("[ERREUR] keyboard non installé. Exécutez: pip install keyboard")
    sys.exit(1)


class AimLogic:
    """
    Port Python de AimLogic.java
    Calcule les angles yaw et pitch pour viser une cible
    """
    
    # Hauteur des yeux du joueur (position Y + eye_height)
    PLAYER_EYE_HEIGHT = 1.62
    # Offset pour viser la tête de la cible
    TARGET_HEAD_OFFSET = 1.4
    
    @staticmethod
    def get_rotations(player_x, player_y, player_z, target_x, target_y, target_z):
        """
        Calcule le yaw et pitch pour regarder vers la cible
        
        Args:
            player_x, player_y, player_z: Position du joueur local
            target_x, target_y, target_z: Position de la cible
            
        Returns:
            tuple: (yaw, pitch) en degrés
        """
        # Position des yeux du joueur
        eye_y = player_y + AimLogic.PLAYER_EYE_HEIGHT
        
        # Différence de position vers la cible (centre de la tête)
        diff_x = target_x - player_x
        diff_y = (target_y + AimLogic.TARGET_HEAD_OFFSET) - eye_y
        diff_z = target_z - player_z
        
        # Distance horizontale
        diff_xz = math.sqrt(diff_x * diff_x + diff_z * diff_z)
        
        # Calcul des angles (identique à Java)
        # atan2(z, x) donne l'angle dans le plan XZ
        # -90° car Minecraft utilise un système où 0° = Sud
        yaw = math.degrees(math.atan2(diff_z, diff_x)) - 90.0
        
        # Pitch: angle vertical (négatif car regarder vers le haut = pitch négatif)
        pitch = -math.degrees(math.atan2(diff_y, diff_xz))
        
        return yaw, pitch
    
    @staticmethod
    def normalize_angle(angle):
        """Normalise un angle entre -180 et 180 degrés"""
        while angle > 180:
            angle -= 360
        while angle < -180:
            angle += 360
        return angle
    
    @staticmethod
    def get_angle_delta(current, target):
        """Calcule le delta entre deux angles (chemin le plus court)"""
        delta = target - current
        return AimLogic.normalize_angle(delta)


class HumanizedAim:
    """
    Système de lissage humanisé pour éviter la détection par anti-cheat.
    
    Techniques utilisées:
    - Courbes de Bézier quadratiques pour trajectoires naturelles
    - Profil d'accélération ease-in-out (sigmoidale)
    - Bruit gaussien pour imperfections
    - Délai de réaction humain simulé
    - Oscillation autour de la cible (overshoot)
    """
    
    def __init__(self):
        # Configuration du lissage - AJUSTÉ pour meilleure réactivité
        self.smoothing_factor = 0.35  # Augmenté: plus rapide mais toujours naturel
        self.noise_amplitude = 0.4    # Degrés de bruit max (réduit un peu)
        self.overshoot_chance = 0.10  # 10% de chance de dépasser
        self.overshoot_amount = 0.05  # 5% de dépassement
        
        # État du mouvement courant
        self.is_aiming = False
        self.aim_start_time = 0
        self.reaction_delay = 0
        self.movement_progress = 0
        
        # Points de la courbe de Bézier
        self.start_yaw = 0
        self.start_pitch = 0
        self.control_yaw = 0
        self.control_pitch = 0
        self.target_yaw = 0
        self.target_pitch = 0
        
        # Dernière cible pour détecter les changements
        self.last_target_id = None
        
        # === SACCADES (simulation bord de tapis) ===
        self.saccade_chance = 0.01        # 1% de chance par frame de déclencher une saccade
        self.saccade_active = False       # Une saccade est en cours
        self.saccade_end_time = 0         # Fin de la saccade
        self.saccade_duration_min = 0.04  # 40ms min
        self.saccade_duration_max = 0.06  # 60ms max
        self.accumulated_movement = 0     # Mouvement accumulé (simule la distance sur le tapis)
        self.saccade_threshold = 40       # Degrés avant saccade probable
    
    def generate_reaction_delay(self):
        """Génère un délai de réaction humain aléatoire (50-120ms) - réduit pour réactivité"""
        return random.uniform(0.05, 0.12)
    
    def generate_control_point(self, start, target):
        """
        Génère un point de contrôle pour la courbe de Bézier.
        Ajoute une déviation naturelle au milieu du trajet.
        """
        midpoint = (start + target) / 2
        # Déviation de ±15° maximum, proportionnelle à la distance
        distance = abs(target - start)
        max_deviation = min(15, distance * 0.3)
        deviation = random.uniform(-max_deviation, max_deviation)
        return midpoint + deviation
    
    def ease_in_out(self, t):
        """
        Fonction d'accélération ease-in-out (sigmoidale).
        Démarre lent, accélère au milieu, ralentit à la fin.
        
        Args:
            t: Progression de 0 à 1
        Returns:
            Valeur transformée entre 0 et 1
        """
        if t < 0.5:
            # Ease-in: accélération
            return 2 * t * t
        else:
            # Ease-out: décélération
            return 1 - pow(-2 * t + 2, 2) / 2
    
    def bezier_quadratic(self, t, p0, p1, p2):
        """
        Calcule un point sur une courbe de Bézier quadratique.
        
        Args:
            t: Progression (0-1)
            p0: Point de départ
            p1: Point de contrôle
            p2: Point d'arrivée
        """
        inv_t = 1 - t
        return inv_t * inv_t * p0 + 2 * inv_t * t * p1 + t * t * p2
    
    def add_gaussian_noise(self, value):
        """Ajoute du bruit gaussien pour des imperfections naturelles"""
        noise = random.gauss(0, self.noise_amplitude * 0.4)
        return value + noise
    
    def check_saccade(self, move_yaw, move_pitch):
        """
        Vérifie et gère les saccades (simulation bord de tapis).
        
        Quand le joueur atteint le bord de son tapis, il doit lever la souris
        et la replacer, causant une brève pause + léger décalage.
        
        Returns:
            tuple: (move_yaw, move_pitch, is_paused) - mouvement modifié et état de pause
        """
        current_time = time.time()
        
        # Si une saccade est en cours, on pause le mouvement
        if self.saccade_active:
            if current_time < self.saccade_end_time:
                # Pendant la saccade: pas de mouvement (souris levée)
                return 0, 0, True
            else:
                # Fin de la saccade: reset et petit décalage de "replacement"
                self.saccade_active = False
                self.accumulated_movement = 0
                # Petit mouvement de correction aléatoire (replacement imparfait)
                correction_yaw = random.uniform(-1.5, 1.5)
                correction_pitch = random.uniform(-0.5, 0.5)
                return move_yaw + correction_yaw, move_pitch + correction_pitch, False
        
        # Accumuler le mouvement
        movement_magnitude = math.sqrt(move_yaw**2 + move_pitch**2)
        self.accumulated_movement += movement_magnitude
        
        # Vérifier si on déclenche une saccade
        # Plus on a bougé, plus la chance augmente
        saccade_probability = self.saccade_chance
        if self.accumulated_movement > self.saccade_threshold:
            # Augmenter la probabilité au-delà du seuil
            saccade_probability = min(0.15, self.saccade_chance * (self.accumulated_movement / self.saccade_threshold))
        
        if random.random() < saccade_probability and self.accumulated_movement > 15:
            # Déclencher une saccade
            self.saccade_active = True
            duration = random.uniform(self.saccade_duration_min, self.saccade_duration_max)
            self.saccade_end_time = current_time + duration
            return 0, 0, True  # Premier frame de saccade: pas de mouvement
        
        return move_yaw, move_pitch, False
    
    def start_new_aim(self, current_yaw, current_pitch, target_yaw, target_pitch, target_id=None):
        """
        Démarre un nouveau mouvement de visée avec délai de réaction.
        """
        # Si c'est une nouvelle cible, simuler un délai de réaction
        if target_id != self.last_target_id:
            self.reaction_delay = self.generate_reaction_delay()
            self.aim_start_time = time.time()
            self.last_target_id = target_id
            self.is_aiming = True
            self.movement_progress = 0
            
            # Initialiser la courbe de Bézier
            self.start_yaw = current_yaw
            self.start_pitch = current_pitch
            self.control_yaw = self.generate_control_point(current_yaw, target_yaw)
            self.control_pitch = self.generate_control_point(current_pitch, target_pitch)
            
            # Appliquer overshoot potentiel
            if random.random() < self.overshoot_chance:
                overshoot = 1 + self.overshoot_amount
                self.target_yaw = current_yaw + (target_yaw - current_yaw) * overshoot
                self.target_pitch = current_pitch + (target_pitch - current_pitch) * overshoot
            else:
                self.target_yaw = target_yaw
                self.target_pitch = target_pitch
    
    def get_humanized_movement(self, current_yaw, current_pitch, target_yaw, target_pitch, target_id=None):
        """
        Calcule le mouvement humanisé à appliquer.
        
        Returns:
            tuple: (delta_yaw, delta_pitch) à appliquer, ou (0, 0) si en délai
        """
        current_time = time.time()
        
        # Vérifier si nouvelle cible
        if target_id != self.last_target_id or not self.is_aiming:
            self.start_new_aim(current_yaw, current_pitch, target_yaw, target_pitch, target_id)
        
        # Vérifier le délai de réaction
        elapsed = current_time - self.aim_start_time
        if elapsed < self.reaction_delay:
            return 0, 0  # Encore en délai de réaction
        
        # Calculer le delta restant
        delta_yaw = AimLogic.get_angle_delta(current_yaw, target_yaw)
        delta_pitch = target_pitch - current_pitch
        distance = math.sqrt(delta_yaw**2 + delta_pitch**2)
        
        # Si très proche, arrêter
        if distance < 0.5:
            self.is_aiming = False
            return 0, 0
        
        # Appliquer le profil d'accélération - AJUSTÉ pour meilleure réactivité
        # La vitesse dépend de la distance: plus loin = plus rapide
        if distance > 30:
            speed_mult = 0.7  # Grandes distances: rapide
        elif distance > 10:
            speed_mult = 1.0  # Moyennes distances: vitesse max
        else:
            speed_mult = 0.6  # Petites distances: précision (mais pas trop lent)
        
        # Calculer le mouvement avec lissage
        smooth_factor = self.smoothing_factor * speed_mult
        move_yaw = delta_yaw * smooth_factor
        move_pitch = delta_pitch * smooth_factor
        
        # Ajouter du bruit gaussien
        move_yaw = self.add_gaussian_noise(move_yaw)
        move_pitch = self.add_gaussian_noise(move_pitch)
        
        # Variation aléatoire de la vitesse (±20%)
        speed_variation = random.uniform(0.8, 1.2)
        move_yaw *= speed_variation
        move_pitch *= speed_variation
        
        # Appliquer les saccades (simulation bord de tapis)
        move_yaw, move_pitch, is_saccade = self.check_saccade(move_yaw, move_pitch)
        
        return move_yaw, move_pitch


class MouseController:
    """
    Contrôle la souris Windows pour orienter la caméra Minecraft
    """
    
    def __init__(self):
        """
        Minecraft utilise environ 0.15 degrés par pixel de mouvement souris
        (avec sensibilité par défaut = 0.5 dans les options)
        """
        # Facteur: combien de degrés par pixel de mouvement souris
        # Valeur Minecraft par défaut ≈ 0.15 (peut varier selon sensibilité in-game)
        self.mc_sensitivity = 0.50
    
    def move_relative(self, delta_yaw, delta_pitch):
        """
        Déplace la souris pour tourner de delta_yaw/delta_pitch degrés
        
        Args:
            delta_yaw: Rotation horizontale désirée en degrés
            delta_pitch: Rotation verticale désirée en degrés
        """
        # Convertir degrés en pixels: pixels = degrés / sensibilité_mc
        pixels_x = int(delta_yaw / self.mc_sensitivity)
        pixels_y = int(delta_pitch / self.mc_sensitivity)
        
        # Limiter les mouvements pour éviter les snaps violents
        max_move = 50
        pixels_x = max(-max_move, min(max_move, pixels_x))
        pixels_y = max(-max_move, min(max_move, pixels_y))
        
        if pixels_x != 0 or pixels_y != 0:
            win32api.mouse_event(win32con.MOUSEEVENTF_MOVE, pixels_x, pixels_y, 0, 0)
    
    def smooth_aim(self, delta_yaw, delta_pitch, smoothing=0.3):
        """
        Applique un lissage pour des mouvements plus naturels
        
        Args:
            delta_yaw: Delta yaw en degrés
            delta_pitch: Delta pitch en degrés
            smoothing: Facteur de lissage (0-1, plus petit = plus lent)
        """
        # Appliquer seulement une fraction du mouvement
        smooth_yaw = delta_yaw * smoothing
        smooth_pitch = delta_pitch * smoothing
        
        self.move_relative(smooth_yaw, smooth_pitch)


import json
import os

class Aimbot:
    """
    Aimbot principal qui combine tracking et contrôle souris
    """
    
    # Fichier JSON partagé avec le proxy
    SHARED_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "aimbot_data.json")
    
    def __init__(self):
        self.enabled = False
        self.running = True
        self.mouse = MouseController()
        self.humanizer = HumanizedAim()  # Système de lissage anti-détection
        self.target_entity_id = None
        
        # Configuration
        self.update_rate = 144  # Hz
        self.max_fov = 180  # Degrés - angle max pour lock
        
        # Cache des données
        self._cached_data = {
            'my_position': {'x': 0, 'y': 0, 'z': 0, 'yaw': 0, 'pitch': 0},
            'players': {}
        }
        
        print(f"[*] Fichier de données: {self.SHARED_FILE}")
        print(f"[*] Lissage humanisé activé (anti-détection)")
    
    def _read_shared_data(self):
        """Lit les données depuis le fichier JSON partagé"""
        try:
            if os.path.exists(self.SHARED_FILE):
                with open(self.SHARED_FILE, 'r') as f:
                    data = json.load(f)
                    self._cached_data = data
                    return True
        except (json.JSONDecodeError, IOError):
            pass
        return False
    
    def get_my_position(self):
        """Récupère la position du joueur local"""
        self._read_shared_data()
        return self._cached_data.get('my_position', {'x': 0, 'y': 0, 'z': 0, 'yaw': 0, 'pitch': 0})
    
    def get_players(self):
        """Récupère la liste des joueurs"""
        self._read_shared_data()
        return self._cached_data.get('players', {})
    
    def find_closest_player(self, my_pos):
        """Trouve le joueur le plus proche"""
        players = self.get_players()
        if not players:
            return None, None
        
        closest_id = None
        closest_dist = float('inf')
        
        for eid, pdata in players.items():
            dx = pdata['x'] - my_pos['x']
            dy = pdata['y'] - my_pos['y']
            dz = pdata['z'] - my_pos['z']
            dist = math.sqrt(dx*dx + dy*dy + dz*dz)
            
            if dist < closest_dist:
                closest_dist = dist
                closest_id = eid
        
        if closest_id:
            return closest_id, players[closest_id]
        return None, None
    
    def get_next_target(self):
        """Passe au joueur suivant"""
        players = self.get_players()
        if not players:
            self.target_entity_id = None
            return
        
        player_ids = sorted(players.keys())
        
        if self.target_entity_id is None or self.target_entity_id not in player_ids:
            self.target_entity_id = player_ids[0]
        else:
            idx = player_ids.index(self.target_entity_id)
            self.target_entity_id = player_ids[(idx + 1) % len(player_ids)]
        
        target = players.get(self.target_entity_id)
        if target:
            uuid_short = target.get('uuid', '?')[:8] if 'uuid' in target else '?'
            print(f"[CIBLE] Joueur ID={self.target_entity_id} UUID={uuid_short}...")
    
    def aim_at_target(self):
        """Effectue un cycle de visée - TRACKING EN TEMPS RÉEL"""
        if not self.enabled:
            return
        
        my_pos = self.get_my_position()
        players = self.get_players()
        
        # Si pas de cible ou cible invalide, prendre le plus proche
        if self.target_entity_id is None or self.target_entity_id not in players:
            self.target_entity_id, _ = self.find_closest_player(my_pos)
        
        if self.target_entity_id is None:
            return
        
        target = players.get(self.target_entity_id)
        if not target:
            return
        
        # Calculer l'angle DÉSIRÉ vers la cible (où on DEVRAIT regarder)
        target_yaw, target_pitch = AimLogic.get_rotations(
            my_pos['x'], my_pos['y'], my_pos['z'],
            target['x'], target['y'], target['z']
        )
        
        # Orientation ACTUELLE du joueur (en temps réel depuis le proxy)
        current_yaw = my_pos.get('yaw', 0)
        current_pitch = my_pos.get('pitch', 0)
        
        # Utiliser le système de lissage humanisé (anti-détection)
        # Calcule un mouvement naturel avec:
        # - Délai de réaction humain
        # - Courbe de vitesse ease-in-out
        # - Bruit gaussien
        # - Variation aléatoire
        move_yaw, move_pitch = self.humanizer.get_humanized_movement(
            current_yaw, current_pitch,
            target_yaw, target_pitch,
            target_id=self.target_entity_id
        )
        
        # DEBUG: afficher les valeurs
        delta_yaw = AimLogic.get_angle_delta(current_yaw, target_yaw)
        delta_pitch = target_pitch - current_pitch
        print(f"\r[HUMANIZED] delta=({delta_yaw:.1f}°, {delta_pitch:.1f}°) move=({move_yaw:.2f}, {move_pitch:.2f})  ", end="", flush=True)
        
        # Si aucun mouvement (en délai de réaction ou proche de la cible)
        if move_yaw == 0 and move_pitch == 0:
            return
        
        # Appliquer le mouvement de souris humanisé
        self.mouse.move_relative(move_yaw, move_pitch)
    
    def toggle(self):
        """Active/désactive l'aimbot"""
        self.enabled = not self.enabled
        status = "ACTIVÉ" if self.enabled else "DÉSACTIVÉ"
        print(f"\n[AIMBOT] {status}")
    
    def run(self):
        """Boucle principale"""
        print("\n" + "=" * 50)
        print("AIMBOT PYTHON - MINECRAFT 1.8.9")
        print("=" * 50)
        print("\nRaccourcis:")
        print("  O   - Activer/Désactiver l'aimbot")
        print("  P   - Changer de cible")
        print("  ESC - Quitter")
        print("\n[*] En attente de données du proxy...")
        print("    Connectez-vous à Minecraft via le proxy")
        print("=" * 50 + "\n")
        
        # Configurer les raccourcis clavier
        keyboard.on_press_key('o', lambda _: self.toggle())
        keyboard.on_press_key('p', lambda _: self.get_next_target())
        
        interval = 1.0 / self.update_rate
        
        try:
            while self.running:
                start = time.perf_counter()
                
                # Afficher le statut périodiquement
                players = self.get_players()
                if players and self.enabled:
                    self.aim_at_target()
                
                # Maintenir le framerate
                elapsed = time.perf_counter() - start
                if elapsed < interval:
                    time.sleep(interval - elapsed)
                    
        except KeyboardInterrupt:
            pass
        finally:
            keyboard.unhook_all()
            print("\n[*] Aimbot arrêté.")


def main():
    print("[*] Démarrage de l'aimbot...")
    print("[!] IMPORTANT: Le proxy mc_proxy.py doit être lancé en premier!")
    print("[!] Puis connectez Minecraft à localhost:25566")
    print()
    
    aimbot = Aimbot()
    aimbot.run()


if __name__ == "__main__":
    main()
