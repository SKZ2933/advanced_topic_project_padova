"""
Minecraft Aimbot - Mouse Control Module
Uses player positions captured by mc_proxy.py to automatically aim at targets.

Based on the AimLogic from the AimbotMC Java mod.

Hotkeys:
- O   : Toggle aimbot on/off
- P   : Switch to next target
- ESC : Quit
"""

import math
import time
import sys
import random
import json
import os

# Windows API for mouse control
try:
    import win32api
    import win32con
except ImportError:
    print("[ERROR] pywin32 not installed. Run: pip install pywin32")
    sys.exit(1)

# Keyboard for hotkeys
try:
    import keyboard
except ImportError:
    print("[ERROR] keyboard not installed. Run: pip install keyboard")
    sys.exit(1)


# =============================================================================
# AIM LOGIC (ported from Java)
# =============================================================================

class AimLogic:
    """
    Calculates yaw and pitch angles to look at a target.
    Ported from AimLogic.java in AimbotMC.
    """
    
    PLAYER_EYE_HEIGHT = 1.62   # Player eye position offset
    TARGET_HEAD_OFFSET = 1.4   # Aim at target's head center

    @staticmethod
    def get_rotations(player_x, player_y, player_z, target_x, target_y, target_z):
        """
        Calculate yaw and pitch to look from player position to target.
        
        Returns:
            tuple: (yaw, pitch) in degrees
        """
        # Player eye position
        eye_y = player_y + AimLogic.PLAYER_EYE_HEIGHT
        
        # Direction to target's head
        diff_x = target_x - player_x
        diff_y = (target_y + AimLogic.TARGET_HEAD_OFFSET) - eye_y
        diff_z = target_z - player_z
        
        # Horizontal distance
        diff_xz = math.sqrt(diff_x * diff_x + diff_z * diff_z)
        
        # Calculate angles (Minecraft: 0° = South, yaw increases counter-clockwise)
        yaw = math.degrees(math.atan2(diff_z, diff_x)) - 90.0
        pitch = -math.degrees(math.atan2(diff_y, diff_xz))
        
        return yaw, pitch

    @staticmethod
    def normalize_angle(angle):
        """Normalize angle to [-180, 180] range."""
        while angle > 180:
            angle -= 360
        while angle < -180:
            angle += 360
        return angle

    @staticmethod
    def get_angle_delta(current, target):
        """Get shortest rotation delta between two angles."""
        return AimLogic.normalize_angle(target - current)


# =============================================================================
# HUMANIZED AIM (Anti-Detection)
# =============================================================================

class HumanizedAim:
    """
    Makes aim movements look human-like to avoid anti-cheat detection.
    
    Techniques used:
    - Bezier curves for natural trajectories
    - Ease-in-out acceleration profile
    - Gaussian noise for imperfection
    - Simulated reaction delay
    - Mouse saccades (simulates lifting mouse at edge of mousepad)
    """

    def __init__(self):
        # Smoothing parameters
        self.smoothing_factor = 0.35   # Movement speed (higher = faster)
        self.noise_amplitude = 0.4     # Random jitter in degrees
        self.overshoot_chance = 0.10   # 10% chance to overshoot target
        self.overshoot_amount = 0.05   # 5% overshoot distance
        
        # Current aim state
        self.is_aiming = False
        self.aim_start_time = 0
        self.reaction_delay = 0
        
        # Bezier curve points
        self.start_yaw = 0
        self.start_pitch = 0
        self.control_yaw = 0
        self.control_pitch = 0
        self.target_yaw = 0
        self.target_pitch = 0
        
        # Target tracking
        self.last_target_id = None
        
        # Saccade simulation (mousepad edge lift)
        self.saccade_chance = 0.01
        self.saccade_active = False
        self.saccade_end_time = 0
        self.accumulated_movement = 0
        self.saccade_threshold = 40  # Degrees before saccade likely

    def _generate_reaction_delay(self):
        """Human reaction time: 50-120ms."""
        return random.uniform(0.05, 0.12)

    def _generate_control_point(self, start, target):
        """Generate Bezier control point with natural deviation."""
        midpoint = (start + target) / 2
        max_deviation = min(15, abs(target - start) * 0.3)
        return midpoint + random.uniform(-max_deviation, max_deviation)

    def _ease_in_out(self, t):
        """Sigmoid-like acceleration curve: slow start, fast middle, slow end."""
        if t < 0.5:
            return 2 * t * t
        return 1 - pow(-2 * t + 2, 2) / 2

    def _add_noise(self, value):
        """Add Gaussian noise for imperfect aim."""
        return value + random.gauss(0, self.noise_amplitude * 0.4)

    def _check_saccade(self, move_yaw, move_pitch):
        """
        Simulate mouse saccade (lifting mouse at mousepad edge).
        Returns (move_yaw, move_pitch, is_paused).
        """
        current_time = time.time()
        
        # During saccade: no movement
        if self.saccade_active:
            if current_time < self.saccade_end_time:
                return 0, 0, True
            # End saccade with small correction
            self.saccade_active = False
            self.accumulated_movement = 0
            correction_yaw = random.uniform(-1.5, 1.5)
            correction_pitch = random.uniform(-0.5, 0.5)
            return move_yaw + correction_yaw, move_pitch + correction_pitch, False
        
        # Accumulate movement
        self.accumulated_movement += math.sqrt(move_yaw**2 + move_pitch**2)
        
        # Check if saccade should trigger
        probability = self.saccade_chance
        if self.accumulated_movement > self.saccade_threshold:
            probability = min(0.15, self.saccade_chance * (self.accumulated_movement / self.saccade_threshold))
        
        if random.random() < probability and self.accumulated_movement > 15:
            self.saccade_active = True
            self.saccade_end_time = current_time + random.uniform(0.04, 0.06)
            return 0, 0, True
        
        return move_yaw, move_pitch, False

    def _start_new_aim(self, current_yaw, current_pitch, target_yaw, target_pitch, target_id):
        """Initialize a new aim movement with reaction delay."""
        if target_id != self.last_target_id:
            self.reaction_delay = self._generate_reaction_delay()
            self.aim_start_time = time.time()
            self.last_target_id = target_id
            self.is_aiming = True
            
            # Setup Bezier curve
            self.start_yaw = current_yaw
            self.start_pitch = current_pitch
            self.control_yaw = self._generate_control_point(current_yaw, target_yaw)
            self.control_pitch = self._generate_control_point(current_pitch, target_pitch)
            
            # Optional overshoot
            if random.random() < self.overshoot_chance:
                overshoot = 1 + self.overshoot_amount
                self.target_yaw = current_yaw + (target_yaw - current_yaw) * overshoot
                self.target_pitch = current_pitch + (target_pitch - current_pitch) * overshoot
            else:
                self.target_yaw = target_yaw
                self.target_pitch = target_pitch

    def get_humanized_movement(self, current_yaw, current_pitch, target_yaw, target_pitch, target_id=None):
        """
        Calculate humanized mouse movement.
        
        Returns:
            tuple: (delta_yaw, delta_pitch) to apply, or (0, 0) if waiting
        """
        # Check for new target
        if target_id != self.last_target_id or not self.is_aiming:
            self._start_new_aim(current_yaw, current_pitch, target_yaw, target_pitch, target_id)
        
        # Wait for reaction delay
        elapsed = time.time() - self.aim_start_time
        if elapsed < self.reaction_delay:
            return 0, 0
        
        # Update target (for moving targets)
        self.target_yaw = target_yaw
        self.target_pitch = target_pitch
        
        # Calculate remaining delta
        delta_yaw = AimLogic.get_angle_delta(current_yaw, target_yaw)
        delta_pitch = target_pitch - current_pitch
        distance = math.sqrt(delta_yaw**2 + delta_pitch**2)
        
        # Close enough - stop aiming
        if distance < 0.5:
            self.is_aiming = False
            return 0, 0
        
        # Speed based on distance
        if distance > 30:
            speed_mult = 0.7   # Long distance: fast
        elif distance > 10:
            speed_mult = 1.0   # Medium: full speed
        else:
            speed_mult = 0.6   # Close: precise
        
        # Apply smoothing
        smooth_factor = self.smoothing_factor * speed_mult
        move_yaw = delta_yaw * smooth_factor
        move_pitch = delta_pitch * smooth_factor
        
        # Add noise
        move_yaw = self._add_noise(move_yaw)
        move_pitch = self._add_noise(move_pitch)
        
        # Random speed variation (±20%)
        speed_var = random.uniform(0.8, 1.2)
        move_yaw *= speed_var
        move_pitch *= speed_var
        
        # Apply saccades
        move_yaw, move_pitch, _ = self._check_saccade(move_yaw, move_pitch)
        
        return move_yaw, move_pitch


# =============================================================================
# MOUSE CONTROLLER
# =============================================================================

class MouseController:
    """Controls Windows mouse to move Minecraft camera."""

    def __init__(self):
        # Minecraft sensitivity: ~0.15 degrees per pixel (default sensitivity 0.5)
        self.mc_sensitivity = 0.50

    def move_relative(self, delta_yaw, delta_pitch):
        """Move mouse to rotate camera by specified degrees."""
        # Convert degrees to pixels
        pixels_x = int(delta_yaw / self.mc_sensitivity)
        pixels_y = int(delta_pitch / self.mc_sensitivity)
        
        # Limit movement to prevent snapping
        max_move = 50
        pixels_x = max(-max_move, min(max_move, pixels_x))
        pixels_y = max(-max_move, min(max_move, pixels_y))
        
        if pixels_x != 0 or pixels_y != 0:
            win32api.mouse_event(win32con.MOUSEEVENTF_MOVE, pixels_x, pixels_y, 0, 0)


# =============================================================================
# AIMBOT MAIN CLASS
# =============================================================================

class Aimbot:
    """Main aimbot controller - reads positions from proxy and aims at targets."""

    SHARED_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "aimbot_data.json")

    def __init__(self):
        self.enabled = False
        self.running = True
        self.mouse = MouseController()
        self.humanizer = HumanizedAim()
        self.target_entity_id = None
        self.update_rate = 144  # Hz
        
        # Cached data from proxy
        self._cached_data = {
            'my_position': {'x': 0, 'y': 0, 'z': 0, 'yaw': 0, 'pitch': 0},
            'players': {}
        }
        
        print(f"[*] Data file: {self.SHARED_FILE}")
        print(f"[*] Humanized aim enabled (anti-detection)")

    def _read_shared_data(self):
        """Read player positions from JSON file (written by proxy)."""
        try:
            if os.path.exists(self.SHARED_FILE):
                with open(self.SHARED_FILE, 'r') as f:
                    self._cached_data = json.load(f)
                    return True
        except (json.JSONDecodeError, IOError):
            pass
        return False

    def _get_my_position(self):
        """Get local player position and rotation."""
        self._read_shared_data()
        return self._cached_data.get('my_position', {'x': 0, 'y': 0, 'z': 0, 'yaw': 0, 'pitch': 0})

    def _get_players(self):
        """Get dictionary of other players."""
        self._read_shared_data()
        return self._cached_data.get('players', {})

    def _find_closest_player(self, my_pos):
        """Find the nearest player to us."""
        players = self._get_players()
        if not players:
            return None, None
        
        closest_id = None
        closest_dist = float('inf')
        
        for entity_id, player_data in players.items():
            dx = player_data['x'] - my_pos['x']
            dy = player_data['y'] - my_pos['y']
            dz = player_data['z'] - my_pos['z']
            dist = math.sqrt(dx*dx + dy*dy + dz*dz)
            
            if dist < closest_dist:
                closest_dist = dist
                closest_id = entity_id
        
        return closest_id, players.get(closest_id) if closest_id else None

    def _next_target(self):
        """Switch to next player target."""
        players = self._get_players()
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
            uuid_short = target.get('uuid', '?')[:8]
            print(f"[TARGET] Player ID={self.target_entity_id} UUID={uuid_short}...")

    def _aim_at_target(self):
        """Perform one aim cycle."""
        if not self.enabled:
            return
        
        my_pos = self._get_my_position()
        players = self._get_players()
        
        # Auto-select closest if no target
        if self.target_entity_id is None or self.target_entity_id not in players:
            self.target_entity_id, _ = self._find_closest_player(my_pos)
        
        if self.target_entity_id is None:
            return
        
        target = players.get(self.target_entity_id)
        if not target:
            return
        
        # Calculate ideal aim angles
        target_yaw, target_pitch = AimLogic.get_rotations(
            my_pos['x'], my_pos['y'], my_pos['z'],
            target['x'], target['y'], target['z']
        )
        
        # Current camera angles
        current_yaw = my_pos.get('yaw', 0)
        current_pitch = my_pos.get('pitch', 0)
        
        # Get humanized movement
        move_yaw, move_pitch = self.humanizer.get_humanized_movement(
            current_yaw, current_pitch,
            target_yaw, target_pitch,
            target_id=self.target_entity_id
        )
        
        # Debug output
        delta_yaw = AimLogic.get_angle_delta(current_yaw, target_yaw)
        delta_pitch = target_pitch - current_pitch
        print(f"\r[AIM] delta=({delta_yaw:.1f}°, {delta_pitch:.1f}°) move=({move_yaw:.2f}, {move_pitch:.2f})  ", end="", flush=True)
        
        # Apply movement
        if move_yaw != 0 or move_pitch != 0:
            self.mouse.move_relative(move_yaw, move_pitch)

    def _toggle(self):
        """Toggle aimbot on/off."""
        self.enabled = not self.enabled
        status = "ENABLED" if self.enabled else "DISABLED"
        print(f"\n[AIMBOT] {status}")

    def run(self):
        """Main loop."""
        print("\n" + "=" * 50)
        print("MINECRAFT AIMBOT - Version 1.8.9")
        print("=" * 50)
        print("\nHotkeys:")
        print("  O   - Toggle aimbot on/off")
        print("  P   - Switch target")
        print("  ESC - Quit")
        print("\n[*] Waiting for proxy data...")
        print("    Connect to Minecraft via the proxy")
        print("=" * 50 + "\n")
        
        # Setup hotkeys
        keyboard.on_press_key('o', lambda _: self._toggle())
        keyboard.on_press_key('p', lambda _: self._next_target())
        
        interval = 1.0 / self.update_rate
        
        try:
            while self.running:
                start = time.perf_counter()
                
                if self._get_players() and self.enabled:
                    self._aim_at_target()
                
                # Maintain framerate
                elapsed = time.perf_counter() - start
                if elapsed < interval:
                    time.sleep(interval - elapsed)
                    
        except KeyboardInterrupt:
            pass
        finally:
            keyboard.unhook_all()
            print("\n[*] Aimbot stopped.")


# =============================================================================
# ENTRY POINT
# =============================================================================

def main():
    print("[*] Starting aimbot...")
    print("[!] IMPORTANT: mc_proxy.py must be running first!")
    print("[!] Then connect Minecraft to localhost:25566")
    print()
    
    aimbot = Aimbot()
    aimbot.run()


if __name__ == "__main__":
    main()
