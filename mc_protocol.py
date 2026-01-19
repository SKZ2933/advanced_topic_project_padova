"""
PARSEUR DE PROTOCOLE MINECRAFT
==============================
Gère la lecture des paquets Minecraft :
- VarInt/VarLong
- Compression zlib
- Parsing des paquets de position
"""

import struct
import zlib

def read_varint(data, offset=0):
    """Lit un VarInt depuis les données, retourne (valeur, nouveau_offset)"""
    result = 0
    shift = 0
    while True:
        if offset >= len(data):
            return None, offset
        byte = data[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        if (byte & 0x80) == 0:
            break
        shift += 7
        if shift >= 32:
            return None, offset
    # Conversion en signed si négatif
    if result & (1 << 31):
        result -= (1 << 32)
    return result, offset

def write_varint(value):
    """Écrit un VarInt en bytes"""
    result = b''
    if value < 0:
        value += (1 << 32)
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            byte |= 0x80
        result += bytes([byte])
        if not value:
            break
    return result

def read_string(data, offset):
    """Lit une string Minecraft (VarInt length + UTF-8)"""
    length, offset = read_varint(data, offset)
    if length is None or offset + length > len(data):
        return None, offset
    string = data[offset:offset + length].decode('utf-8')
    return string, offset + length

def read_position(data, offset):
    """Lit une position encodée (X, Y, Z en 64 bits)"""
    if offset + 8 > len(data):
        return None, None, None, offset
    val = struct.unpack('>Q', data[offset:offset + 8])[0]
    x = val >> 38
    y = val & 0xFFF
    z = (val >> 12) & 0x3FFFFFF
    # Conversion en signed
    if x >= (1 << 25): x -= (1 << 26)
    if y >= (1 << 11): y -= (1 << 12)
    if z >= (1 << 25): z -= (1 << 26)
    return x, y, z, offset + 8

def read_double(data, offset):
    """Lit un double (8 bytes)"""
    if offset + 8 > len(data):
        return None, offset
    val = struct.unpack('>d', data[offset:offset + 8])[0]
    return val, offset + 8

def read_float(data, offset):
    """Lit un float (4 bytes)"""
    if offset + 4 > len(data):
        return None, offset
    val = struct.unpack('>f', data[offset:offset + 4])[0]
    return val, offset + 4

def read_short(data, offset):
    """Lit un short signé (2 bytes)"""
    if offset + 2 > len(data):
        return None, offset
    val = struct.unpack('>h', data[offset:offset + 2])[0]
    return val, offset + 2

def read_byte(data, offset):
    """Lit un byte signé"""
    if offset >= len(data):
        return None, offset
    val = data[offset]
    if val > 127:
        val -= 256
    return val, offset + 1

def read_ubyte(data, offset):
    """Lit un byte non signé"""
    if offset >= len(data):
        return None, offset
    return data[offset], offset + 1

def read_uuid(data, offset):
    """Lit un UUID (16 bytes)"""
    if offset + 16 > len(data):
        return None, offset
    uuid_bytes = data[offset:offset + 16]
    uuid_str = uuid_bytes.hex()
    return f"{uuid_str[:8]}-{uuid_str[8:12]}-{uuid_str[12:16]}-{uuid_str[16:20]}-{uuid_str[20:]}", offset + 16


# IDs des paquets (Minecraft 1.8.9 - Play state, Server -> Client)
# Version 47 du protocole
PACKET_IDS = {
    # Entity movement packets - 1.8.9
    0x08: "Player Position And Look",  # Position du joueur local
    0x15: "Entity Relative Move",
    0x17: "Entity Look and Relative Move",
    0x16: "Entity Look",
    0x18: "Entity Teleport",
    0x0C: "Spawn Player",
    0x0E: "Spawn Object",
    0x0F: "Spawn Mob",
    0x12: "Entity Velocity",
}

def read_int(data, offset):
    """Lit un int signé (4 bytes)"""
    if offset + 4 > len(data):
        return None, offset
    val = struct.unpack('>i', data[offset:offset + 4])[0]
    return val, offset + 4


def parse_packet(packet_id, data):
    """Parse un paquet et extrait les infos pertinentes (Minecraft 1.8.9)"""
    offset = 0
    
    if packet_id == 0x15:  # Entity Relative Move (1.8.9)
        entity_id, offset = read_varint(data, offset)
        dx, offset = read_byte(data, offset)
        dy, offset = read_byte(data, offset)
        dz, offset = read_byte(data, offset)
        on_ground, offset = read_ubyte(data, offset)
        return {
            'type': 'position_delta',
            'entity_id': entity_id,
            'dx': dx / 32.0,  # Fixed-point 1.8.9 : position / 32
            'dy': dy / 32.0,
            'dz': dz / 32.0
        }
    
    elif packet_id == 0x17:  # Entity Look and Relative Move (1.8.9)
        entity_id, offset = read_varint(data, offset)
        dx, offset = read_byte(data, offset)
        dy, offset = read_byte(data, offset)
        dz, offset = read_byte(data, offset)
        yaw, offset = read_ubyte(data, offset)
        pitch, offset = read_ubyte(data, offset)
        on_ground, offset = read_ubyte(data, offset)
        return {
            'type': 'position_rotation_delta',
            'entity_id': entity_id,
            'dx': dx / 32.0,
            'dy': dy / 32.0,
            'dz': dz / 32.0,
            'yaw': yaw * 360 / 256,
            'pitch': pitch * 360 / 256
        }
    
    elif packet_id == 0x18:  # Entity Teleport (1.8.9 - position en Fixed-Point int)
        entity_id, offset = read_varint(data, offset)
        x, offset = read_int(data, offset)
        y, offset = read_int(data, offset)
        z, offset = read_int(data, offset)
        yaw, offset = read_ubyte(data, offset)
        pitch, offset = read_ubyte(data, offset)
        on_ground, offset = read_ubyte(data, offset)
        return {
            'type': 'teleport',
            'entity_id': entity_id,
            'x': x / 32.0,  # Fixed-point 1.8.9
            'y': y / 32.0,
            'z': z / 32.0,
            'yaw': yaw * 360 / 256,
            'pitch': pitch * 360 / 256
        }
    
    elif packet_id == 0x0C:  # Spawn Player (1.8.9 - position en Fixed-Point int)
        entity_id, offset = read_varint(data, offset)
        uuid, offset = read_uuid(data, offset)
        x, offset = read_int(data, offset)
        y, offset = read_int(data, offset)
        z, offset = read_int(data, offset)
        yaw, offset = read_ubyte(data, offset)
        pitch, offset = read_ubyte(data, offset)
        return {
            'type': 'spawn_player',
            'entity_id': entity_id,
            'uuid': uuid,
            'x': x / 32.0,  # Fixed-point 1.8.9
            'y': y / 32.0,
            'z': z / 32.0
        }
    
    elif packet_id == 0x08:  # Player Position And Look (1.8.9)
        # Position du joueur local envoyée par le serveur
        x, offset = read_double(data, offset)
        y, offset = read_double(data, offset)
        z, offset = read_double(data, offset)
        yaw, offset = read_float(data, offset)
        pitch, offset = read_float(data, offset)
        flags, offset = read_ubyte(data, offset)
        return {
            'type': 'my_position',
            'x': x,
            'y': y,
            'z': z,
            'yaw': yaw,
            'pitch': pitch,
            'flags': flags
        }
    
    return None


def parse_client_packet(packet_id, data):
    """Parse les paquets CLIENT -> SERVEUR pour tracker la position et orientation du joueur local (1.8.9)"""
    offset = 0
    
    if packet_id == 0x04:  # Player Position (C->S)
        # x: double, y: double, z: double, onGround: bool
        x, offset = read_double(data, offset)
        y, offset = read_double(data, offset)
        z, offset = read_double(data, offset)
        on_ground, offset = read_ubyte(data, offset)
        return {
            'type': 'client_position',
            'x': x,
            'y': y,
            'z': z
        }
    
    elif packet_id == 0x05:  # Player Look (C->S)
        # yaw: float, pitch: float, onGround: bool
        yaw, offset = read_float(data, offset)
        pitch, offset = read_float(data, offset)
        on_ground, offset = read_ubyte(data, offset)
        return {
            'type': 'client_look',
            'yaw': yaw,
            'pitch': pitch
        }
    
    elif packet_id == 0x06:  # Player Position And Look (C->S)
        # x: double, y: double, z: double, yaw: float, pitch: float, onGround: bool
        x, offset = read_double(data, offset)
        y, offset = read_double(data, offset)
        z, offset = read_double(data, offset)
        yaw, offset = read_float(data, offset)
        pitch, offset = read_float(data, offset)
        on_ground, offset = read_ubyte(data, offset)
        return {
            'type': 'client_position_look',
            'x': x,
            'y': y,
            'z': z,
            'yaw': yaw,
            'pitch': pitch
        }
    
    return None
