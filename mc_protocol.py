"""
Minecraft Protocol Parser for version 1.8.9 (Protocol 47)
Handles VarInt encoding and packet parsing for position tracking.
"""

import struct

# =============================================================================
# VARINT ENCODING/DECODING
# =============================================================================

def read_varint(data, offset=0):
    """Read a VarInt from data. Returns (value, new_offset) or (None, offset) on error."""
    result = 0
    shift = 0
    while True:
        if offset >= len(data):
            return None, offset
        byte = data[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            break
        shift += 7
        if shift >= 32:
            return None, offset
    # Convert to signed 32-bit
    if result & (1 << 31):
        result -= (1 << 32)
    return result, offset


def write_varint(value):
    """Encode an integer as VarInt bytes."""
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


# =============================================================================
# DATA TYPE READERS
# =============================================================================

def read_string(data, offset):
    """Read a Minecraft string (VarInt length + UTF-8 data)."""
    length, offset = read_varint(data, offset)
    if length is None or offset + length > len(data):
        return None, offset
    return data[offset:offset + length].decode('utf-8'), offset + length


def read_position(data, offset):
    """Read packed position (X/Y/Z in 64 bits). Returns (x, y, z, new_offset)."""
    if offset + 8 > len(data):
        return None, None, None, offset
    val = struct.unpack('>Q', data[offset:offset + 8])[0]
    x = val >> 38
    y = val & 0xFFF
    z = (val >> 12) & 0x3FFFFFF
    # Convert to signed
    if x >= (1 << 25): x -= (1 << 26)
    if y >= (1 << 11): y -= (1 << 12)
    if z >= (1 << 25): z -= (1 << 26)
    return x, y, z, offset + 8


def read_double(data, offset):
    """Read 8-byte double."""
    if offset + 8 > len(data):
        return None, offset
    return struct.unpack('>d', data[offset:offset + 8])[0], offset + 8


def read_float(data, offset):
    """Read 4-byte float."""
    if offset + 4 > len(data):
        return None, offset
    return struct.unpack('>f', data[offset:offset + 4])[0], offset + 4


def read_int(data, offset):
    """Read 4-byte signed integer."""
    if offset + 4 > len(data):
        return None, offset
    return struct.unpack('>i', data[offset:offset + 4])[0], offset + 4


def read_short(data, offset):
    """Read 2-byte signed short."""
    if offset + 2 > len(data):
        return None, offset
    return struct.unpack('>h', data[offset:offset + 2])[0], offset + 2


def read_byte(data, offset):
    """Read signed byte (-128 to 127)."""
    if offset >= len(data):
        return None, offset
    val = data[offset]
    return (val - 256 if val > 127 else val), offset + 1


def read_ubyte(data, offset):
    """Read unsigned byte (0 to 255)."""
    if offset >= len(data):
        return None, offset
    return data[offset], offset + 1


def read_uuid(data, offset):
    """Read 16-byte UUID and format as string."""
    if offset + 16 > len(data):
        return None, offset
    hex_str = data[offset:offset + 16].hex()
    formatted = f"{hex_str[:8]}-{hex_str[8:12]}-{hex_str[12:16]}-{hex_str[16:20]}-{hex_str[20:]}"
    return formatted, offset + 16


# =============================================================================
# PACKET IDS (Minecraft 1.8.9 - Play State, Server -> Client)
# =============================================================================

PACKET_IDS = {
    0x08: "Player Position And Look",   # Server tells client their position
    0x0C: "Spawn Player",               # Another player spawned nearby
    0x0E: "Spawn Object",
    0x0F: "Spawn Mob",
    0x12: "Entity Velocity",
    0x15: "Entity Relative Move",       # Entity moved by delta
    0x16: "Entity Look",
    0x17: "Entity Look and Relative Move",
    0x18: "Entity Teleport",            # Entity teleported to absolute position
}


# =============================================================================
# PACKET PARSERS (Server -> Client)
# =============================================================================

def parse_packet(packet_id, data):
    """
    Parse a server->client packet and extract position data.
    Returns dict with 'type' and position info, or None if not a position packet.
    """
    offset = 0

    # Entity Relative Move (delta position)
    if packet_id == 0x15:
        entity_id, offset = read_varint(data, offset)
        dx, offset = read_byte(data, offset)
        dy, offset = read_byte(data, offset)
        dz, offset = read_byte(data, offset)
        return {
            'type': 'position_delta',
            'entity_id': entity_id,
            'dx': dx / 32.0,  # Fixed-point: divide by 32
            'dy': dy / 32.0,
            'dz': dz / 32.0
        }

    # Entity Look and Relative Move
    if packet_id == 0x17:
        entity_id, offset = read_varint(data, offset)
        dx, offset = read_byte(data, offset)
        dy, offset = read_byte(data, offset)
        dz, offset = read_byte(data, offset)
        yaw, offset = read_ubyte(data, offset)
        pitch, offset = read_ubyte(data, offset)
        return {
            'type': 'position_rotation_delta',
            'entity_id': entity_id,
            'dx': dx / 32.0,
            'dy': dy / 32.0,
            'dz': dz / 32.0,
            'yaw': yaw * 360 / 256,
            'pitch': pitch * 360 / 256
        }

    # Entity Teleport (absolute position)
    if packet_id == 0x18:
        entity_id, offset = read_varint(data, offset)
        x, offset = read_int(data, offset)
        y, offset = read_int(data, offset)
        z, offset = read_int(data, offset)
        yaw, offset = read_ubyte(data, offset)
        pitch, offset = read_ubyte(data, offset)
        return {
            'type': 'teleport',
            'entity_id': entity_id,
            'x': x / 32.0,
            'y': y / 32.0,
            'z': z / 32.0,
            'yaw': yaw * 360 / 256,
            'pitch': pitch * 360 / 256
        }

    # Spawn Player (new player appears)
    if packet_id == 0x0C:
        entity_id, offset = read_varint(data, offset)
        uuid, offset = read_uuid(data, offset)
        x, offset = read_int(data, offset)
        y, offset = read_int(data, offset)
        z, offset = read_int(data, offset)
        return {
            'type': 'spawn_player',
            'entity_id': entity_id,
            'uuid': uuid,
            'x': x / 32.0,
            'y': y / 32.0,
            'z': z / 32.0
        }

    # Player Position And Look (our own position from server)
    if packet_id == 0x08:
        x, offset = read_double(data, offset)
        y, offset = read_double(data, offset)
        z, offset = read_double(data, offset)
        yaw, offset = read_float(data, offset)
        pitch, offset = read_float(data, offset)
        flags, offset = read_ubyte(data, offset)
        return {
            'type': 'my_position',
            'x': x, 'y': y, 'z': z,
            'yaw': yaw, 'pitch': pitch,
            'flags': flags
        }

    return None


# =============================================================================
# CLIENT PACKET PARSERS (Client -> Server)
# =============================================================================

def parse_client_packet(packet_id, data):
    """
    Parse a client->server packet to track local player movement.
    Used to get real-time yaw/pitch updates.
    """
    offset = 0

    # Player Position
    if packet_id == 0x04:
        x, offset = read_double(data, offset)
        y, offset = read_double(data, offset)
        z, offset = read_double(data, offset)
        return {'type': 'client_position', 'x': x, 'y': y, 'z': z}

    # Player Look
    if packet_id == 0x05:
        yaw, offset = read_float(data, offset)
        pitch, offset = read_float(data, offset)
        return {'type': 'client_look', 'yaw': yaw, 'pitch': pitch}

    # Player Position And Look
    if packet_id == 0x06:
        x, offset = read_double(data, offset)
        y, offset = read_double(data, offset)
        z, offset = read_double(data, offset)
        yaw, offset = read_float(data, offset)
        pitch, offset = read_float(data, offset)
        return {'type': 'client_position_look', 'x': x, 'y': y, 'z': z, 'yaw': yaw, 'pitch': pitch}

    return None
