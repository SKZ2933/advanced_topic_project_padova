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
        # VarInt use 7 first bits to store data and last bit to store the flag that means more data
        # e.g. = 0000 1111 => no more data coming but 1000 1111 more data coming!
        # 0x7F is 01111111 so we just retrieve the real data bits here
        # First shift is 0 as this shift is in the case the data is longer we have to take in 
        # consideration that now we are at the index 7 of the power of 2 
        # e.g. 0000 0001 and 1000 1111 the final number is 1000 1111 (because the flag used the 7 index data bit) 
        result |= (byte & 0x7F) << shift
        # 0x80 is 1000 000 so we check only the "flag" bit that means if more data is coming
        if not (byte & 0x80):
            break
        # Shift to take in consideration that we now shifted of power of 2 for the data!
        shift += 7
        # VarInt data is maximum 32 bit integer so 5 data packets maximum, hence the 32 max!
        if shift >= 32:
            return None, offset
    # Convert to signed 32-bit
    # We check the highest bit if it's set 1000 0000 0000 ... (bit 31) we count from 0
    # If it is -> it's a negative number
    # We substract by 2^32 which give -result !
    if result & (1 << 31):
        result -= (1 << 32)
    return result, offset


def write_varint(value):
    """Encode an integer as VarInt bytes."""
    result = b''
    if value < 0:
        value += (1 << 32)
    while True:
        # First 7 bits of data with Ox7F
        byte = value & 0x7F
        # Shift to the right and take only the highest bit
        # If value (which means the flag is set to continue)
        # We add the highest bit 0x80 to the current byte
        value >>= 7
        if value:
            byte |= 0x80
        # Append the byte to result
        result += bytes([byte])
        # No more bits to proceed
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
#
# Each packet has a unique structure. Here's what we parse:
#
# 0x15 - Entity Relative Move (something moved by DELTA)
#        [entity_id: VarInt][dx: Byte][dy: Byte][dz: Byte]
#        → Small deltas fit in bytes, saves bandwidth
#
# 0x17 - Entity Look and Relative Move (moved + rotated)
#        [entity_id: VarInt][dx: Byte][dy: Byte][dz: Byte][yaw: UByte][pitch: UByte]
#        → Angles: 0-255 maps to 0°-360° (×360÷256)
#
# 0x18 - Entity Teleport (something moved to ABSOLUTE position)
#        [entity_id: VarInt][x: Int][y: Int][z: Int][yaw: UByte][pitch: UByte]
#        → Used for large movements or corrections
#
# 0x08 - Player Position And Look (YOUR position from server)
#        [x: Double][y: Double][z: Double][yaw: Float][pitch: Float][flags: UByte]
#        → Doubles for precision (client's own position matters more)
#
# 0x0C - Spawn Player (a NEW player appears nearby)
#        [entity_id: VarInt][uuid: UUID][x: Int][y: Int][z: Int]...
#        → Fixed-point integers (÷32), UUID identifies the player
#
# =============================================================================

def parse_server_packet(packet_id, data):
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
        if dx is None or dy is None or dz is None:
            return None
        return {
            'type': 'position_delta',
            'entity_id': entity_id,
            'dx': dx / 32.0,  # As position is integer, minecraft multiply by 32 to have better precision -> each integer representer a smaller float so better resolution
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
        if dx is None or dy is None or dz is None or yaw is None or pitch is None:
            return None
        return {
            'type': 'position_rotation_delta',
            'entity_id': entity_id,
            'dx': dx / 32.0,
            'dy': dy / 32.0,
            'dz': dz / 32.0,
            'yaw': yaw * 360 / 256, # ubyte is a value from 0 to 255 so we convert to 360
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
        if x is None or y is None or z is None or yaw is None or pitch is None:
            return None
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
        if x is None or y is None or z is None:
            return None
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
#
# These are packets YOU send to the server. We parse them to know:
# - Your current camera angle (yaw/pitch) for aimbot calculations
# - Your exact position (more accurate than server corrections)
#
# 0x04 - Player Position (you moved, no rotation change)
#        [x: Double][y: Double][z: Double][on_ground: Bool]
#
# 0x05 - Player Look (you rotated camera, no position change)
#        [yaw: Float][pitch: Float][on_ground: Bool]
#        → This tells us where you're CURRENTLY looking
#
# 0x06 - Player Position And Look (you moved AND rotated)
#        [x: Double][y: Double][z: Double][yaw: Float][pitch: Float][on_ground: Bool]
#        → Complete update of your state
#
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
        return {
            'type': 'client_position', 
            'x': x, 
            'y': y, 
            'z': z
        }

    # Player Look
    if packet_id == 0x05:
        yaw, offset = read_float(data, offset)
        pitch, offset = read_float(data, offset)
        return {
            'type': 'client_look', 
            'yaw': yaw, 
            'pitch': pitch
        }

    # Player Position And Look
    if packet_id == 0x06:
        x, offset = read_double(data, offset)
        y, offset = read_double(data, offset)
        z, offset = read_double(data, offset)
        yaw, offset = read_float(data, offset)
        pitch, offset = read_float(data, offset)
        return {
            'type': 'client_position_look', 
            'x': x, 
            'y': y, 
            'z': z, 
            'yaw': yaw, 
            'pitch': pitch
        }

    return None

