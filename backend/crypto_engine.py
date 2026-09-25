import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from PIL import Image

# ==========================================
# 🔐 ADVANCED AES-256-GCM ENCRYPTION
# ==========================================
def _get_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
    return kdf.derive(password.encode())

def encrypt_file_data(data: bytes, password: str) -> bytes:
    salt = os.urandom(16)
    key = _get_key(password, salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return salt + nonce + ciphertext

def decrypt_file_data(data: bytes, password: str) -> bytes:
    try:
        salt = data[:16]
        nonce = data[16:28]
        ciphertext = data[28:]
        key = _get_key(password, salt)
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, None)
    except Exception:
        raise ValueError("Decryption failed. Invalid Key or Corrupted Data.")

# ==========================================
# 🖼️ LSB STEGANOGRAPHY & WATERMARKING
# ==========================================
def hide_data_in_image(image_path: str, secret_data: bytes, output_path: str, watermark: str = "UNKNOWN_AGENT"):
    """Hides the watermark and encrypted payload inside the image pixels."""
    
    # 1. Format the payload: [1 Byte: Watermark Length] + [Watermark Bytes] + [4 Bytes: Data Length] + [Secret Data]
    wm_bytes = watermark.encode('utf-8')
    wm_len = len(wm_bytes)
    
    if wm_len > 255:
        raise ValueError("Watermark too long (max 255 chars).")
        
    # Combine everything into one master binary payload
    payload = bytes([wm_len]) + wm_bytes + len(secret_data).to_bytes(4, 'big') + secret_data
    
    # Convert payload to a string of 1s and 0s
    bits = ''.join([format(b, '08b') for b in payload])
    
    img = Image.open(image_path).convert('RGB')
    pixels = list(img.getdata())
    
    if len(bits) > len(pixels) * 3:
        raise ValueError("Image is too small to hold this much classified data.")
    
    new_pixels = []
    bit_idx = 0
    
    # 2. Inject bits into the Least Significant Bit of the Red, Green, and Blue channels
    for r, g, b in pixels:
        if bit_idx < len(bits): r = (r & 254) | int(bits[bit_idx]); bit_idx += 1
        if bit_idx < len(bits): g = (g & 254) | int(bits[bit_idx]); bit_idx += 1
        if bit_idx < len(bits): b = (b & 254) | int(bits[bit_idx]); bit_idx += 1
        new_pixels.append((r, g, b))
        
    new_img = Image.new(img.mode, img.size)
    new_img.putdata(new_pixels)
    new_img.save(output_path, format="PNG") # Must be PNG to prevent compression loss

def extract_data_from_image(image_path: str) -> bytes:
    """Extracts the hidden encrypted payload, skipping over the watermark."""
    img = Image.open(image_path).convert('RGB')
    bits = ""
    for r, g, b in img.getdata():
        bits += str(r & 1) + str(g & 1) + str(b & 1)
        
    extracted_bytes = bytearray()
    for i in range(0, len(bits) - 7, 8):
        extracted_bytes.append(int(bits[i:i+8], 2))
        
    # Parse the Watermark to know how much to skip
    wm_len = extracted_bytes[0]
    data_start = 1 + wm_len
    
    # Parse the actual data length
    data_len = int.from_bytes(extracted_bytes[data_start:data_start+4], 'big')
    
    # Extract just the AES payload
    payload_start = data_start + 4
    return bytes(extracted_bytes[payload_start:payload_start+data_len])

def scan_image_for_watermark(image_path: str) -> str:
    """FORENSIC TOOL: Scans a leaked image and returns the Agent's Watermark."""
    img = Image.open(image_path).convert('RGB')
    bits = ""
    
    # We only need the first few hundred pixels to get the watermark header
    for idx, (r, g, b) in enumerate(img.getdata()):
        bits += str(r & 1) + str(g & 1) + str(b & 1)
        if idx > 1000: break
        
    extracted_bytes = bytearray()
    for i in range(0, len(bits) - 7, 8):
        extracted_bytes.append(int(bits[i:i+8], 2))
        
    wm_len = extracted_bytes[0]
    return extracted_bytes[1:1+wm_len].decode('utf-8', errors='ignore')