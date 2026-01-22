from fastapi import FastAPI, Request
from Crypto.Cipher import AES
import base64
import json
import os
from typing import Any, Dict

app = FastAPI()

KEY = bytes.fromhex(
    "de01865dbcbf272e80389feb5f73f195ca043a740df2f66650281d6a41c9cb81"
)

BLOCK_SIZE = 16

# -----------------------------
# Utils
# -----------------------------

def pkcs7_pad(data: bytes) -> bytes:
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len]) * pad_len

def pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        raise ValueError("Empty data")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > BLOCK_SIZE:
        raise ValueError("Invalid padding")
    return data[:-pad_len]

def safe_b64decode(value: Any) -> bytes:
    if not isinstance(value, str):
        raise ValueError("Expected base64 string")
    return base64.b64decode(value.strip())

def extract_passthrough(body: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "SL no": body.get("SL no"),
        "name": body.get("name"),
        "Chat ID": body.get("Chat ID"),
        "Follow Up date": body.get("Follow Up date"),
        "Follow Up Status": body.get("Follow Up Status"),
    }

# -----------------------------
# Health check
# -----------------------------

@app.get("/")
@app.get("/health")
def health():
    return {"status": "ok"}

# -----------------------------
# Decrypt
# -----------------------------

@app.post("/decrypt")
async def decrypt(request: Request):
    try:
        body = await request.json()

        iv = safe_b64decode(body["iv"])
        encrypted = safe_b64decode(body["data"])

        if len(iv) != BLOCK_SIZE:
            raise ValueError("IV must be 16 bytes")

        cipher = AES.new(KEY, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted)
        decrypted = pkcs7_unpad(decrypted)

        decrypted_json = json.loads(decrypted.decode("utf-8"))

        return {
            **extract_passthrough(body),
            **decrypted_json
        }

    except Exception as e:
        return {
            "error": "decrypt_failed",
            "message": str(e)
        }

# -----------------------------
# Encrypt
# -----------------------------

@app.post("/encrypt")
async def encrypt(request: Request):
    try:
        body = await request.json()
        payload = body["payload"]

        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        raw = pkcs7_pad(raw)

        iv = os.urandom(BLOCK_SIZE)
        cipher = AES.new(KEY, AES.MODE_CBC, iv)
        encrypted = cipher.encrypt(raw)

        return {
            **extract_passthrough(body),
            "iv": base64.b64encode(iv).decode(),
            "data": base64.b64encode(encrypted).decode(),
        }

    except Exception as e:
        return {
            "error": "encrypt_failed",
            "message": str(e)
        }


