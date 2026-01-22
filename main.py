from fastapi import FastAPI, Request
from Crypto.Cipher import AES
import base64
import json
import os
from typing import Dict, Any

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
    pad_len = data[-1]
    if pad_len < 1 or pad_len > BLOCK_SIZE:
        raise ValueError("Invalid padding")
    return data[:-pad_len]

def b64d(v: Any) -> bytes:
    if not isinstance(v, str):
        raise ValueError("Expected base64 string")
    return base64.b64decode(v.strip())

# -----------------------------
# Health
# -----------------------------

@app.get("/")
@app.get("/health")
def health():
    return {"status": "ok"}

# -----------------------------
# DECRYPT (dynamic passthrough)
# -----------------------------

@app.post("/decrypt")
async def decrypt(request: Request):
    try:
        body: Dict[str, Any] = await request.json()

        # Copy everything except crypto fields
        passthrough = {
            k: v for k, v in body.items()
            if k not in ("iv", "data")
        }

        iv = b64d(body["iv"])
        encrypted = b64d(body["data"])

        cipher = AES.new(KEY, AES.MODE_CBC, iv)
        decrypted = pkcs7_unpad(cipher.decrypt(encrypted))

        payload = json.loads(decrypted.decode("utf-8"))

        return {
            **passthrough,
            **payload
        }

    except Exception as e:
        return {
            "error": "decrypt_failed",
            "message": str(e)
        }

# -----------------------------
# ENCRYPT (dynamic passthrough)
# -----------------------------

@app.post("/encrypt")
async def encrypt(request: Request):
    try:
        body: Dict[str, Any] = await request.json()

        payload = body["payload"]

        # Copy everything except payload
        passthrough = {
            k: v for k, v in body.items()
            if k != "payload"
        }

        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        raw = pkcs7_pad(raw)

        iv = os.urandom(BLOCK_SIZE)
        cipher = AES.new(KEY, AES.MODE_CBC, iv)
        encrypted = cipher.encrypt(raw)

        return {
            **passthrough,
            "iv": base64.b64encode(iv).decode(),
            "data": base64.b64encode(encrypted).decode(),
        }

    except Exception as e:
        return {
            "error": "encrypt_failed",
            "message": str(e)
        }

