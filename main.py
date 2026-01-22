from fastapi import FastAPI, HTTPException, Request
from Crypto.Cipher import AES
import base64
import json
import os
from typing import Dict, Any

app = FastAPI()

KEY = bytes.fromhex(
    "de01865dbcbf272e80389feb5f73f195ca043a740df2f66650281d6a41c9cb81"
)

# -----------------------------
# Padding helpers
# -----------------------------

def pkcs7_pad(data: bytes) -> bytes:
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len] * pad_len)

def pkcs7_unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    return data[:-pad_len]

# -----------------------------
# Helper: extract passthrough
# -----------------------------

def extract_passthrough(body: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "SL no": body.get("SL no"),
        "name": body.get("name"),
        "Chat ID": body.get("Chat ID"),
        "Follow Up date": body.get("Follow Up date"),
        "Follow Up Status": body.get("Follow Up Status"),
    }

# -----------------------------
# DECRYPT
# -----------------------------

@app.post("/decrypt")
async def decrypt(request: Request):
    try:
        body = await request.json()

        iv = base64.b64decode(body["iv"].strip())
        encrypted_data = base64.b64decode(body["data"])

        cipher = AES.new(KEY, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted_data)
        decrypted = pkcs7_unpad(decrypted)

        decrypted_json = json.loads(decrypted.decode("utf-8"))

        return {
            **extract_passthrough(body),
            **decrypted_json
        }

    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# -----------------------------
# ENCRYPT
# -----------------------------

@app.post("/encrypt")
async def encrypt(request: Request):
    try:
        body = await request.json()

        payload = body["payloa]()
