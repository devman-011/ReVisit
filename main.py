from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
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
# Shared helpers
# -----------------------------

def pkcs7_unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    return data[:-pad_len]

def pkcs7_pad(data: bytes) -> bytes:
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len] * pad_len)

# -----------------------------
# Models
# -----------------------------

class DecryptRequest(BaseModel):
    iv: str
    data: str

    # passthrough fields
    SL_no: int | None = None
    name: str | None = None
    Chat_ID: int | None = None
    Follow_Up_date: str | None = None
    Follow_Up_Status: str | None = None


class EncryptRequest(BaseModel):
    payload: Dict[str, Any]

    # passthrough fields
    SL_no: int | None = None
    name: str | None = None
    Chat_ID: int | None = None
    Follow_Up_date: str | None = None
    Follow_Up_Status: str | None = None


# -----------------------------
# DECRYPT
# -----------------------------

@app.post("/decrypt")
def decrypt(req: DecryptRequest):
    try:
        iv = base64.b64decode(req.iv.strip())
        encrypted_data = base64.b64decode(req.data)

        cipher = AES.new(KEY, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted_data)
        decrypted = pkcs7_unpad(decrypted)

        decrypted_json = json.loads(decrypted.decode("utf-8"))

        return {
            # passthrough
            "SL no": req.SL_no,
            "name": req.name,
            "Chat ID": req.Chat_ID,
            "Follow Up date": req.Follow_Up_date,
            "Follow Up Status": req.Follow_Up_Status,

            # decrypted payload
            **decrypted_json
        }

    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# -----------------------------
# ENCRYPT (reverse)
# -----------------------------

@app.post("/encrypt")
def encrypt(req: EncryptRequest):
    try:
        raw = json.dumps(req.payload).encode("utf-8")
        raw = pkcs7_pad(raw)

        iv = os.urandom(16)
        cipher = AES.new(KEY, AES.MODE_CBC, iv)
        encrypted = cipher.encrypt(raw)

        return {
            # passthrough
            "SL no": req.SL_no,
            "name": req.name,
            "Chat ID": req.Chat_ID,
            "Follow Up date": req.Follow_Up_date,
            "Follow Up Status": req.Follow_Up_Status,

            # encrypted output
            "iv": base64.b64encode(iv).decode(),
            "data": base64.b64encode(encrypted).decode()
        }

    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
