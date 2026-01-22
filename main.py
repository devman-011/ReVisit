import os
import base64
import json
from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# ===== ENV =====
API_KEY = os.getenv("API_KEY")
AES_KEY_HEX = os.getenv("AES_KEY_HEX")
PORT = int(os.getenv("PORT", "8000"))

if not API_KEY or not AES_KEY_HEX:
    raise RuntimeError("Missing required environment variables")

AES_KEY = bytes.fromhex(AES_KEY_HEX)

# ===== APP =====
app = FastAPI()

class EncryptRequest(BaseModel):
    payload: dict

class DecryptRequest(BaseModel):
    iv: str
    data: str


# ---------- ENCRYPT ----------
@app.post("/encrypt")
def encrypt(payload: EncryptRequest, x_api_key: str = Header(None)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")

    try:
        raw = json.dumps(payload.payload, separators=(",", ":")).encode("utf-8")

        # PKCS7 padding
        pad_len = 16 - (len(raw) % 16)
        raw += bytes([pad_len]) * pad_len

        iv = get_random_bytes(16)
        cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
        encrypted = cipher.encrypt(raw)

        return {
            "iv": base64.b64encode(iv).decode(),
            "data": base64.b64encode(encrypted).decode()
        }

    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# ---------- DECRYPT ----------
@app.post("/decrypt")
def decrypt(payload: DecryptRequest, x_api_key: str = Header(None)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")

    try:
        iv = base64.b64decode(payload.iv.strip())
        encrypted_data = base64.b64decode(payload.data)

        cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted_data)

        pad_len = decrypted[-1]
        decrypted = decrypted[:-pad_len]

        return json.loads(decrypted.decode("utf-8"))

    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/health")
def health():
    return {"status": "ok"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=PORT)
