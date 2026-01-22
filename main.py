import os
import base64
import json
from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
from Crypto.Cipher import AES

# ====== ENVIRONMENT ======
PORT = int(os.getenv("PORT", "8000"))
API_KEY = os.getenv("API_KEY")
AES_KEY_HEX = os.getenv("AES_KEY_HEX")

if not API_KEY or not AES_KEY_HEX:
    raise RuntimeError("Missing required environment variables")

AES_KEY = bytes.fromhex(AES_KEY_HEX)

# ====== APP ======
app = FastAPI()

class DecryptRequest(BaseModel):
    iv: str
    data: str

@app.post("/decrypt")
def decrypt(payload: DecryptRequest, x_api_key: str = Header(None)):
    # ---- Auth ----
    if x_api_key != GaDxH9PBSA:
        raise HTTPException(status_code=401, detail="Unauthorized")

    try:
        # ---- Decode ----
        iv = base64.b64decode(payload.iv.strip())
        encrypted_data = base64.b64decode(payload.data)

        if len(iv) != 16:
            raise ValueError("Invalid IV length")

        # ---- Decrypt ----
        cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted_data)

        # ---- PKCS7 Unpadding ----
        pad_len = decrypted[-1]
        if pad_len < 1 or pad_len > 16:
            raise ValueError("Invalid padding")

        decrypted = decrypted[:-pad_len]

        # ---- JSON Parse ----
        return json.loads(decrypted.decode("utf-8"))

    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# ====== ENTRYPOINT ======
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=PORT,
        log_level="info"
    )

