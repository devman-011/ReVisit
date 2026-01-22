from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
from Crypto.Cipher import AES
import base64
import json

app = FastAPI()

KEY = bytes.fromhex(
    "de01865dbcbf272e80389feb5f73f195ca043a740df2f66650281d6a41c9cb81"
)

class DecryptRequest(BaseModel):
    iv: str
    data: str

@app.post("/decrypt")
def decrypt(payload: DecryptRequest, x_api_key: str = Header(None)):
    if x_api_key != "SUPER_SECRET_KEY":
        raise HTTPException(status_code=401, detail="Unauthorized")

    try:
        iv = base64.b64decode(payload.iv.strip())
        encrypted_data = base64.b64decode(payload.data)

        cipher = AES.new(KEY, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted_data)

        pad_len = decrypted[-1]
        decrypted = decrypted[:-pad_len]

        return json.loads(decrypted.decode("utf-8"))

    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
