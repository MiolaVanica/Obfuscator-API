from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
import json
import os
from cryptography.fernet import Fernet
from telegram import Bot, InlineKeyboardButton, InlineKeyboardMarkup
import asyncio
from dotenv import load_dotenv
from functools import wraps
import secrets
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

load_dotenv()

app = FastAPI()

# Configuration
APPROVAL_BOT_TOKEN = os.getenv("APPROVAL_BOT_TOKEN")
ADMIN_CHAT_ID = os.getenv("ADMIN_CHAT_ID")
API_SECRET = os.getenv("API_SECRET")

# Generate RSA key pair for server
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# Load Fernet key
with open("fernet_key.bin", "rb") as f:
    FERNET_KEY = f.read()
fernet = Fernet(FERNET_KEY)

# Load encrypted code and mapping
with open("obfuscated_code.bin", "rb") as f:
    encrypted_code = f.read()
with open("mapping.bin", "rb") as f:
    encrypted_mapping = f.read()
obfuscated_code = fernet.decrypt(encrypted_code).decode()
reverse_mapping = json.loads(fernet.decrypt(encrypted_mapping).decode())

# Store pending requests
pending_requests = {}

class ExecutionRequest(BaseModel):
    secret: str
    session_key: str
    client_public_key: str  # Client's RSA public key

def require_secret(func):
    @wraps(func)
    async def wrapper(request: ExecutionRequest, *args, **kwargs):
        if request.secret != API_SECRET:
            raise HTTPException(status_code=403, detail="Invalid API secret")
        return await func(request, *args, **kwargs)
    return wrapper

async def send_approval_message(request_id: str, session_key: str):
    bot = Bot(token=APPROVAL_BOT_TOKEN)
    keyboard = [
        [
            InlineKeyboardButton("Accept", callback_data=f"accept_{request_id}"),
            InlineKeyboardButton("Reject", callback_data=f"reject_{request_id}"),
        ]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await bot.send_message(
        chat_id=ADMIN_CHAT_ID,
        text=f"New execution request (ID: {request_id})\nSession Key: {session_key[:10]}...",
        reply_markup=reply_markup
    )

@app.get("/public_key")
async def get_public_key():
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKey
    )
    return {"public_key": public_pem.decode()}

@app.post("/execute")
@require_secret
async def execute_code(request: ExecutionRequest):
    # Load client's public key
    try:
        client_public_key = serialization.load_pem_public_key(request.client_public_key.encode())
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid client public key")

    # Generate a unique request ID
    request_id = secrets.token_hex(16)
    
    # Store the request
    pending_requests[request_id] = {
        "status": "pending",
        "result": None,
        "session_key": request.session_key,
        "client_public_key": client_public_key
    }
    
    # Send Telegram approval message
    await send_approval_message(request_id, request.session_key)
    
    # Wait for approval (timeout after 5 minutes)
    for _ in range(300):
        if pending_requests[request_id]["status"] != "pending":
            break
        await asyncio.sleep(1)
    
    # Check result
    request_data = pending_requests.pop(request_id, None)
    if not request_data:
        raise HTTPException(status_code=408, detail="Request timed out")
    
    if request_data["status"] == "approved":
        # Decrypt the code
        decrypted_code = obfuscated_code
        for code, original in reverse_mapping.items():
            decrypted_code = decrypted_code.replace(code, original)
        
        # Encrypt the code with the client's public key
        encrypted_code = request_data["client_public_key"].encrypt(
            decrypted_code.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return {"encrypted_code": encrypted_code.hex()}
    else:
        raise HTTPException(status_code=403, detail="Decryption Rejected! Contact @SCDP3")

@app.post("/handle_callback")
async def handle_callback(callback_data: str):
    action, request_id = callback_data.split("_", 1)
    if request_id not in pending_requests:
        return {"status": "error", "message": "Invalid request ID"}
    if action == "accept":
        pending_requests[request_id]["status"] = "approved"
    elif action == "reject":
        pending_requests[request_id]["status"] = "rejected"
    return {"status": "success"}