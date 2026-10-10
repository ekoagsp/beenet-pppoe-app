
import os
import json
import hmac
import hashlib
import time

from urllib.parse import parse_qsl
from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import FileResponse

app = FastAPI(title="BeeNet PPPoE Checker")

BOT_TOKEN = os.environ.get("BOT_TOKEN", "")
ALLOWED_IDS = {
    item.strip()
    for item in os.environ.get("ALLOWED_USER_IDS", "").split(",")
    if item.strip()
}

# DATA DEMO — BUKAN DATA LIVE DARI ROUTER
DEMO_USERS = {
    "WA-EKO_AGUS_P": {
        "status": "ONLINE",
        "ip": "10.50.255.241",
        "uptime": "4d01:03:31"
    },
    "DEMO-OFFLINE": {
        "status": "OFFLINE",
        "ip": None,
        "uptime": None
    }
}


def verify_telegram(init_data: str):
    if not BOT_TOKEN or not ALLOWED_IDS:
        raise HTTPException(
            status_code=503,
            detail="Konfigurasi keamanan belum lengkap"
        )

    try:
        data = dict(parse_qsl(
            init_data,
            keep_blank_values=True
        ))

        received_hash = data.pop("hash", "")
        auth_date = int(data.get("auth_date", "0"))

        # Batas usia autentikasi 5 menit
        if not received_hash:
            raise ValueError("Hash tidak ada")

        if abs(time.time() - auth_date) > 300:
            raise ValueError("Autentikasi kedaluwarsa")

        check_string = "\n".join(
            f"{key}={value}"
            for key, value in sorted(data.items())
        )

        secret_key = hmac.new(
            b"WebAppData",
            BOT_TOKEN.encode(),
            hashlib.sha256
        ).digest()

        calculated_hash = hmac.new(
            secret_key,
            check_string.encode(),
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(
            calculated_hash, received_hash
        ):
            raise ValueError("Hash tidak valid")

        user = json.loads(data.get("user", "{}"))
        user_id = str(user.get("id", ""))

        if user_id not in ALLOWED_IDS:
            raise HTTPException(
                status_code=403,
                detail="Akses tidak diizinkan"
            )

        return user_id

    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=401,
            detail="Autentikasi Telegram tidak valid"
        )


@app.get("/")
def home():
    return FileResponse("index.html")


@app.get("/api/pppoe")
def check_pppoe(
    username: str,
    x_telegram_init_data: str = Header(default="")
):
    verify_telegram(x_telegram_init_data)

    username = username.strip()

    if not username or len(username) > 64:
        raise HTTPException(
            status_code=400,
            detail="Username tidak valid"
        )

    customer = DEMO_USERS.get(username.upper())

    if not customer:
        return {
            "found": False,
            "message": "Username tidak ditemukan"
        }

    return {
        "found": True,
        "username": username,
        **customer
    }
