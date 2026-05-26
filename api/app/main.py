import os
import psycopg2
from fastapi import FastAPI, BackgroundTasks
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timezone

app = FastAPI(
    title="OT Inventory Tool API",
    description="OT Network Asset Discovery and Inventory Platform",
    version="0.5.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Scan State ────────────────────────────────────────────────────────────
scan_state = {"status": "idle", "devices_found": 0, "last_error": None}


def get_connection():
    return psycopg2.connect(
        host=os.getenv("POSTGRES_HOST", "db"),
        port=os.getenv("POSTGRES_PORT", "5432"),
        database=os.getenv("POSTGRES_DB", "ot_inventory"),
        user=os.getenv("POSTGRES_USER", "otadmin"),
        password=os.getenv("POSTGRES_PASSWORD", "OtLabPassword123")
    )


# ── Models ────────────────────────────────────────────────────────────────

class AssetCreate(BaseModel):
    asset_tag: str
    vendor: Optional[str] = None
    device_type: Optional[str] = None
    model: Optional[str] = None
    firmware_version: Optional[str] = None
    ip_address: Optional[str] = None
    mac_address: Optional[str] = None
    protocol: Optional[str] = None
    location: Optional[str] = None
    hostname: Optional[str] = None

class ObservationCreate(BaseModel):
    asset_tag: str
    parameter: str
    value_text: Optional[str] = None
    value_numeric: Optional[float] = None
    source_protocol: Optional[str] = None
    quality: Optional[str] = "good"

class ScanRequest(BaseModel):
    subnet: str = "192.168.2.0/24"
    interface: str = "eth0"
    retries: int = 3
    interval: int = 15


# ── Health ────────────────────────────────────────────────────────────────

@app.get("/health", tags=["Health"])
def health():
    return {"status": "ok", "service": "ot-inventory-api", "version": "0.5.0"}


# ── Assets ────────────────────────────────────────────────────────────────

@app.get("/assets", tags=["Assets"])
def list_assets():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT
            id, asset_tag, vendor, device_type, model,
            firmware_version, ip_address::text, protocol,
            location, created_at, hostname, open_ports,
            mac_address, first_seen, last_seen,
            classification_source, subnet
        FROM assets
        ORDER BY id;
    """)
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return [
        {
            "id": row[0],
            "asset_tag": row[1],
            "vendor": row[2],
            "device_type": row[3],
            "model": row[4],
            "firmware_version": row[5],
            "ip_address": row[6],
            "protocol": row[7],
            "location": row[8],
            "created_at": row[9],
            "hostname": row[10],
            "open_ports": row[11],
            "mac_address": row[12],
            "first_seen": row[13],
            "last_seen": row[14],
            "classification_source": row[15],
            "subnet": row[16]
        }
        for row in rows
    ]


@app.post("/assets", tags=["Assets"])
def create_asset(asset: AssetCreate):
    conn = get_connection()
    cur = conn.cursor()
    now = datetime.now(timezone.utc)
    cur.execute("""
        INSERT INTO assets (
            asset_tag, vendor, device_type, model,
            firmware_version, ip_address, mac_address,
            protocol, location, first_seen, last_seen
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (asset_tag)
        DO UPDATE SET
            vendor = EXCLUDED.vendor,
            device_type = EXCLUDED.device_type,
            model = EXCLUDED.model,
            firmware_version = EXCLUDED.firmware_version,
            ip_address = EXCLUDED.ip_address,
            mac_address = EXCLUDED.mac_address,
            protocol = EXCLUDED.protocol,
            location = EXCLUDED.location,
            last_seen = EXCLUDED.last_seen
        RETURNING id;
    """, (
        asset.asset_tag, asset.vendor, asset.device_type, asset.model,
        asset.firmware_version, asset.ip_address, asset.mac_address,
        asset.protocol, asset.location, now, now
    ))
    asset_id = cur.fetchone()[0]
    conn.commit()
    cur.close()
    conn.close()
    return {"status": "saved", "id": asset_id, "asset_tag": asset.asset_tag}


# ── Discovery ─────────────────────────────────────────────────────────────

def _run_scan_and_save(subnet: str, interface: str, retries: int, interval: int):
    """Background task — runs full discovery and saves results to database."""
    global scan_state
    scan_state = {"status": "running", "devices_found": 0, "last_error": None}
    try:
        import sys
        sys.path.insert(0, "/app")
        from app.modules.discovery.discovery_service import DiscoveryService
        svc = DiscoveryService()
        devices = svc.run_full_discovery(subnet=subnet, interface=interface)
        conn = get_connection()
        cur = conn.cursor()
        saved = 0
        now = datetime.now(timezone.utc)
        for d in devices:
            mac_raw = d.get("mac", "")
            mac_clean = mac_raw.replace(":", "").upper()
            asset_tag = f"NET-{mac_clean}"

            # Format MAC with colons for the mac_address column
            mac_formatted = mac_raw.lower() if mac_raw else None

            open_ports = d.get("open_ports", [])
            ports_str = ",".join(str(p) for p in open_ports) if open_ports else None
            hostname = d.get("hostname") or None
            classification_source = d.get("classification_source") or None

            cur.execute("""
                INSERT INTO assets (
                    asset_tag, vendor, device_type, ip_address,
                    mac_address, hostname, protocol, location,
                    open_ports, classification_source, subnet,
                    first_seen, last_seen
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (asset_tag)
                DO UPDATE SET
                    ip_address = EXCLUDED.ip_address,
                    vendor = EXCLUDED.vendor,
                    device_type = EXCLUDED.device_type,
                    mac_address = EXCLUDED.mac_address,
                    hostname = EXCLUDED.hostname,
                    open_ports = EXCLUDED.open_ports,
                    classification_source = EXCLUDED.classification_source,
                    subnet = EXCLUDED.subnet,
                    last_seen = EXCLUDED.last_seen
            """, (
                asset_tag,
                d.get("vendor", "Unknown"),
                d.get("device_type", "Unknown"),
                d.get("ip", ""),
                mac_formatted,
                hostname,
                "ARP",
                "Network",
                ports_str,
                classification_source,
                subnet,
                now,
                now
            ))
            saved += 1
        conn.commit()
        cur.close()
        conn.close()
        scan_state = {"status": "complete", "devices_found": saved, "last_error": None}
        print(f"[scan] Saved {saved} assets from {subnet}")
    except Exception as e:
        scan_state = {"status": "error", "devices_found": 0, "last_error": str(e)}
        print(f"[scan] Error: {e}")
        import traceback
        traceback.print_exc()

@app.post("/discovery/scan", tags=["Discovery"])
def trigger_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """
    Trigger an ARP scan on the specified subnet.
    Runs in background — results saved automatically to asset database.
    """
    background_tasks.add_task(
        _run_scan_and_save,
        subnet=request.subnet,
        interface=request.interface,
        retries=request.retries,
        interval=request.interval
    )
    return {
        "status": "scan started",
        "subnet": request.subnet,
        "interface": request.interface,
        "message": "Scan running in background. Check /assets for results."
    }


@app.get("/discovery/scan/status", tags=["Discovery"])
def scan_status():
    """Check the status of the current or last scan."""
    return scan_state


@app.get("/discovery/scan/quick", tags=["Discovery"])
def quick_scan():
    """Run a quick ARP scan on the default subnet and return results immediately."""
    try:
        import sys
        sys.path.insert(0, "/app")
        from app.modules.discovery.discovery_service import DiscoveryService

        svc = DiscoveryService()
        devices = svc.run_arp_scan(
            subnet="192.168.2.0/24",
            interface="eth0",
            retries=3,
            interval=15
        )
        return {"status": "ok", "devices_found": len(devices), "devices": devices}
    except Exception as e:
        return {"status": "error", "message": str(e)}


# ── Observations ──────────────────────────────────────────────────────────

@app.post("/observations", tags=["Observations"])
def create_observation(obs: ObservationCreate):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO asset_observations (
            time, asset_tag, parameter, value_text,
            value_numeric, source_protocol, quality
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s);
    """, (
        datetime.now(timezone.utc),
        obs.asset_tag, obs.parameter, obs.value_text,
        obs.value_numeric, obs.source_protocol, obs.quality
    ))
    conn.commit()
    cur.close()
    conn.close()
    return {"status": "saved", "asset_tag": obs.asset_tag, "parameter": obs.parameter}


@app.get("/observations/{asset_tag}", tags=["Observations"])
def list_observations(asset_tag: str):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT time, asset_tag, parameter, value_text,
               value_numeric, source_protocol, quality
        FROM asset_observations
        WHERE asset_tag = %s
        ORDER BY time DESC
        LIMIT 100;
    """, (asset_tag,))
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return [
        {
            "time": row[0], "asset_tag": row[1], "parameter": row[2],
            "value_text": row[3], "value_numeric": row[4],
            "source_protocol": row[5], "quality": row[6]
        }
        for row in rows
    ]
app.mount("/static", StaticFiles(directory="/app/app/static"), name="static")

@app.get("/", include_in_schema=False)
def dashboard():
    return FileResponse("/app/app/static/index.html")


# ── Authentication endpoints ──────────────────────────────────
from app.auth import authenticate_user, create_token, verify_token
from fastapi import Request
from fastapi.responses import JSONResponse

@app.post("/auth/login", tags=["Auth"])
def login(credentials: dict):
    username = credentials.get("username", "")
    password = credentials.get("password", "")
    user = authenticate_user(username, password)
    if not user:
        return JSONResponse(status_code=401, content={"error": "Invalid username or password"})
    token = create_token(user["username"], user["role"])
    return {
        "token": token,
        "username": user["username"],
        "role": user["role"],
        "full_name": user["full_name"]
    }

@app.get("/auth/verify", tags=["Auth"])
def verify(request: Request):
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return JSONResponse(status_code=401, content={"error": "No token"})
    token = auth.replace("Bearer ", "")
    payload = verify_token(token)
    if not payload:
        return JSONResponse(status_code=401, content={"error": "Invalid or expired token"})
    return {"username": payload["sub"], "role": payload["role"]}
