import os
import psycopg2
from fastapi import FastAPI
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timezone

app = FastAPI(
    title="OT Inventory Lab API",
    description="API base para inventario OT con PostgreSQL + TimescaleDB",
    version="0.1.0"
)

def get_connection():
    return psycopg2.connect(
        host=os.getenv("POSTGRES_HOST", "db"),
        port=os.getenv("POSTGRES_PORT", "5432"),
        database=os.getenv("POSTGRES_DB", "ot_inventory"),
        user=os.getenv("POSTGRES_USER", "otadmin"),
        password=os.getenv("POSTGRES_PASSWORD", "OtLabPassword123")
    )

class AssetCreate(BaseModel):
    asset_tag: str
    vendor: Optional[str] = None
    device_type: Optional[str] = None
    model: Optional[str] = None
    firmware_version: Optional[str] = None
    ip_address: Optional[str] = None
    protocol: Optional[str] = None
    location: Optional[str] = None

class ObservationCreate(BaseModel):
    asset_tag: str
    parameter: str
    value_text: Optional[str] = None
    value_numeric: Optional[float] = None
    source_protocol: Optional[str] = None
    quality: Optional[str] = "good"

@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "ot-inventory-api"
    }

@app.get("/assets")
def list_assets():
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT
            id,
            asset_tag,
            vendor,
            device_type,
            model,
            firmware_version,
            ip_address::text,
            protocol,
            location,
            created_at
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
            "created_at": row[9]
        }
        for row in rows
    ]

@app.post("/assets")
def create_asset(asset: AssetCreate):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO assets (
            asset_tag,
            vendor,
            device_type,
            model,
            firmware_version,
            ip_address,
            protocol,
            location
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (asset_tag)
        DO UPDATE SET
            vendor = EXCLUDED.vendor,
            device_type = EXCLUDED.device_type,
            model = EXCLUDED.model,
            firmware_version = EXCLUDED.firmware_version,
            ip_address = EXCLUDED.ip_address,
            protocol = EXCLUDED.protocol,
            location = EXCLUDED.location
        RETURNING id;
    """, (
        asset.asset_tag,
        asset.vendor,
        asset.device_type,
        asset.model,
        asset.firmware_version,
        asset.ip_address,
        asset.protocol,
        asset.location
    ))

    asset_id = cur.fetchone()[0]
    conn.commit()

    cur.close()
    conn.close()

    return {
        "status": "saved",
        "id": asset_id,
        "asset_tag": asset.asset_tag
    }

@app.post("/observations")
def create_observation(obs: ObservationCreate):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO asset_observations (
            time,
            asset_tag,
            parameter,
            value_text,
            value_numeric,
            source_protocol,
            quality
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s);
    """, (
        datetime.now(timezone.utc),
        obs.asset_tag,
        obs.parameter,
        obs.value_text,
        obs.value_numeric,
        obs.source_protocol,
        obs.quality
    ))

    conn.commit()

    cur.close()
    conn.close()

    return {
        "status": "saved",
        "asset_tag": obs.asset_tag,
        "parameter": obs.parameter
    }

@app.get("/observations/{asset_tag}")
def list_observations(asset_tag: str):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT
            time,
            asset_tag,
            parameter,
            value_text,
            value_numeric,
            source_protocol,
            quality
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
            "time": row[0],
            "asset_tag": row[1],
            "parameter": row[2],
            "value_text": row[3],
            "value_numeric": row[4],
            "source_protocol": row[5],
            "quality": row[6]
        }
        for row in rows
    ]
