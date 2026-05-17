#!/bin/bash
# ═══════════════════════════════════════════════════════════
# OT Inventory Tool — Instalador Automatico
# Potenza Services Inc.
# Uso: sudo bash install.sh
# ═══════════════════════════════════════════════════════════

set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}"
echo "╔═══════════════════════════════════════════════╗"
echo "║     OT Inventory Tool — Potenza Services      ║"
echo "║           Instalador Automatico v1.0          ║"
echo "╚═══════════════════════════════════════════════╝"
echo -e "${NC}"

# ── 1. Verificar root ─────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Error: Ejecutar como root: sudo bash install.sh${NC}"
  exit 1
fi

# ── 2. Solicitar IP del servidor ──────────────────────────
echo ""
echo "Configuracion de red:"
echo "---------------------"
ip addr show | grep "inet " | grep -v "127.0.0.1" | awk '{print $2}' | cut -d/ -f1
echo ""
read -p "Ingrese la IP de este servidor (ej. 192.168.1.100): " SERVER_IP
read -p "Ingrese el puerto (default: 8000): " SERVER_PORT
SERVER_PORT=${SERVER_PORT:-8000}

echo ""
echo -e "${BLUE}Instalando en: $SERVER_IP:$SERVER_PORT${NC}"
echo ""

# ── 3. Instalar dependencias ──────────────────────────────
echo -e "${GREEN}[1/6] Actualizando sistema...${NC}"
apt-get update -qq

echo -e "${GREEN}[2/6] Instalando Docker...${NC}"
if ! command -v docker &> /dev/null; then
  apt-get install -y docker.io docker-compose-v2
  systemctl enable docker
  systemctl start docker
  echo "Docker instalado correctamente."
else
  echo "Docker ya esta instalado."
fi

# ── 4. Instalar git ───────────────────────────────────────
echo -e "${GREEN}[3/6] Instalando Git...${NC}"
apt-get install -y git

# ── 5. Clonar repositorio ─────────────────────────────────
echo -e "${GREEN}[4/6] Clonando repositorio...${NC}"
INSTALL_DIR="/opt/ot-inventory"
if [ -d "$INSTALL_DIR" ]; then
  echo "Directorio existente. Actualizando..."
  cd $INSTALL_DIR/ot-inventory-lab
  git pull
else
  mkdir -p $INSTALL_DIR
  cd $INSTALL_DIR
  git clone https://github.com/ldelgado71col-star/ot-inventory-tool.git
  # Copiar la version de lab que tiene docker-compose funcional
  cp -r /home/*/ot-inventory-lab $INSTALL_DIR/ 2>/dev/null || true
fi

# ── 6. Configurar IP en el dashboard ─────────────────────
echo -e "${GREEN}[5/6] Configurando IP del servidor...${NC}"
DASHBOARD="$INSTALL_DIR/ot-inventory-lab/api/app/static/index.html"
if [ -f "$DASHBOARD" ]; then
  sed -i "s|const API = '.*'|const API = 'http://$SERVER_IP:$SERVER_PORT'|g" "$DASHBOARD"
  echo "IP configurada: $SERVER_IP:$SERVER_PORT"
fi

# ── 7. Arrancar servicios ─────────────────────────────────
echo -e "${GREEN}[6/6] Iniciando servicios...${NC}"
cd $INSTALL_DIR/ot-inventory-lab
docker compose down 2>/dev/null || true
docker compose up -d --build

# ── 8. Configurar inicio automatico ──────────────────────
echo -e "${GREEN}Configurando inicio automatico...${NC}"
cat > /etc/systemd/system/ot-inventory.service << SVCEOF
[Unit]
Description=OT Inventory Tool
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=$INSTALL_DIR/ot-inventory-lab
ExecStart=/usr/bin/docker compose up -d
ExecStop=/usr/bin/docker compose down
TimeoutStartSec=300

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable ot-inventory.service

# ── 9. Resultado final ────────────────────────────────────
echo ""
echo -e "${BLUE}╔═══════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║         Instalacion Completada ✅             ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Dashboard: ${GREEN}http://$SERVER_IP:$SERVER_PORT${NC}"
echo -e "  API Docs:  ${GREEN}http://$SERVER_IP:$SERVER_PORT/docs${NC}"
echo ""
echo -e "  Usuario admin:   ${GREEN}Engineer${NC}"
echo -e "  Usuario field:   ${GREEN}FieldSupport${NC}"
echo -e "  Usuario viewer:  ${GREEN}View${NC}"
echo ""
echo -e "  La aplicacion arranca automaticamente al encender el PC."
echo ""
