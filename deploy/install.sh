#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════
# OT Inventory Tool — Instalador Automatico v2.0
# Potenza Services Inc.
# Uso: sudo bash install.sh
# Probado en: Ubuntu 22.04 LTS / Ubuntu 24.04 LTS
# ═══════════════════════════════════════════════════════════════════════════

set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}"
echo "╔═══════════════════════════════════════════════════╗"
echo "║      OT Inventory Tool — Potenza Services         ║"
echo "║           Instalador Automatico v2.0              ║"
echo "║         github.com/ldelgado71col-star              ║"
echo "╚═══════════════════════════════════════════════════╝"
echo -e "${NC}"

# ── 1. Verificar root ─────────────────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Error: Ejecutar como root: sudo bash install.sh${NC}"
  exit 1
fi

# ── 2. Detectar usuario no-root para el directorio home ──────────────────
REAL_USER=${SUDO_USER:-$(logname 2>/dev/null || echo "ubuntu")}
REAL_HOME=$(eval echo "~$REAL_USER")
echo -e "${BLUE}Usuario de instalacion: $REAL_USER ($REAL_HOME)${NC}"

# ── 3. Solicitar configuracion de red ─────────────────────────────────────
echo ""
echo "Interfaces de red disponibles:"
echo "──────────────────────────────"
ip addr show | grep -E "^[0-9]+:|inet " | grep -v "127.0.0.1" | grep -v "::1"
echo ""

# Detectar interfaz principal automaticamente
DEFAULT_IFACE=$(ip route | grep default | awk '{print $5}' | head -1)
DEFAULT_IP=$(ip addr show "$DEFAULT_IFACE" | grep "inet " | awk '{print $2}' | cut -d/ -f1 | head -1)
DEFAULT_GW=$(ip route | grep default | awk '{print $3}' | head -1)
DEFAULT_DNS="8.8.8.8"

echo -e "${YELLOW}Detectado automaticamente:${NC}"
echo "  Interfaz : $DEFAULT_IFACE"
echo "  IP actual: $DEFAULT_IP"
echo "  Gateway  : $DEFAULT_GW"
echo ""

read -p "IP ESTATICA para este servidor [${DEFAULT_IP}]: " SERVER_IP
SERVER_IP=${SERVER_IP:-$DEFAULT_IP}

read -p "Interfaz de red [${DEFAULT_IFACE}]: " NET_IFACE
NET_IFACE=${NET_IFACE:-$DEFAULT_IFACE}

read -p "Gateway [${DEFAULT_GW}]: " NET_GW
NET_GW=${NET_GW:-$DEFAULT_GW}

read -p "DNS [${DEFAULT_DNS}]: " NET_DNS
NET_DNS=${NET_DNS:-$DEFAULT_DNS}

read -p "Puerto API [8000]: " SERVER_PORT
SERVER_PORT=${SERVER_PORT:-8000}

echo ""
echo -e "${BLUE}Configurando:${NC}"
echo "  IP       : $SERVER_IP/24"
echo "  Interfaz : $NET_IFACE"
echo "  Gateway  : $NET_GW"
echo "  DNS      : $NET_DNS"
echo "  Puerto   : $SERVER_PORT"
echo ""
read -p "Continuar? [s/N]: " CONFIRM
if [[ ! "$CONFIRM" =~ ^[sS]$ ]]; then
  echo "Instalacion cancelada."
  exit 0
fi

# ── 4. Instalar dependencias del sistema ──────────────────────────────────
echo ""
echo -e "${GREEN}[1/7] Actualizando sistema e instalando dependencias...${NC}"
apt-get update -qq
apt-get install -y -qq \
  git \
  curl \
  wget \
  arp-scan \
  nmap \
  nbtscan \
  net-tools \
  python3 \
  python3-pip

# ── 5. Instalar Docker ────────────────────────────────────────────────────
echo -e "${GREEN}[2/7] Instalando Docker...${NC}"
if ! command -v docker &> /dev/null; then
  apt-get install -y -qq docker.io docker-compose-v2
  systemctl enable docker
  systemctl start docker
  usermod -aG docker "$REAL_USER"
  echo "  Docker instalado y configurado."
else
  echo "  Docker ya instalado: $(docker --version)"
fi

# Verificar docker compose
if ! docker compose version &> /dev/null; then
  apt-get install -y -qq docker-compose-v2
fi

# ── 6. Clonar repositorio ─────────────────────────────────────────────────
echo -e "${GREEN}[3/7] Instalando OT Inventory Tool...${NC}"
INSTALL_DIR="$REAL_HOME/ot-inventory-tool"

if [ -d "$INSTALL_DIR/.git" ]; then
  echo "  Repositorio existente — actualizando..."
  cd "$INSTALL_DIR"
  git pull origin main
else
  echo "  Clonando desde GitHub..."
  rm -rf "$INSTALL_DIR"
  git clone https://github.com/ldelgado71col-star/ot-inventory-tool.git "$INSTALL_DIR"
fi

chown -R "$REAL_USER:$REAL_USER" "$INSTALL_DIR"
echo "  Instalado en: $INSTALL_DIR"

# ── 7. Crear archivo .env ─────────────────────────────────────────────────
echo -e "${GREEN}[4/7] Configurando variables de entorno...${NC}"
cat > "$INSTALL_DIR/.env" << ENVEOF
POSTGRES_USER=otadmin
POSTGRES_PASSWORD=OtLabPassword123
POSTGRES_DB=ot_inventory
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
API_PORT=$SERVER_PORT
ENVEOF
chown "$REAL_USER:$REAL_USER" "$INSTALL_DIR/.env"
echo "  Archivo .env creado."

# ── 8. Configurar IP fija con Netplan ─────────────────────────────────────
echo -e "${GREEN}[5/7] Configurando IP estatica ($SERVER_IP)...${NC}"

NETPLAN_FILE="/etc/netplan/99-ot-inventory-static.yaml"

cat > "$NETPLAN_FILE" << NETEOF
network:
  version: 2
  renderer: networkd
  ethernets:
    $NET_IFACE:
      dhcp4: false
      addresses:
        - $SERVER_IP/24
      routes:
        - to: default
          via: $NET_GW
      nameservers:
        addresses:
          - $NET_DNS
          - 1.1.1.1
NETEOF

chmod 600 "$NETPLAN_FILE"
echo "  Netplan configurado en $NETPLAN_FILE"

# Aplicar configuracion de red
netplan apply 2>/dev/null || true
echo "  IP estatica aplicada."

# ── 9. Configurar IP en el dashboard ─────────────────────────────────────
echo -e "${GREEN}[6/7] Configurando dashboard con IP $SERVER_IP:$SERVER_PORT...${NC}"
DASHBOARD="$INSTALL_DIR/api/app/static/index.html"
if [ -f "$DASHBOARD" ]; then
  sed -i "s|const API = '.*'|const API = 'http://$SERVER_IP:$SERVER_PORT'|g" "$DASHBOARD"
  echo "  Dashboard configurado: http://$SERVER_IP:$SERVER_PORT"
else
  echo -e "  ${YELLOW}Advertencia: dashboard no encontrado en $DASHBOARD${NC}"
fi

# ── 10. Arrancar servicios Docker ─────────────────────────────────────────
echo -e "${GREEN}[7/7] Iniciando servicios...${NC}"
cd "$INSTALL_DIR"
docker compose down 2>/dev/null || true
docker compose up -d --build

# Esperar a que la DB este lista
echo "  Esperando base de datos..."
for i in $(seq 1 30); do
  if docker exec ot_inventory_db pg_isready -U otadmin -d ot_inventory &>/dev/null; then
    echo "  Base de datos lista."
    break
  fi
  sleep 2
  echo -n "."
done

# Verificar API
echo "  Verificando API..."
for i in $(seq 1 15); do
  if curl -sf "http://localhost:$SERVER_PORT/health" &>/dev/null; then
    echo "  API respondiendo correctamente."
    break
  fi
  sleep 2
  echo -n "."
done

# ── 11. Configurar servicio systemd ──────────────────────────────────────
echo -e "${GREEN}Configurando arranque automatico...${NC}"
cat > /etc/systemd/system/ot-inventory.service << SVCEOF
[Unit]
Description=OT Inventory Tool — Potenza Services
After=docker.service network-online.target
Requires=docker.service
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=$INSTALL_DIR
EnvironmentFile=$INSTALL_DIR/.env
ExecStart=/usr/bin/docker compose up -d
ExecStop=/usr/bin/docker compose down
TimeoutStartSec=300
User=root

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable ot-inventory.service
echo "  Servicio systemd configurado y habilitado."

# ── 12. Verificacion final ────────────────────────────────────────────────
echo ""
HEALTH=$(curl -sf "http://localhost:$SERVER_PORT/health" 2>/dev/null || echo '{"status":"error"}')
API_STATUS=$(echo "$HEALTH" | grep -o '"status":"[^"]*"' | cut -d'"' -f4)

echo -e "${BLUE}╔═════════════════════════════════════════════════════╗${NC}"
if [ "$API_STATUS" = "ok" ]; then
  echo -e "${BLUE}║         ✅  Instalacion Completada                 ║${NC}"
else
  echo -e "${BLUE}║         ⚠️   Instalacion con advertencias           ║${NC}"
fi
echo -e "${BLUE}╚═════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Dashboard : ${GREEN}http://$SERVER_IP:$SERVER_PORT${NC}"
echo -e "  API Docs  : ${GREEN}http://$SERVER_IP:$SERVER_PORT/docs${NC}"
echo -e "  API Health: ${GREEN}http://$SERVER_IP:$SERVER_PORT/health${NC}"
echo ""
echo -e "  Credenciales:"
echo -e "    Admin  : ${GREEN}Engineer / Luis2005+-*${NC}"
echo -e "    Field  : ${GREEN}FieldSupport / Support01${NC}"
echo -e "    Viewer : ${GREEN}View / View01${NC}"
echo ""
echo -e "  Directorio : $INSTALL_DIR"
echo -e "  Logs       : docker logs ot_inventory_api --tail 30"
echo ""
echo -e "  Arranque automatico habilitado."
echo -e "  La herramienta se inicia sola al encender el PC."
echo ""
if [ "$REAL_USER" != "root" ]; then
  echo -e "${YELLOW}  NOTA: Cierra sesion y vuelve a entrar para usar Docker sin sudo.${NC}"
  echo ""
fi
