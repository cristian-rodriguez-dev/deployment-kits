cat > prometheus_installer.sh << 'SCRIPT'
#!/bin/bash
set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
NC='\033[0m' # Sin color

echo -e "${BLUE}🛠️  Iniciando instalación de Prometheus en Ubuntu...${NC}"

echo -e "${YELLOW}📦 Actualizando repositorios del sistema...${NC}"
sudo apt-get update -y

echo -e "${YELLOW}🔑 Configuración de red, puertos y etiquetas...${NC}"

read -r -p "Introduce el nombre de este servidor [Servidor-Principal]: " NODENAME
NODENAME=${NODENAME:-Servidor-Principal}
NODENAME=$(echo "$NODENAME" | tr ' ' '-')

read -r -p "Introduce el puerto para la web de Prometheus [9090]: " PUERTO_PROM
PUERTO_PROM=${PUERTO_PROM:-9090}

read -r -p "Introduce el puerto para Node Exporter local [9100]: " PUERTO_NODE
PUERTO_NODE=${PUERTO_NODE:-9100}

read -r -p "Introduce la red Docker externa [single-node_default]: " NOMBRE_NETWORK
NOMBRE_NETWORK=${NOMBRE_NETWORK:-single-node_default}

echo -e "${YELLOW}📁 Creando estructura de directorios...${NC}"
mkdir -p prometheus_server/prometheus
mkdir -p prometheus_server/data

echo -e "${YELLOW}📂 Creando archivo prometheus.yml...${NC}"
cat << EOF > prometheus_server/prometheus/prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: "prometheus"
    static_configs:
      - targets: ["localhost:9090"]

  - job_name: "node-exporter-local"
    static_configs:
      - targets: ["host.docker.internal:${PUERTO_NODE}"]
        labels:
          nodename: "${NODENAME}"
EOF

echo -e "${YELLOW}📂 Creando archivo docker-compose.yml...${NC}"
cat << EOF > prometheus_server/docker-compose.yml
services:
  prometheus:
    image: prom/prometheus:latest
    container_name: prometheus
    user: "root"
    ports:
      - "${PUERTO_PROM}:9090"
    extra_hosts:
      - "host.docker.internal:host-gateway"
    volumes:
      - ./prometheus/prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - ./data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--storage.tsdb.retention.time=15d'
    restart: unless-stopped
    networks:
      - red_externa
    depends_on:
      - node-exporter

  node-exporter:
    image: prom/node-exporter:latest
    container_name: node-exporter
    restart: unless-stopped
    network_mode: host
    pid: host
    volumes:
      - /:/host:ro,rslave
    command:
      - '--path.rootfs=/host'
      - '--web.listen-address=:${PUERTO_NODE}'

networks:
  red_externa:
    name: "${NOMBRE_NETWORK}"
    external: true
EOF

echo -e "${YELLOW}📂 Entrando en prometheus_server...${NC}"
cd prometheus_server

echo -e "${YELLOW}🌐 Verificando red Docker: ${NOMBRE_NETWORK}...${NC}"
sudo docker network inspect "$NOMBRE_NETWORK" >/dev/null 2>&1 ||
    sudo docker network create "$NOMBRE_NETWORK"

echo -e "${YELLOW}🚀 Levantando el entorno de monitorización...${NC}"
sudo docker compose down
sudo docker compose up -d

echo -e "${GREEN}✅ ¡Prometheus y Node Exporter iniciados!${NC}"
echo -e "${BLUE}🌍 Panel de Prometheus: http://localhost:${PUERTO_PROM}${NC}"
echo -e "${BLUE}📊 Métricas de Node Exporter: http://localhost:${PUERTO_NODE}/metrics${NC}"
echo -e "${BLUE}🔎 Estado de los equipos: http://localhost:${PUERTO_PROM}/targets${NC}"
echo -e "${BLUE}🏷️ Etiqueta nodename: ${NODENAME}${NC}"

echo -e "${YELLOW}🧹 Limpiando variables...${NC}"
unset NODENAME
unset PUERTO_PROM
unset PUERTO_NODE
unset NOMBRE_NETWORK

unset GREEN
unset YELLOW
unset BLUE
unset NC
SCRIPT

chmod +x prometheus_installer.sh && ./prometheus_installer.sh && rm -- prometheus_installer.sh