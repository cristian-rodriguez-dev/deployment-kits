cat > add_prometheus_agent.sh << 'SCRIPT'
#!/bin/bash
set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
RED='\033[0;31m'
NC='\033[0m' # Sin color

CONFIG_FILE="prometheus_server/prometheus/prometheus.yml"

echo -e "${BLUE}🛠️  Añadiendo nuevo agente a Prometheus...${NC}"

if [ ! -f "$CONFIG_FILE" ]; then
    echo -e "${RED}❌ No se encuentra el archivo $CONFIG_FILE.${NC}"
    echo -e "${YELLOW}Ejecuta este script desde la carpeta donde instalaste Prometheus.${NC}"
    exit 1
fi

read -r -p "Introduce el nombre del agente remoto: " AGENT_NAME
AGENT_NAME=$(echo "$AGENT_NAME" | tr ' ' '-')

read -r -p "Introduce la IP o dominio del agente remoto: " AGENT_IP

read -r -p "Introduce el puerto de Node Exporter [9100]: " AGENT_PORT
AGENT_PORT=${AGENT_PORT:-9100}

if grep -Fq -- "job_name: \"$AGENT_NAME\"" "$CONFIG_FILE"; then
    echo -e "${RED}❌ Ya existe un agente llamado '$AGENT_NAME'.${NC}"
    exit 1
fi

echo -e "${YELLOW}⚙️ Añadiendo configuración a prometheus.yml...${NC}"
cat << EOF >> "$CONFIG_FILE"

  - job_name: "$AGENT_NAME"
    static_configs:
      - targets: ["$AGENT_IP:$AGENT_PORT"]
        labels:
          nodename: "$AGENT_NAME"
EOF

echo -e "${GREEN}✅ Configuración del agente añadida.${NC}"

echo -e "${YELLOW}🔄 Reiniciando Prometheus...${NC}"
cd prometheus_server
sudo docker compose restart prometheus
cd ..

echo -e "${GREEN}✅ Agente '$AGENT_NAME' añadido a la configuración.${NC}"
echo -e "${BLUE}🌍 Comprueba que aparezca UP en: http://localhost:9090/targets${NC}"

echo -e "${YELLOW}🧹 Limpiando variables...${NC}"
unset AGENT_NAME
unset AGENT_IP
unset AGENT_PORT
unset CONFIG_FILE

unset GREEN
unset YELLOW
unset BLUE
unset RED
unset NC
SCRIPT

chmod +x add_prometheus_agent.sh && ./add_prometheus_agent.sh && rm -- add_prometheus_agent.sh