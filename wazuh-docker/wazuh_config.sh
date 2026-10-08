cat > wazuh_config.sh <<'SCRIPT'
#!/bin/bash
set -eo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
RED='\033[0;31m'
NC='\033[0m'

CONFIG_FILE="wazuh-docker/single-node/config/wazuh_dashboard/opensearch_dashboards.yml"
ZONA=${ZONA:-Europe/Madrid}
OSCURO=${OSCURO:-true}

echo -e "${BLUE}🛠️ Configurando Wazuh Dashboard...${NC}"

if [ ! -f "$CONFIG_FILE" ]; then
    echo -e "${RED}❌ No se encuentra el archivo $CONFIG_FILE.${NC}"
    echo -e "${YELLOW}Ejecuta este script desde la carpeta donde instalaste Wazuh.${NC}"
    exit 1
fi

echo -e "${YELLOW}📂 Entrando en single-node...${NC}"
cd wazuh-docker/single-node

echo -e "${YELLOW}💾 Guardando copia de la configuración...${NC}"
sudo cp config/wazuh_dashboard/opensearch_dashboards.yml \
    config/wazuh_dashboard/opensearch_dashboards.yml.bak

echo -e "${YELLOW}⚙️ Actualizando tema y zona horaria...${NC}"
sudo sed -i \
    -e '/^uiSettings\.overrides\.theme:darkMode:/d' \
    -e '/^uiSettings\.overrides\.dateFormat:tz:/d' \
    config/wazuh_dashboard/opensearch_dashboards.yml

sudo tee -a config/wazuh_dashboard/opensearch_dashboards.yml > /dev/null <<EOF

uiSettings.overrides.theme:darkMode: ${OSCURO}
uiSettings.overrides.dateFormat:tz: "${ZONA}"
EOF

echo -e "${YELLOW}🔄 Recreando únicamente Wazuh Dashboard...${NC}"
sudo docker compose up -d --no-deps --force-recreate wazuh.dashboard

echo -e "${GREEN}✅ Configuración aplicada.${NC}"
echo -e "${YELLOW}⏳ El Dashboard tardará un poco en responder.${NC}"
SCRIPT

chmod +x wazuh_config.sh && ./wazuh_config.sh && rm -- wazuh_config.sh