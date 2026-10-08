cat > wazuh_config_agent.sh <<'SCRIPT'
#!/bin/bash
set -eo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
NC='\033[0m'

echo -e "${BLUE}🛠️ Configurando la IP del manager Wazuh...${NC}"

read -r -p "Nueva IP del servidor Wazuh: " NUEVA_IP

echo -e "${YELLOW}💾 Guardando copia de ossec.conf...${NC}"
sudo cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.bak

echo -e "${YELLOW}⚙️ Actualizando la dirección dentro del bloque client...${NC}"
sudo sed -i "/<client>/,/<\/client>/ {
    s|<address>[^<]*</address>|<address>${NUEVA_IP}</address>|
    s|<manager_address>[^<]*</manager_address>|<manager_address>${NUEVA_IP}</manager_address>|
}" /var/ossec/etc/ossec.conf

echo -e "${YELLOW}🔄 Reiniciando el agente...${NC}"
sudo systemctl restart wazuh-agent
sudo systemctl is-active wazuh-agent

echo -e "${GREEN}✅ Configuración actualizada y servicio iniciado.${NC}"
SCRIPT

chmod +x wazuh_config_agent.sh && ./wazuh_config_agent.sh && rm -- wazuh_config_agent.sh