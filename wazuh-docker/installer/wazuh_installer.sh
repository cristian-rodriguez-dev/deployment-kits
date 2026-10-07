cat > wazuh_installer.sh << 'SCRIPT'
#!/bin/bash
set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
NC='\033[0m' # Sin color

echo -e "${BLUE}🛠️  Iniciando instalación de Wazuh en Ubuntu...${NC}"
echo -e "${YELLOW}📦 Actualizando repositorios...${NC}"
sudo apt-get update -y

echo -e "${YELLOW}📦 Clonando repositorio...${NC}"
git clone https://github.com/wazuh/wazuh-docker.git -b v4.14.8

echo -e "${YELLOW}📂 Moviendo a directorio single-node...${NC}"
cd wazuh-docker/single-node

echo -e "${YELLOW}🔐 Generando certificados...${NC}"
sudo docker compose -f generate-indexer-certs.yml run --rm generator

echo -e "${BLUE}🔐 Configuración de seguridad y credenciales personalizadas...${NC}"
echo -e "${YELLOW}🔑 Solicitando datos de seguridad...${NC}"

read -p "Introduce la nueva contraseña para el ADMIN: " PASS_ADMIN
read -p "Introduce la nueva contraseña para la API: " PASS_API
read -p "Introduce el puerto externo para el Dashboard [Por defecto 443]: " NUEVO_PUERTO
NUEVO_PUERTO=${NUEVO_PUERTO:-443}

echo -e "${YELLOW}🔑 Modificando credenciales en el bloque wazuh.manager...${NC}"
sed -i "/wazuh.manager:/,/wazuh.dashboard:/ {
    s|INDEXER_PASSWORD=.*|INDEXER_PASSWORD=${PASS_ADMIN}|
    s|API_PASSWORD=.*|API_PASSWORD=${PASS_API}|
}" docker-compose.yml

echo -e "${YELLOW}📺 Modificando credenciales y puerto en el bloque wazuh.dashboard...${NC}"
sed -i "/wazuh.dashboard:/,/depends_on:/ {
    s|INDEXER_PASSWORD=.*|INDEXER_PASSWORD=${PASS_ADMIN}|
    s|API_PASSWORD=.*|API_PASSWORD=${PASS_API}|
    s|- 443:5601|- ${NUEVO_PUERTO}:5601|
}" docker-compose.yml

echo -e "${YELLOW}⚙️ Aplicando cambios en config/wazuh_dashboard/wazuh.yml...${NC}"
sed -i "s|password: \".*\"|password: \"${PASS_API}\"|g" \
    config/wazuh_dashboard/wazuh.yml

echo -e "${GREEN}✅ Credenciales y puerto actualizados en los archivos de configuración.${NC}"

echo -e "${YELLOW}🔐 Generando hash para la cuenta ADMIN...${NC}"
# Contenedor temporal: genera el hash y se elimina automáticamente.
HASH_ADMIN=$(sudo docker run --rm \
    --entrypoint bash \
    -e JAVA_HOME=/usr/share/wazuh-indexer/jdk \
    wazuh/wazuh-indexer:4.14.8 \
    /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh \
    -p "$PASS_ADMIN" | tail -n 1)

HASH_ADMIN=$(echo "$HASH_ADMIN" | tr -d '\r')

echo -e "${YELLOW}⚙️ Aplicando el hash a la cuenta ADMIN...${NC}"
sed -i "/^admin:/,/^[^[:space:]]/ {
    s|^[[:space:]]*hash:.*|  hash: \"${HASH_ADMIN}\"|
}" config/wazuh_indexer/internal_users.yml

echo -e "${GREEN}✅ Hash de ADMIN configurado.${NC}"

echo -e "${YELLOW}🚀 Levantando contenedores...${NC}"
sudo docker compose up -d

echo -e "${GREEN}✅ ¡Instalación y configuración finalizadas!${NC}"
echo -e "${YELLOW}⏳ Wazuh puede tardar unos minutos en estar disponible.${NC}"
echo -e "${BLUE}🌍 Puedes acceder desde este equipo en: https://localhost:${NUEVO_PUERTO}${NC}"

echo -e "${YELLOW}🧹 Limpiando credenciales y variables de la memoria...${NC}"
unset PASS_ADMIN
unset PASS_API
unset HASH_ADMIN
unset NUEVO_PUERTO
unset REPLY

unset GREEN
unset YELLOW
unset BLUE
unset NC
SCRIPT

chmod +x wazuh_installer.sh && ./wazuh_installer.sh && rm -- wazuh_installer.sh