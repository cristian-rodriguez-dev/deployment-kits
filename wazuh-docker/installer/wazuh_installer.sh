cat > instalar_wazuh.sh << 'SCRIPT'
#!/bin/bash
set -eo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
RED='\033[0;31m'
NC='\033[0m' # Sin color

echo -e "${BLUE}🛠️  Iniciando instalación de Wazuh en Ubuntu...${NC}"
echo -e "${YELLOW}📦 Actualizando repositorios...${NC}"
sudo apt-get update -y

echo -e "${YELLOW}📦 Clonando repositorio...${NC}"
rm -rf wazuh-docker
git clone https://github.com/wazuh/wazuh-docker.git -b v4.14.8

echo -e "${YELLOW}📂 Moviendo a directorio single-node...${NC}"
cd wazuh-docker/single-node

echo -e "${YELLOW}🔐 Generando certificados...${NC}"
sudo docker compose -f generate-indexer-certs.yml run --rm generator

echo -e "${BLUE}🔐 Configuración de seguridad y credenciales personalizadas...${NC}"
echo -e "${YELLOW}🔑 Solicitando datos de seguridad...${NC}"

while true; do
    read -r -s -p "Introduce la contraseña de ADMIN (mín. 8 caracteres): " PASS_ADMIN
    echo ""

    if [ ${#PASS_ADMIN} -ge 8 ]; then
        break
    else
        echo -e "${RED}❌ Debe tener al menos 8 caracteres.${NC}"
    fi
done

while true; do
    read -r -s -p "Introduce la contraseña de la API (mín. 8 caracteres): " PASS_API
    echo ""

        if [ ${#PASS_API} -ge 8 ]; then
        break
    else
        echo -e "${RED}❌ Debe tener al menos 8 caracteres.${NC}"
    fi
done

read -r -p "Introduce el puerto externo para el Dashboard [Por defecto 443]: " NUEVO_PUERTO
NUEVO_PUERTO=${NUEVO_PUERTO:-443}

echo -e "${YELLOW}🔑 Modificando credenciales y puerto...${NC}"
sed -i "s|INDEXER_PASSWORD=.*|INDEXER_PASSWORD=${PASS_ADMIN}|g" docker-compose.yml
sed -i "s|API_PASSWORD=.*|API_PASSWORD=${PASS_API}|g" docker-compose.yml
sed -i "s|443:5601|${NUEVO_PUERTO}:5601|g" docker-compose.yml

echo -e "${YELLOW}⚙️ Aplicando cambios en config/wazuh_dashboard/wazuh.yml...${NC}"
sed -i "s|password: \".*\"|password: \"${PASS_API}\"|g" \
    config/wazuh_dashboard/wazuh.yml

echo -e "${GREEN}✅ Credenciales y puerto actualizados.${NC}"

echo -e "${YELLOW}🔐 Generando hash para la cuenta ADMIN...${NC}"
HASH_ADMIN=$(sudo docker run --rm \
    --entrypoint bash \
    -e JAVA_HOME=/usr/share/wazuh-indexer/jdk \
    wazuh/wazuh-indexer:4.14.8 \
    /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh \
    -p "$PASS_ADMIN" | tail -n 1)

HASH_ADMIN=$(echo "$HASH_ADMIN" | tr -d '\r')

if [[ ! "$HASH_ADMIN" =~ ^\$2[aby]\$ ]]; then
    echo -e "${RED}❌ No se pudo generar un hash válido para ADMIN.${NC}"
    exit 1
fi

echo -e "${YELLOW}⚙️ Aplicando el hash únicamente a la cuenta ADMIN...${NC}"
sed -i "/^admin:/,/^[^[:space:]]/ {
    s|^[[:space:]]*hash:.*|  hash: \"${HASH_ADMIN}\"|
}" config/wazuh_indexer/internal_users.yml

echo -e "${GREEN}✅ Hash de ADMIN configurado.${NC}"

echo -e "${YELLOW}🚀 Levantando contenedores...${NC}"
sudo docker compose up -d

echo -e "${GREEN}✅ ¡Contenedores arrancados y configuración preparada!${NC}"
echo -e "${YELLOW}⏳ Wazuh puede tardar unos minutos en estar disponible.${NC}"
echo -e "${BLUE}🌍 Desde este equipo: https://localhost:${NUEVO_PUERTO}${NC}"
echo -e "${BLUE}🌍 Desde otro equipo: https://IP_DEL_SERVIDOR:${NUEVO_PUERTO}${NC}"
echo -e "${BLUE}👤 Usuario: admin | Contraseña: la que has introducido.${NC}"

echo -e "${YELLOW}🧹 Limpiando variables sensibles...${NC}"
unset PASS_ADMIN
unset PASS_API
unset HASH_ADMIN
unset NUEVO_PUERTO

unset GREEN
unset YELLOW
unset BLUE
unset RED
unset NC
SCRIPT

chmod +x instalar_wazuh.sh && ./instalar_wazuh.sh && rm -- instalar_wazuh.sh