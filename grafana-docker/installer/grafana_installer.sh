cat > grafana_installer.sh << 'SCRIPT'
#!/bin/bash
set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
RED='\033[0;31m'
NC='\033[0m' # Sin color

echo -e "${BLUE}🛠️  Iniciando instalación de Grafana en Ubuntu...${NC}"
echo -e "${YELLOW}📦 Actualizando repositorios...${NC}"
sudo apt-get update -y

echo -e "${YELLOW}📦 Clonando repositorio...${NC}"
rm -rf grafana
git clone https://github.com/grafana/grafana.git

echo -e "${YELLOW}📂 Entrando en grafana...${NC}"
cd grafana

echo -e "${YELLOW}🔑 Solicitando credenciales de Grafana...${NC}"

read -r -p "Introduce el nombre del administrador [admin]: " ADMIN_USERNAME
ADMIN_USERNAME=${ADMIN_USERNAME:-admin}

while true; do
    read -r -s -p "Introduce la contraseña del administrador (mín. 8 caracteres): " ADMIN_PASSWORD
    echo ""

        if [ ${#ADMIN_PASSWORD} -ge 8 ]; then
        break
    else
        echo -e "${RED}❌ Debe tener al menos 8 caracteres.${NC}"
    fi
done

read -r -p "Introduce el correo del administrador [admin@localhost]: " ADMIN_EMAIL
ADMIN_EMAIL=${ADMIN_EMAIL:-admin@localhost}

echo -e "${YELLOW}🔑 Solicitando nombres de imagen, contenedor y red...${NC}"

read -r -p "Introduce el nombre de la imagen [grafana-personalizada]: " NOMBRE_IMAGEN
NOMBRE_IMAGEN=${NOMBRE_IMAGEN:-grafana-personalizada}

read -r -p "Introduce el nombre del contenedor [grafana]: " NOMBRE_CONTENEDOR
NOMBRE_CONTENEDOR=${NOMBRE_CONTENEDOR:-grafana}

read -r -p "Introduce la red Docker [single-node_default]: " NOMBRE_NETWORK
NOMBRE_NETWORK=${NOMBRE_NETWORK:-single-node_default}

echo -e "${YELLOW}🌐 Verificando red Docker: ${NOMBRE_NETWORK}...${NC}"
sudo docker network inspect "$NOMBRE_NETWORK" >/dev/null 2>&1 ||
    sudo docker network create "$NOMBRE_NETWORK"

echo -e "${YELLOW}📺 Aplicando configuraciones en conf/defaults.ini...${NC}"
sed -i "s|^admin_user =.*|admin_user = ${ADMIN_USERNAME}|g" conf/defaults.ini
sed -i "s|^admin_password =.*|admin_password = ${ADMIN_PASSWORD}|g" conf/defaults.ini
sed -i "s|^admin_email =.*|admin_email = ${ADMIN_EMAIL}|g" conf/defaults.ini

echo -e "${YELLOW}🐳 Construyendo la imagen de Grafana. Puede tardar bastante...${NC}"
sudo docker build -t "$NOMBRE_IMAGEN" .

echo -e "${YELLOW}🚀 Iniciando el contenedor de Grafana...${NC}"
sudo docker rm -f "$NOMBRE_CONTENEDOR" >/dev/null 2>&1 || true

sudo docker run -d \
    --name "$NOMBRE_CONTENEDOR" \
    --restart unless-stopped \
    --network "$NOMBRE_NETWORK" \
    -p 3000:3000 \
    -v grafana-data:/var/lib/grafana \
    "$NOMBRE_IMAGEN"

echo -e "${GREEN}✅ Contenedor de Grafana iniciado correctamente.${NC}"
echo -e "${YELLOW}⏳ Grafana puede tardar unos segundos en estar disponible.${NC}"
echo -e "${BLUE}🌍 Desde este equipo: http://localhost:3000${NC}"
echo -e "${BLUE}🌍 Desde otro equipo: http://IP_DEL_SERVIDOR:3000${NC}"
echo -e "${BLUE}👤 Usuario: ${ADMIN_USERNAME} | Contraseña: la que has introducido.${NC}"

echo -e "${YELLOW}🧹 Limpiando variables...${NC}"
unset ADMIN_USERNAME
unset ADMIN_PASSWORD
unset ADMIN_EMAIL
unset NOMBRE_IMAGEN
unset NOMBRE_CONTENEDOR
unset NOMBRE_NETWORK

unset GREEN
unset YELLOW
unset BLUE
unset RED
unset NC
SCRIPT

chmod +x grafana_installer.sh && ./grafana_installer.sh && rm -- grafana_installer.sh