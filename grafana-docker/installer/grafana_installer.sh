cat > grafana_installer.sh << 'SCRIPT'
#!/bin/bash
set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
NC='\033[0m' # Sin color

echo -e "${BLUE}🛠️  Iniciando instalación de Grafana en Ubuntu...${NC}"
echo -e "${YELLOW}📦 Actualizando repositorios...${NC}"
sudo apt-get update -y

echo -e "${YELLOW}📦 Clonando repositorio...${NC}"
git clone https://github.com/grafana/grafana.git

echo -e "${YELLOW}📂 Entrando en grafana/conf...${NC}"
cd grafana/conf

echo -e "${YELLOW}🔑 Solicitando credenciales de Grafana...${NC}"

read -r -p "Introduce el nombre del administrador: " ADMIN_USERNAME
read -r -s -p "Introduce la contraseña del administrador: " ADMIN_PASSWORD
read -r -p "Introduce el correo del administrador: " ADMIN_EMAIL

echo -e "${YELLOW}📺 Modificando credenciales en defaults.ini...${NC}"
sed -i \
    -e "s|admin_user=.*|admin_user = ${ADMIN_USERNAME}|" \
    -e "s|admin_password=.*|admin_password = ${ADMIN_PASSWORD}|" \
    -e "s|admin_email=.*|admin_email = ${ADMIN_EMAIL}|" \
    defaults.ini

echo -e "${GREEN}✅ Credenciales actualizadas en defaults.ini.${NC}"

echo -e "${YELLOW}📂 Volviendo a grafana...${NC}"
cd ..

echo -e "${YELLOW}🔑 Solicitando nombres de imagen, contenedor y red...${NC}"
read -p "Introduce el nombre de la imagen [grafana-personalizada]: " NOMBRE_IMAGEN
NOMBRE_IMAGEN=${NOMBRE_IMAGEN:-grafana-personalizada}

read -p "Introduce el nombre del contenedor [grafana]: " NOMBRE_CONTENEDOR
NOMBRE_CONTENEDOR=${NOMBRE_CONTENEDOR:-grafana}

read -p "Introduce la red Docker [single-node_default]: " NOMBRE_NETWORK
NOMBRE_NETWORK=${NOMBRE_NETWORK:-single-node_default}

echo -e "${YELLOW}🐳 Construyendo la imagen de Grafana...${NC}"
sudo docker build -t "$NOMBRE_IMAGEN" .

echo -e "${YELLOW}🚀 Iniciando el contenedor de Grafana...${NC}"
sudo docker run -d \
    --name "$NOMBRE_CONTENEDOR" \
    --restart unless-stopped \
    --network "$NOMBRE_NETWORK" \
    -p 3000:3000 \
    -e GF_SECURITY_ADMIN_USER="$ADMIN_USERNAME" \
    -e GF_SECURITY_ADMIN_PASSWORD="$ADMIN_PASSWORD" \
    -e GF_SECURITY_ADMIN_EMAIL="$ADMIN_EMAIL" \
    -v grafana-data:/var/lib/grafana \
    "$NOMBRE_IMAGEN"

echo -e "${GREEN}✅ Contenedor de Grafana iniciado correctamente.${NC}"
echo -e "${BLUE}🌍 Puedes acceder a Grafana en: http://IP_DEL_SERVIDOR:3000${NC}"

chmod +x grafana_installer.sh && ./grafana_installer.sh && rm -- grafana_installer.sh