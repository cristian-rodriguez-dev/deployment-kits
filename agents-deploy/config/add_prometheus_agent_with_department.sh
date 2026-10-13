cat > add_prometheus_agent_with_dep.sh << 'SCRIPT'
#!/bin/bash
set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
RED='\033[0;31m'
NC='\033[0m'

CONFIG_FILE="prometheus_server/prometheus/prometheus.yml"

echo -e "${BLUE}🛠️ Añadiendo equipo a Prometheus...${NC}"

if [ ! -f "$CONFIG_FILE" ]; then
    echo -e "${RED}❌ No se encuentra $CONFIG_FILE.${NC}"
    exit 1
fi

read -r -p "Introduce el departamento: " DEPARTAMENTO
DEPARTAMENTO=$(echo "$DEPARTAMENTO" | tr ' ' '-')

read -r -p "Introduce el nombre del equipo: " AGENT_NAME
AGENT_NAME=$(echo "$AGENT_NAME" | tr ' ' '-')

read -r -p "Introduce la IP o dominio del equipo: " AGENT_IP

read -r -p "Introduce el puerto de Node Exporter [9100]: " AGENT_PORT
AGENT_PORT=${AGENT_PORT:-9100}

if grep -Fq -- "targets: [\"$AGENT_IP:$AGENT_PORT\"]" "$CONFIG_FILE"; then
    echo -e "${RED}❌ Esa dirección ya está configurada.${NC}"
    exit 1
fi

if grep -Fq -- "job_name: \"$DEPARTAMENTO\"" "$CONFIG_FILE"; then
    echo -e "${YELLOW}⚙️ Añadiendo equipo al departamento existente...${NC}"

    TEMP_FILE=$(mktemp)

    awk \
        -v departamento="$DEPARTAMENTO" \
        -v nombre="$AGENT_NAME" \
        -v destino="$AGENT_IP:$AGENT_PORT" '
        /^  - job_name:/ {
            seleccionado = ($0 == "  - job_name: \"" departamento "\"")
        }

        seleccionado && /^    static_configs:/ {
            print "    static_configs:"
            print "      - targets: [\"" destino "\"]"
            print "        labels:"
            print "          nodename: \"" nombre "\""
            seleccionado = 0
            next
        }

        { print }
    ' "$CONFIG_FILE" > "$TEMP_FILE"

    # Conservar el archivo original para mantener su montaje en Docker.
    cat "$TEMP_FILE" > "$CONFIG_FILE"
    rm -- "$TEMP_FILE"

else
    echo -e "${YELLOW}📁 Creando departamento con su primer equipo...${NC}"

    cat << EOF >> "$CONFIG_FILE"

  - job_name: "$DEPARTAMENTO"
    static_configs:
      - targets: ["$AGENT_IP:$AGENT_PORT"]
        labels:
          nodename: "$AGENT_NAME"
EOF
fi

echo -e "${YELLOW}🔄 Reiniciando Prometheus...${NC}"
cd prometheus_server
sudo docker compose restart prometheus

echo -e "${GREEN}✅ Equipo '$AGENT_NAME' añadido a '$DEPARTAMENTO'.${NC}"
echo -e "${BLUE}🌍 Comprueba que aparezca UP en http://localhost:9090/targets${NC}"

unset DEPARTAMENTO AGENT_NAME AGENT_IP AGENT_PORT
unset CONFIG_FILE TEMP_FILE
unset GREEN YELLOW BLUE RED NC
SCRIPT

chmod +x add_prometheus_agent_with_dep.sh && ./add_prometheus_agent_with_dep.sh && rm -- add_prometheus_agent_with_dep.sh