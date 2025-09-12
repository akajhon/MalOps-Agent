#!/usr/bin/env bash

set -eo pipefail

REPO_URL="https://github.com/akajhon/MalOps-Agent.git"
PROJECT_DIR="$(pwd)/MalOps-Agent"
COMPOSE_FILE="docker-compose.yml"

log(){ echo "[*] $*"; }
die(){ echo "[ERROR] $*" >&2; exit 1; }

# Handle Ctrl+C gracefully
cleanup(){
  echo -e "\n[!] Setup aborted by user. Exiting..."
  exit 1
}
trap cleanup INT

# Required dependencies
command -v docker >/dev/null 2>&1 || die "docker not found"
docker compose version >/dev/null 2>&1 || die "docker compose not found"
command -v git >/dev/null 2>&1 || die "git not found"
command -v unzip >/dev/null 2>&1 || die "unzip not found"

# Remove existing project directory if it already exists
if [ -d "$PROJECT_DIR" ]; then
  log "Removing existing directory at $PROJECT_DIR..."
  rm -rf "$PROJECT_DIR"
fi

# Clone repository
log "Cloning repository..."
git clone --branch main --depth 1 "$REPO_URL" "$PROJECT_DIR"

# Create .env from template
cp "$PROJECT_DIR/.env.example" "$PROJECT_DIR/.env"
log ".env file created from .env.example"

# Prompt user for API Keys
read -rp "Enter your GEMINI_API_KEY: " GEMINI_API_KEY
read -rp "Enter your VT_API_KEY: " VT_API_KEY
read -rp "Enter your OTX_API_KEY: " OTX_API_KEY
read -rp "Enter your HA_API_KEY: " HA_API_KEY
read -rp "Enter your ABUSE_API_KEY: " ABUSE_API_KEY

# Update .env with provided credentials
sed -i "s/^GEMINI_API_KEY=.*/GEMINI_API_KEY=$GEMINI_API_KEY/" "$PROJECT_DIR/.env"
sed -i "s/^VT_API_KEY=.*/VT_API_KEY=$VT_API_KEY/" "$PROJECT_DIR/.env"
sed -i "s/^OTX_API_KEY=.*/OTX_API_KEY=$OTX_API_KEY/" "$PROJECT_DIR/.env"
sed -i "s/^HA_API_KEY=.*/HA_API_KEY=$HA_API_KEY/" "$PROJECT_DIR/.env"
sed -i "s/^ABUSE_API_KEY=.*/ABUSE_API_KEY=$ABUSE_API_KEY/" "$PROJECT_DIR/.env"

log "API keys saved in $PROJECT_DIR/.env"

# Extract capa-rules.zip
log "Extracting capa-rules.zip..."
unzip -o "$PROJECT_DIR/rules/capa-rules.zip" -d "$PROJECT_DIR/rules/" >/dev/null

# Build + start containers
cd "$PROJECT_DIR"
log "Building containers..."
docker compose -f "$COMPOSE_FILE" build --pull
log "Starting containers..."
docker compose -f "$COMPOSE_FILE" up -d

# Final message
cat <<EOF

==========================================
✅ Setup completed

Addresses:
- API: http://localhost:8000/
- API Docs (Swagger): http://localhost:8000/docs
- UI: http://localhost:8501/

📁 Project: $PROJECT_DIR
📄 Compose file: $COMPOSE_FILE

Useful commands:
- Status:  (cd "$PROJECT_DIR" && docker compose ps)
- Logs:    (cd "$PROJECT_DIR" && docker compose logs -f --tail=200)
- Start:   (cd "$PROJECT_DIR" && docker compose up -d)
- Stop:    (cd "$PROJECT_DIR" && docker compose down)
==========================================
EOF
