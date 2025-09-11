#!/usr/bin/env bash

set -Eeuo pipefail

REPO_URL="${REPO_URL:-https://github.com/SEU_USUARIO/SEU_REPO.git}"
GIT_BRANCH="${GIT_BRANCH:-main}"
PROJECT_DIR="${PROJECT_DIR:-$HOME/$(basename -s .git "$REPO_URL")}"
COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.yml}"
COMPOSE_PROFILES="${COMPOSE_PROFILES:-}" 
ENV_FILE_NAME="${ENV_FILE_NAME:-.env}"
ENV_TEMPLATES=(".env" ".env.example" ".env.template" "env.example")

log(){ printf "\033[1;36m[bootstrap]\033[0m %s\n" "$*"; }
ok(){  printf "\033[1;32m[  ok  ]\033[0m %s\n" "$*"; }
err(){ printf "\033[1;31m[ fail ]\033[0m %s\n" "$*" >&2; }
die(){ err "$*"; exit 1; }

need_cmd(){ command -v "$1" >/dev/null 2>&1 || die "Dependência ausente: $1"; }

preflight(){
  need_cmd docker
  docker compose version >/dev/null 2>&1 || die "Dependência ausente: docker compose (v2)"
  need_cmd git
  ok "Dependências encontradas: docker, docker compose, git."
}

clone_or_update_repo(){
  if [ -d "$PROJECT_DIR/.git" ]; then
    log "Atualizando repositório em: $PROJECT_DIR"
    (cd "$PROJECT_DIR" && git fetch --all --prune && git checkout "$GIT_BRANCH" && git pull --ff-only) \
      || die "Falha ao atualizar repositório."
  else
    log "Clonando repositório em: $PROJECT_DIR"
    git clone --branch "$GIT_BRANCH" --depth 1 "$REPO_URL" "$PROJECT_DIR" \
      || die "Falha ao clonar $REPO_URL"
  fi
  ok "Repositório pronto."
}

prepare_env(){
  local env_path="$PROJECT_DIR/$ENV_FILE_NAME"
  [ -f "$env_path" ] && { ok "$ENV_FILE_NAME já existe. Mantendo."; return; }

  for tmpl in "${ENV_TEMPLATES[@]}"; do
    if [ -f "$PROJECT_DIR/$tmpl" ] && [ "$PROJECT_DIR/$tmpl" != "$env_path" ]; then
      cp "$PROJECT_DIR/$tmpl" "$env_path"
      ok "Criado $ENV_FILE_NAME a partir de '$tmpl'."
      return
    fi
  done

  cat > "$env_path" <<'EOF'
# ===== .env gerado pelo bootstrap =====
APP_ENV=production
LOG_LEVEL=INFO
# Adicione aqui as variáveis necessárias ao seu stack.
EOF
  ok "Criado $ENV_FILE_NAME mínimo."
}

compose(){
  local args=()
  [ -n "$COMPOSE_PROFILES" ] && args=(--profile "$COMPOSE_PROFILES")
  (cd "$PROJECT_DIR" && docker compose -f "$COMPOSE_FILE" "${args[@]}" "$@")
}

start_stack(){
  [ -f "$PROJECT_DIR/$COMPOSE_FILE" ] || die "Arquivo $COMPOSE_FILE não encontrado em $PROJECT_DIR"
  log "Atualizando imagens (pull)..."; compose pull || true
  log "Build (se necessário)...";    compose build --pull || true
  log "Subindo containers...";       compose up -d
  ok "Stack em execução:"
  compose ps
}

next_steps(){
  cat <<EOF

==========================================
✅ Setup concluído

📁 Projeto: $PROJECT_DIR
📄 Compose: $COMPOSE_FILE

Comandos úteis:
- Status:  (cd "$PROJECT_DIR" && docker compose ps)
- Logs:    (cd "$PROJECT_DIR" && docker compose logs -f --tail=200)
- Subir:   (cd "$PROJECT_DIR" && docker compose up -d)
- Parar:   (cd "$PROJECT_DIR" && docker compose down)
==========================================
EOF
}

# Execução
log "Iniciando bootstrap (modo minimalista)..."
preflight
clone_or_update_repo
prepare_env
start_stack
next_steps
ok "Tudo pronto."
