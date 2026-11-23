# TunAI Personal Gateway

Personal AI & MCP Gateway built on Rust `agentgateway` with a personalized Admin UI and automated Docker builds via GitHub Actions (GHCR).

## Quick Start (Docker)

1. Copy environment variables:
   ```bash
   cp .env.example .env
   ```
   Fill in your provider keys (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`) in `.env`.

2. Start the gateway:
   ```bash
   docker compose -f docker-compose.personal.yml up -d
   ```

3. Access:
   - **Admin UI**: `http://localhost:15005/ui/`
   - **LLM / MCP Data Plane**: `http://localhost:3000`
   - **Metrics / Readiness**: `http://localhost:15020`, `http://localhost:15021`

## GitHub Actions Deployment

Pushing to `main` triggers `.github/workflows/docker-publish.yml`, which builds the multi-stage Docker image (UI + Rust core + Python UI proxy) and pushes it to:

`ghcr.io/tunbq21/agent_gateway_personal:latest`

On any VPS/server:
```bash
docker compose -f docker-compose.personal.yml pull
docker compose -f docker-compose.personal.yml up -d
```

## Security Notes

When exposing the Admin UI (`15005`) outside localhost, set both in `.env`:
```env
PERSONAL_UI_REQUIRE_AUTH=true
PERSONAL_UI_ADMIN_TOKEN=<strong-random-token>
```
