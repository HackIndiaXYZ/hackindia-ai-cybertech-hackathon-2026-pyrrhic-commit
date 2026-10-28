# VeriRespond Local Deployment Guide (Docker Compose)

## Prerequisites
- Docker Engine 20.10+
- Docker Compose v2+

## Quick Start

1. Start the VeriRespond Enforcement Connector:
   ```bash
   cd deploy
   docker compose up -d --build
   ```

2. Check service health:
   ```bash
   curl http://127.0.0.1:3000/api/health
   ```

3. Open the Executive Dashboard:
   Navigate to `http://127.0.0.1:3000` in your browser.

4. Connect an AI Agent using the SDK:
   ```javascript
   const { VeriRespondClient } = require('@verirespond/sdk');
   const client = new VeriRespondClient({ baseUrl: 'http://127.0.0.1:3000' });
   ```

## Security Configuration
- Container runs as unprivileged user `appuser`.
- Capabilities dropped: `ALL`.
- Bound strictly to loopback `127.0.0.1` by default to prevent unauthorized network access.
- Persistent evidence stored in named volume `verirespond_durable_evidence`.
