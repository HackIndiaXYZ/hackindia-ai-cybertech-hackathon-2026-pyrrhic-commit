# VeriRespond Production Dockerfile
FROM node:22-alpine AS builder

WORKDIR /app

# Copy dependency manifests
COPY package.json package-lock.json ./
COPY frontend/package.json frontend/package-lock.json ./frontend/

# Install dependencies
RUN npm ci && cd frontend && npm ci

# Copy application source
COPY . .

# Build frontend production bundle
RUN npm run build:frontend

# Runtime stage
FROM node:22-alpine

WORKDIR /app

# Install security updates
RUN apk update && apk upgrade && rm -rf /var/cache/apk/*

# Create dedicated non-root user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Copy application from builder
COPY --from=builder /app /app

# Setup data directory with correct permissions
RUN mkdir -p /app/data && chown -R appuser:appgroup /app

USER appuser

ENV NODE_ENV=production
ENV PORT=3000

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:3000/api/health || exit 1

CMD ["node", "src/server.js"]
