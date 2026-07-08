# Stage 1: Build
FROM node:18-alpine AS builder

WORKDIR /app

# Required build-time variables for Next.js
ARG NEXT_PUBLIC_GRAPH_DB_URL
ARG NEXT_PUBLIC_AGENT_URL
ARG NEXT_PUBLIC_RECON_URL
ARG NEXT_PUBLIC_EXPLOIT_RUNNER_URL
ARG NEXT_PUBLIC_REPORTING_URL

ENV NEXT_PUBLIC_GRAPH_DB_URL=$NEXT_PUBLIC_GRAPH_DB_URL
ENV NEXT_PUBLIC_AGENT_URL=$NEXT_PUBLIC_AGENT_URL
ENV NEXT_PUBLIC_RECON_URL=$NEXT_PUBLIC_RECON_URL
ENV NEXT_PUBLIC_EXPLOIT_RUNNER_URL=$NEXT_PUBLIC_EXPLOIT_RUNNER_URL
ENV NEXT_PUBLIC_REPORTING_URL=$NEXT_PUBLIC_REPORTING_URL

COPY package*.json ./
RUN npm install

COPY . .
RUN npm run build

# Stage 2: Production
FROM node:18-alpine AS runner

WORKDIR /app

ENV NODE_ENV=production

# Install curl for health checks
RUN apk add --no-cache curl

COPY --from=builder /app/public ./public
COPY --from=builder /app/.next ./.next
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./package.json

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
  CMD curl -f http://localhost:3000/ || exit 1

CMD ["npm", "start"]
