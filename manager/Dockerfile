FROM node:20-bookworm-slim

ENV NODE_ENV=production
ENV PORT=3000

WORKDIR /app

COPY package.json /app/package.json
COPY src /app/src
COPY public /app/public

USER node

HEALTHCHECK --interval=20s --timeout=5s --start-period=10s --retries=3 CMD \
  node -e "fetch('http://127.0.0.1:' + (process.env.PORT || '3000') + '/healthz').then((response) => process.exit(response.ok ? 0 : 1)).catch(() => process.exit(1))"

CMD ["node", "src/server.js"]
