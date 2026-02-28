FROM node:20-bookworm-slim

ENV NODE_ENV=production
ENV PORT=3000

WORKDIR /app

COPY package.json /app/package.json
COPY src /app/src
COPY public /app/public
RUN find /app/src -type f -name "*.js" -exec sed -i 's/\r$//' {} + \
  && find /app/public -type f -name "*.html" -exec sed -i 's/\r$//' {} + \
  && node --check /app/src/server.js \
  && node --check /app/src/docker-api.js \
  && node --check /app/src/kubernetes-api.js \
  && node --check /app/src/catalog.js \
  && node --check /app/src/auth.js \
  && node --check /app/src/util.js \
  && node --check /app/src/logger.js

USER node

HEALTHCHECK --interval=20s --timeout=5s --start-period=10s --retries=3 CMD \
  node -e "fetch('http://127.0.0.1:' + (process.env.PORT || '3000') + '/healthz').then((response) => process.exit(response.ok ? 0 : 1)).catch(() => process.exit(1))"

CMD ["node", "src/server.js"]
