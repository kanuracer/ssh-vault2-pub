FROM node:22-alpine

ENV NODE_ENV=production \
    HOST=0.0.0.0 \
    PORT=18080 \
    SSH_VAULT2_ROOT=/var/lib/ssh-vault2

WORKDIR /app

COPY server.mjs /app/server.mjs
COPY qrcode.js /app/qrcode.js

RUN mkdir -p /var/lib/ssh-vault2/downloads /var/lib/ssh-vault2/data \
    && chown -R node:node /var/lib/ssh-vault2 /app

USER node
EXPOSE 18080
VOLUME ["/var/lib/ssh-vault2"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||18080)+'/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "/app/server.mjs"]
