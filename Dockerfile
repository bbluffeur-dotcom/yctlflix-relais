# Relais Yctlflix pour un hébergeur en ligne (Railway, etc.)
FROM node:24-slim
RUN apt-get update && apt-get install -y --no-install-recommends ffmpeg ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY package.json server.mjs parse.mjs admin.html app.html ./
# DATA = dossier du volume (à créer chez l'hébergeur, point de montage /data)
ENV HOST=0.0.0.0 \
    DATA=/data \
    ADMIN_REMOTE=1 \
    NODE_OPTIONS=--disable-warning=ExperimentalWarning
CMD ["node", "server.mjs"]
