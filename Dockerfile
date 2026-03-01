FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV DISPLAY=:0
ENV PORT=8080
ENV APP_USER=appuser
ENV APP_CACHE_DIR=/cache
ENV DATA_DIR=/data

RUN apt-get update && apt-get install -y --no-install-recommends \
  bash \
  ca-certificates \
  curl \
  dbus-x11 \
  fonts-dejavu-core \
  libappindicator3-1 \
  libasound2 \
  libatk-bridge2.0-0 \
  libdrm2 \
  libfuse2 \
  libgbm1 \
  libgdk-pixbuf2.0-0 \
  libglib2.0-0 \
  libgtk-3-0 \
  libnotify4 \
  libnss3 \
  libsecret-1-0 \
  libx11-xcb1 \
  libxkbcommon0 \
  libxshmfence1 \
  libxss1 \
  libxtst6 \
  openbox \
  python3-websockify \
  tini \
  unzip \
  x11-apps \
  x11-utils \
  x11vnc \
  x11-xserver-utils \
  xauth \
  wmctrl \
  xterm \
  xvfb \
  && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --shell /bin/bash "${APP_USER}" \
  && mkdir -p /app /cache /data \
  && chown -R "${APP_USER}:${APP_USER}" /cache /data /home/"${APP_USER}"

WORKDIR /app
COPY app /app
RUN sed -i 's/\r$//' /app/entrypoint.sh && chmod 0755 /app/entrypoint.sh

HEALTHCHECK --interval=20s --timeout=5s --start-period=20s --retries=3 CMD \
  curl --fail --silent http://127.0.0.1:${PORT}/ >/dev/null || exit 1

ENTRYPOINT ["/usr/bin/tini", "--", "/app/entrypoint.sh"]
