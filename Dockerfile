FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV DISPLAY=:0
ENV PORT=8080
ENV APP_USER=appuser
ENV APP_CACHE_DIR=/cache
ENV DATA_DIR=/data

RUN apt-get update && apt-get install -y --no-install-recommends \
  bash \
  bzip2 \
  ca-certificates \
  curl \
  desktop-file-utils \
  dbus-x11 \
  falkon \
  epiphany-browser \
  netsurf-gtk \
  fonts-dejavu-core \
  fonts-liberation \
  fonts-noto-color-emoji \
  libcairo2 \
  libcups2 \
  libegl1 \
  libgl1 \
  libglu1-mesa \
  libappindicator3-1 \
  libasound2 \
  libatspi2.0-0 \
  libatk-bridge2.0-0 \
  libdrm2 \
  libfuse2 \
  libgbm1 \
  libgconf-2-4 \
  libgdk-pixbuf2.0-0 \
  libgdk-pixbuf2.0-bin \
  libpng16-16 \
  libglib2.0-0 \
  libgtk-3-0 \
  librsvg2-common \
  librsvg2-2 \
  shared-mime-info \
  adwaita-icon-theme \
  hicolor-icon-theme \
  gnome-icon-theme \
  libnotify4 \
  libnss3 \
  libpango-1.0-0 \
  libsecret-1-0 \
  libx11-xcb1 \
  libxcomposite1 \
  libxdamage1 \
  libxfixes3 \
  libxkbcommon0 \
  libxkbfile1 \
  libxrandr2 \
  libxshmfence1 \
  libxss1 \
  libxtst6 \
  file \
  mesa-utils \
  openbox \
  procps \
  python3-websockify \
  tini \
  unzip \
  x11-apps \
  x11-utils \
  x11vnc \
  x11-xserver-utils \
  xrandr \
  xauth \
  xdg-utils \
  wmctrl \
  xclip \
  xsel \
  xdotool \
  xterm \
  xvfb \
  && GDK_PIXBUF_QL="$(find /usr/lib -name 'gdk-pixbuf-query-loaders*' -type f 2>/dev/null | head -1)" \
  && if [ -n "$GDK_PIXBUF_QL" ]; then echo "Found: $GDK_PIXBUF_QL"; "$GDK_PIXBUF_QL" --update-cache; fi \
  && echo "=== Pixbuf loaders ===" \
  && ls /usr/lib/*/gdk-pixbuf-2.0/*/loaders/libpixbufloader-png.so 2>/dev/null || echo "PNG loader not found" \
  && cat /usr/lib/*/gdk-pixbuf-2.0/*/loaders.cache 2>/dev/null | grep -c 'module_path' || true \
  && (update-mime-database /usr/share/mime 2>/dev/null || true) \
  && (gtk-update-icon-cache /usr/share/icons/hicolor 2>/dev/null || true) \
  && (gtk-update-icon-cache /usr/share/icons/Adwaita 2>/dev/null || true) \
  && rm -rf /var/lib/apt/lists/*

RUN dbus-uuidgen > /etc/machine-id 2>/dev/null || true \
  && useradd --create-home --shell /bin/bash "${APP_USER}" \
  && mkdir -p /app /cache /data \
  && chown -R "${APP_USER}:${APP_USER}" /cache /data /home/"${APP_USER}"

WORKDIR /app
COPY app /app
RUN sed -i 's/\r$//' /app/entrypoint.sh /app/xdg-open-bridge.sh /app/file-bridge.py 2>/dev/null || true \
  && chmod 0755 /app/entrypoint.sh /app/xdg-open-bridge.sh /app/file-bridge.py

HEALTHCHECK --interval=20s --timeout=5s --start-period=20s --retries=3 CMD \
  curl --fail --silent http://127.0.0.1:${PORT}/ >/dev/null || exit 1

ENTRYPOINT ["/usr/bin/tini", "--", "/app/entrypoint.sh"]
