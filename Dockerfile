FROM python:3.12-slim

ARG ACME_SH_VERSION=3.1.3
ARG ACME_SH_SHA256=efd12b265252f8875269960b6b31830731ccce2b3e6ff8e7ecfbee21fde35ab4
ARG APP_UID=10001
ARG APP_GID=10001

RUN apt-get update && apt-get install -y --no-install-recommends \
      bash ca-certificates curl openssl socat && \
    curl -fsSL "https://github.com/acmesh-official/acme.sh/archive/refs/tags/${ACME_SH_VERSION}.tar.gz" -o /tmp/acme.tar.gz && \
    echo "${ACME_SH_SHA256}  /tmp/acme.tar.gz" | sha256sum -c - && \
    tar xzf /tmp/acme.tar.gz -C /opt && rm /tmp/acme.tar.gz && \
    mv "/opt/acme.sh-${ACME_SH_VERSION}" /opt/acme.sh && \
    ln -s /opt/acme.sh /root/.acme.sh && \
    chmod 0711 /root && chmod 0555 /opt/acme.sh/acme.sh && \
    groupadd --gid "${APP_GID}" app && \
    useradd --uid "${APP_UID}" --gid app --home-dir /app --shell /usr/sbin/nologin app && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --disable-pip-version-check -r requirements.txt
COPY --chown=app:app app.py i18n.py certificates.py certificate_commands.py dns_slots.py get-cert.sh ./
COPY --chown=app:app templates ./templates
COPY --chown=app:app client ./client
RUN mkdir -p /app/data && chown app:app /app/data && chmod 0750 /app/data

USER app:app
ENV PORT=8787 PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
EXPOSE 8787
CMD ["waitress-serve", "--host=0.0.0.0", "--port=8787", "--threads=8", "app:app"]
