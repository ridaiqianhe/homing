FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      curl bash openssl ca-certificates socat && \
    curl -fsSL https://github.com/acmesh-official/acme.sh/archive/refs/heads/master.tar.gz \
      | tar xz -C /root && mv /root/acme.sh-master /root/.acme.sh && \
    chmod +x /root/.acme.sh/acme.sh && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
COPY templates ./templates
COPY get-cert.sh ./get-cert.sh
ENV PORT=8787
EXPOSE 8787
CMD ["waitress-serve", "--host=0.0.0.0", "--port=8787", "--threads=8", "app:app"]
