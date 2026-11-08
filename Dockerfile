# LX-Dork-Pro container image
FROM python:3.12-slim

LABEL org.opencontainers.image.title="LX-Dork-Pro"
LABEL org.opencontainers.image.description="Advanced multi-engine Google Dorking recon tool"
LABEL org.opencontainers.image.licenses="MIT"

# Keep Python output unbuffered so `rich` progress bars render live in
# `docker logs` / attached terminals instead of getting buffered away.
ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY requirements.txt pyproject.toml README.md ./
COPY lxdorkpro ./lxdorkpro

RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir .

# Run as an unprivileged user: this tool fetches attacker-influenceable URLs
# and parses untrusted content, so a bug in it should not mean root in the
# container. /app/out is where compose mounts scan output.
RUN useradd --create-home --uid 1000 lxdork && \
    mkdir -p /app/out /home/lxdork/.config/lx-dork-pro && \
    chown -R lxdork:lxdork /app /home/lxdork
USER lxdork

# Config/history live here so they can be mounted as a named volume and
# survive container recreation.
ENV LXDORK_HOME=/home/lxdork/.config/lx-dork-pro
VOLUME ["/home/lxdork/.config/lx-dork-pro"]

# Inside docker-compose, the bundled SearXNG service is reachable by name.
ENV LXDORK_SEARXNG_URL=http://searxng:8080

ENTRYPOINT ["lxdorkpro"]
CMD ["--help"]
