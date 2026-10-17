FROM python:3.14-slim-trixie

COPY --from=ghcr.io/astral-sh/uv:0.13.1 /uv /bin/

# wg reads the kernel's WireGuard state over netlink; no kernel module or
# userspace implementation is needed in the image.
RUN apt-get update \
    && apt-get install -y --no-install-recommends wireguard-tools \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/app/.venv

COPY pyproject.toml uv.lock /app/
RUN uv sync --locked --no-dev --no-install-project --no-cache

COPY exporter/ /app/

EXPOSE 9586

# Run the venv interpreter directly: `uv run` would re-sync at startup, which
# fails on a read-only root filesystem.
CMD ["/app/.venv/bin/python", "main.py"]
