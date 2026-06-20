FROM python:3.12-bookworm

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install Patchright Chromium + system deps (stealth Playwright fork)
RUN patchright install --with-deps chromium

# Install REAL Google Chrome — Akamai fingerprints bundled Chromium and
# blocks it even with stealth patches. Real Chrome gets past the Layer-4
# block that was returning Akamai 'Access Denied' on Railway.
RUN patchright install --with-deps chrome

# Xvfb (virtual display) so Chrome can run HEADFUL on Railway. Akamai
# keys off the headless=true flag — headful + Xvfb makes the browser
# look much closer to a real user session.
RUN apt-get update && apt-get install -y --no-install-recommends \
        xvfb xauth \
    && rm -rf /var/lib/apt/lists/*

# Copy application code
COPY . .

# Railway injects PORT at runtime (only meaningful for the HTTP server mode).
ENV PORT=8080
EXPOSE 8080

# Three dispatch modes, selected via BOT env var:
#   BOT=nike   -> Nike purchase bot (headful Chrome under Xvfb)
#   BOT=worker -> long-running VFS scanner (scanner.main)
#   else       -> VFS HTTP API server (uvicorn), the default
CMD ["/bin/sh", "-c", "\
if [ \"$BOT\" = nike ]; then \
    Xvfb :99 -screen 0 1280x800x24 -nolisten tcp & \
    export DISPLAY=:99 PYTHONUNBUFFERED=1; \
    sleep 2; \
    exec python -u nike_main.py; \
elif [ \"$BOT\" = worker ]; then \
    exec python main.py; \
else \
    echo '[boot] starting uvicorn on port '${PORT:-8080}; \
    exec python -m uvicorn server:app --host 0.0.0.0 --port ${PORT:-8080} --log-level info; \
fi"]
