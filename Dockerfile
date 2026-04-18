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

# For the Nike bot: wrap with xvfb-run so Chrome gets a virtual display.
# For VFS (BOT != nike): run as before, no display needed.
CMD ["/bin/sh", "-c", "if [ \"$BOT\" = nike ]; then Xvfb :99 -screen 0 1280x800x24 -nolisten tcp & export DISPLAY=:99 PYTHONUNBUFFERED=1; sleep 2; exec python -u nike_main.py; else exec python main.py; fi"]
