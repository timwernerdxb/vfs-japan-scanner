FROM python:3.12-bookworm

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install Patchright Chromium + system deps (stealth Playwright fork)
RUN patchright install --with-deps chromium

# Copy application code
COPY . .

# Dispatch on Railway service name so the same image powers both services.
# Railway sets RAILWAY_SERVICE_NAME automatically; locally defaults to VFS.
CMD ["/bin/sh", "-c", "if [ \"$RAILWAY_SERVICE_NAME\" = nike-bot ]; then exec python nike_main.py; else exec python main.py; fi"]
