FROM python:3.12-bookworm

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install Patchright Chromium + system deps (stealth Playwright fork)
RUN patchright install --with-deps chromium

# Copy application code
COPY . .

# Dispatch on an explicit BOT env var (set per Railway service) so one
# image powers both services. BOT=nike -> Nike purchase bot; else VFS.
CMD ["/bin/sh", "-c", "if [ \"$BOT\" = nike ]; then exec python nike_main.py; else exec python main.py; fi"]
