FROM python:3.12-bookworm

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install Patchright Chromium + system deps (stealth Playwright fork)
RUN patchright install --with-deps chromium

# Copy application code
COPY . .

# Default entrypoint is the VFS scanner. For the Nike purchase service,
# set Railway's startCommand override to: python nike_main.py
CMD ["python", "main.py"]
