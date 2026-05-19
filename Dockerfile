FROM python:3.12-bookworm

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install Patchright Chromium + system deps (stealth Playwright fork)
RUN patchright install --with-deps chromium

# Copy application code
COPY . .

# Railway injects PORT at runtime.
ENV PORT=8080
EXPOSE 8080

CMD ["sh", "-c", "echo '[boot] starting uvicorn on port '${PORT:-8080} && exec python -m uvicorn server:app --host 0.0.0.0 --port ${PORT:-8080} --log-level info"]
