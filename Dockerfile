FROM python:3.12-bookworm

ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install Playwright Chromium + system deps
RUN playwright install --with-deps chromium

# Copy application code
COPY . .

CMD ["python", "main.py"]
