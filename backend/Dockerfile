FROM python:3.11-slim

# Install system dependencies required for scanning (nmap) and building
RUN apt-get update && apt-get install -y \
    nmap \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Let uvicorn start by default if no command is provided
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
