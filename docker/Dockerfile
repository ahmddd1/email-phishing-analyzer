FROM python:3.9-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY src/ ./src/
COPY config/ ./config/
COPY samples/ ./samples/

# Create necessary directories
RUN mkdir -p logs reports

# Expose port
EXPOSE 5000

# Set environment variables
ENV PYTHONPATH=/app/src
ENV FLASK_APP=src/web/app.py

# Run the application
CMD ["python", "src/web/app.py"]