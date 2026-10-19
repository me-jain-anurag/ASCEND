FROM python:3.11-slim

WORKDIR /app

# Install Python dependencies for the API service + verifier
COPY service/requirements.txt /tmp/service-requirements.txt
COPY verifier/requirements.txt /tmp/verifier-requirements.txt
RUN pip install --no-cache-dir -r /tmp/service-requirements.txt \
    -r /tmp/verifier-requirements.txt

# Copy the entire repo (volumes override this in dev mode)
COPY . /app

EXPOSE 8000

CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload", "--app-dir", "service"]
