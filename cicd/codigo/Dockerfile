FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p files && \
    echo "Default file content" > files/default.txt && \
    echo "SECRET: This should not be accessible!" > files/secret.txt

EXPOSE 5000

CMD ["python", "vulnerable-app.py"]