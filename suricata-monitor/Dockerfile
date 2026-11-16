FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py ai_model.py ./
COPY templates ./templates
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
EXPOSE 8080
CMD ["python", "app.py", "--eve", "/logs/eve.json", "--db", "/data/alerts.sqlite3", "--model", "/app/models/suricata_iforest.joblib", "--bind", "0.0.0.0", "--port", "8080"]
