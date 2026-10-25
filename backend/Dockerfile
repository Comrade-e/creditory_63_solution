FROM python:3.12-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONPATH="/app:/app/backend/src"

COPY requirements.txt /app/requirements.txt

RUN pip install --no-cache-dir -r /app/requirements.txt

COPY . /app/backend/

EXPOSE 8000

CMD ["sh", "-c", "python -c 'from backend.src.db import init_db; init_db()' && uvicorn backend.src.main:app --host 0.0.0.0 --port 8000"]