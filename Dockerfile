FROM python:3.11-slim

RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*

# in log ra render ngay, khong cho xuat ra file bien dich cua python
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .

# cai cac goi phu thuoc
RUN python -m pip install --no-cache-dir -r requirements.txt && python -m pip uninstall -y pip setuptools wheel

RUN useradd --create-home appuser

COPY app.py .

USER appuser

EXPOSE 5000

CMD ["sh", "-c", "exec gunicorn --bind 0.0.0.0:${PORT:-5000} app:app"]
