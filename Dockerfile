FROM python:3.11-slim

# in log ra render ngay, khong cho xuat ra file bien dich cua python
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .

# nang cap cac goi cong cu trong base image
RUN python -m pip install --no-cache-dir --upgrade pip setuptools wheel

# cai cac goi phu thuoc
RUN python -m pip install --no-cache-dir -r requirements.txt

RUN useradd --create-home appuser

COPY app.py .

USER appuser

EXPOSE 5000

CMD ["sh", "-c", "exec gunicorn --bind 0.0.0.0:${PORT:-5000} app:app"]
