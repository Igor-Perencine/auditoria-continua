FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /srv

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY app ./app

# Executa sem privilégios de root
RUN useradd --system --uid 10001 --no-create-home appuser
USER appuser

EXPOSE 8000
# --proxy-headers: confia no X-Forwarded-For do Nginx (FORWARDED_ALLOW_IPS no compose)
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
