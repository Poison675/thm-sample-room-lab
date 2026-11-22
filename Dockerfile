FROM python:3.12-slim
RUN useradd -m lab
WORKDIR /app
COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app/ .
USER lab
# 0.0.0.0 inside the container only; publish to the host on 127.0.0.1 (see compose/README).
ENV HOST=0.0.0.0 PORT=8080
EXPOSE 8080
CMD ["python", "app.py"]
