FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENV WIGUARD_HOST=0.0.0.0 WIGUARD_PORT=5000 FLASK_DEBUG=0 WIGUARD_AUTH_REQUIRED=1
EXPOSE 5000
CMD ["python", "app.py"]
