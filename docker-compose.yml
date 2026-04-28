services:
  wiguard:
    build: .
    container_name: wiguard-nexus
    ports:
      - "5000:5000"
    environment:
      WIGUARD_ENV: production
      WIGUARD_HOST: 0.0.0.0
      WIGUARD_PORT: 5000
      WIGUARD_SECRET_KEY: change-me-with-a-long-random-secret
      WIGUARD_DISABLE_DEMO_FALLBACK: "1"
      WIGUARD_DB_PATH: /app/data/wiguard.sqlite3
      WIGUARD_DATA_FILE: /app/data/state.json
      WIGUARD_MAX_UPLOAD_BYTES: 52428800
    volumes:
      - ./data:/app/data
    restart: unless-stopped

  # Optional future PostgreSQL backend placeholder. Current app keeps SQLite for the demo/MVP.
  # postgres:
  #   image: postgres:16-alpine
  #   environment:
  #     POSTGRES_DB: wiguard
  #     POSTGRES_USER: wiguard
  #     POSTGRES_PASSWORD: change-me
  #   volumes:
  #     - postgres_data:/var/lib/postgresql/data

# volumes:
#   postgres_data:
