# Running locally in dev mode

```bash
export LOGLEVEL=INFO && gunicorn --reload  -w 3 -t 120 -b 0.0.0.0:8000 app:app
```

# Running in production

```bash
docker-compose up --build --force-recreate --no-deps -d web
```
