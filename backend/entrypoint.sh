#!/usr/bin/env sh
set -e

ROLE="${1:-web}"
echo "▶ Starting role: ${ROLE}"

echo "▶ Waiting for Postgres at ${POSTGRES_HOST}:${POSTGRES_PORT}..."
until nc -z "${POSTGRES_HOST}" "${POSTGRES_PORT}"; do sleep 1; done
echo "✅ Postgres is up."

if [ "$ROLE" = "web" ]; then
  # Only the web container migrates and collects static (avoids a 3-way migration race).
  echo "▶ Running migrations..."
  python manage.py migrate --noinput
  echo "▶ Collecting static..."
  python manage.py collectstatic --noinput

  if [ "${DJANGO_DEBUG}" = "1" ]; then
    echo "▶ Running Django dev server..."
    exec python manage.py runserver 0.0.0.0:8000
  else
    echo "▶ Running Gunicorn..."
    exec gunicorn config.wsgi:application --bind 0.0.0.0:8000 --workers 3 --timeout ${GUNICORN_TIMEOUT:-300}
  fi
fi

# worker / beat: wait until web has applied all migrations
echo "▶ Waiting for migrations to be applied by web..."
until python manage.py migrate --check >/dev/null 2>&1; do sleep 3; done
echo "✅ Schema is current."

if [ "$ROLE" = "worker" ]; then
  echo "▶ Running Celery worker..."
  exec celery -A config.celery_app worker -l INFO
fi

if [ "$ROLE" = "beat" ]; then
  echo "▶ Running Celery beat..."
  exec celery -A config.celery_app beat -l INFO --scheduler django_celery_beat.schedulers:DatabaseScheduler
fi

echo "❌ Unknown role: ${ROLE}"
exit 1
