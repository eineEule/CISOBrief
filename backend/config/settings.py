import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

DEBUG = os.getenv("DJANGO_DEBUG", "0") == "1"
SECRET_KEY = os.getenv("DJANGO_SECRET_KEY", "")
if not SECRET_KEY:
    if DEBUG:
        SECRET_KEY = "dev-only-insecure-key"
    else:
        raise RuntimeError("DJANGO_SECRET_KEY must be set when DJANGO_DEBUG is off")
ALLOWED_HOSTS = [h.strip() for h in os.getenv("DJANGO_ALLOWED_HOSTS", "localhost").split(",") if h.strip()]
CSRF_TRUSTED_ORIGINS = [o.strip() for o in os.getenv("DJANGO_CSRF_TRUSTED_ORIGINS", "http://localhost,http://127.0.0.1").split(",") if o.strip()]
SITE_URL = os.getenv("SITE_URL", "http://localhost").rstrip("/")

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django.contrib.sites",
    # Third party
    "allauth",
    "allauth.account",
    "django_celery_beat",
    # Local
    "apps.accounts",
    "apps.intelligence",
    "apps.reports",
    "apps.dashboard",
    "apps.mailers",
    "apps.watch",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "allauth.account.middleware.AccountMiddleware",
    "apps.accounts.middleware.RequireOrganizationMiddleware",
]

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {"context_processors": [
            "django.template.context_processors.debug",
            "django.template.context_processors.request",
            "django.contrib.auth.context_processors.auth",
            "django.contrib.messages.context_processors.messages",
        ]},
    },
]

WSGI_APPLICATION = "config.wsgi.application"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.getenv("POSTGRES_DB", "cisobrief"),
        "USER": os.getenv("POSTGRES_USER", "cisobrief"),
        "PASSWORD": os.getenv("POSTGRES_PASSWORD", ""),  # no built-in default credential; set it in .env
        "HOST": os.getenv("POSTGRES_HOST", "db"),
        "PORT": os.getenv("POSTGRES_PORT", "5432"),
    }
}
if os.getenv("USE_SQLITE") == "1":  # local smoke tests without Docker
    DATABASES["default"] = {"ENGINE": "django.db.backends.sqlite3", "NAME": BASE_DIR / "db.sqlite3"}

AUTH_USER_MODEL = "accounts.User"
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator", "OPTIONS": {"min_length": 12}},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]
AUTHENTICATION_BACKENDS = [
    "django.contrib.auth.backends.ModelBackend",
    "allauth.account.auth_backends.AuthenticationBackend",
]

# allauth: email-only login
SITE_ID = 1
ACCOUNT_USER_MODEL_USERNAME_FIELD = None
ACCOUNT_AUTHENTICATION_METHOD = "email"
ACCOUNT_EMAIL_REQUIRED = True
ACCOUNT_USERNAME_REQUIRED = False
ACCOUNT_EMAIL_VERIFICATION = "mandatory"
ACCOUNT_LOGOUT_ON_GET = False
ACCOUNT_SIGNUP_FORM_CLASS = "apps.accounts.forms.OrgSignupForm"  # company name / domain / industry on sign-up
LOGIN_URL = "/accounts/login/"
LOGIN_REDIRECT_URL = "/"
ACCOUNT_LOGOUT_REDIRECT_URL = "/accounts/login/"

LANGUAGE_CODE = "en-us"
TIME_ZONE = "America/New_York"
USE_I18N = True
USE_TZ = True
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_DIRS = [BASE_DIR / "static"]  # brand assets (logo, favicon)
MEDIA_URL = "/media/"
MEDIA_ROOT = BASE_DIR / "media"

# Email (Mailpit in dev, SES/SMTP later)
EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
EMAIL_HOST = os.getenv("EMAIL_HOST", "mailpit").strip()
EMAIL_PORT = int(os.getenv("EMAIL_PORT", "1025"))
EMAIL_HOST_USER = os.getenv("EMAIL_HOST_USER", "").strip()
EMAIL_HOST_PASSWORD = os.getenv("EMAIL_HOST_PASSWORD", "").replace(" ", "").strip()  # Gmail shows app passwords with spaces
EMAIL_USE_TLS = os.getenv("EMAIL_USE_TLS", "0").strip() == "1"   # STARTTLS, usually port 587
EMAIL_USE_SSL = os.getenv("EMAIL_USE_SSL", "0").strip() == "1"   # implicit TLS, usually port 465
if EMAIL_USE_TLS and EMAIL_USE_SSL:
    EMAIL_USE_SSL = False  # Django refuses both; 587/STARTTLS wins
EMAIL_TIMEOUT = int(os.getenv("EMAIL_TIMEOUT", "20"))
DEFAULT_FROM_EMAIL = os.getenv("DEFAULT_FROM_EMAIL", "cisobrief@localhost").strip()

# Celery
CELERY_BROKER_URL = os.getenv("CELERY_BROKER_URL", "redis://redis:6379/0")
CELERY_RESULT_BACKEND = os.getenv("CELERY_RESULT_BACKEND", "redis://redis:6379/1")
CELERY_ACCEPT_CONTENT = ["json"]
CELERY_TASK_SERIALIZER = "json"
CELERY_RESULT_SERIALIZER = "json"
CELERY_TIMEZONE = TIME_ZONE
CELERY_BEAT_SCHEDULER = "django_celery_beat.schedulers:DatabaseScheduler"
CELERY_BROKER_CONNECTION_RETRY_ON_STARTUP = True

# Threat intel pipeline
# AI (optional). Any OpenAI-compatible provider: OpenAI, Google Gemini (free tier), or a local Ollama (free).
# Blank AI_BASE_URL + blank AI_API_KEY = AI off; briefs still build without the written sections.
AI_BASE_URL = os.getenv("AI_BASE_URL", "").strip()
AI_API_KEY = (os.getenv("AI_API_KEY") or os.getenv("OPENAI_API_KEY") or "").strip()      # OPENAI_* kept for older .env files
def _default_ai_model(base_url: str) -> str:
    if "11434" in base_url or "ollama" in base_url:
        return "qwen2.5:7b"
    if "googleapis.com" in base_url:
        return "gemini-3.8-flash"
    return "gpt-4.1-mini"


AI_MODEL = (os.getenv("AI_MODEL") or "").strip() or (
    (os.getenv("OPENAI_MODEL") or "").strip() if not AI_BASE_URL else "") or _default_ai_model(AI_BASE_URL)
AI_TIMEOUT = int(os.getenv("AI_TIMEOUT", "120"))          # local CPU models can need 300+
AI_MAX_ITEMS = int(os.getenv("AI_MAX_ITEMS", "20"))       # items sent to the model; lower it for small local models
AI_MAX_TOKENS = int(os.getenv("AI_MAX_TOKENS", "4096"))   # reply length cap; too low cuts the JSON off
NVD_API_KEY = os.getenv("NVD_API_KEY", "")  # reserved: NVD enrichment not wired up yet
LOOKBACK_HOURS = int(os.getenv("LOOKBACK_HOURS", "24"))
SEVERITY_FLOOR = int(os.getenv("SEVERITY_FLOOR", "50"))

# Behind nginx
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
if not DEBUG:
    SESSION_COOKIE_SECURE = os.getenv("DJANGO_SECURE_COOKIES", "1") == "1"
    CSRF_COOKIE_SECURE = SESSION_COOKIE_SECURE
    SECURE_CONTENT_TYPE_NOSNIFF = True

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {"console": {"class": "logging.StreamHandler"}},
    "loggers": {"apps": {"handlers": ["console"], "level": "INFO"}},
}

# Early-warning sources (all free). Leave blank to skip that source.
OTX_API_KEY = os.getenv("OTX_API_KEY", "")            # https://otx.alienvault.com -> Settings -> API key
ABUSECH_AUTH_KEY = os.getenv("ABUSECH_AUTH_KEY", "")  # https://auth.abuse.ch -> Auth-Key (URLhaus)
