import os
from pathlib import Path

# Base directory
BASE_DIR = Path(__file__).resolve().parent.parent

# Load environment variables (Recommended for production)
SECRET_KEY = os.getenv('DJANGO_SECRET_KEY', 'django-insecure-ogni_0%$ugoim30f2f+8cl%#llfwwx5i(cz9mi4p7a-nrsnn^(')

# SECURITY WARNING: Don't run with debug turned on in production!
DEBUG = os.getenv('DJANGO_DEBUG', 'True') == 'True'
DEBUG = True

ALLOWED_HOSTS = os.getenv('DJANGO_ALLOWED_HOSTS', 'eshiroflex.zapto.org').split(',')


# Installed apps
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    
    
    'rest_framework',
    'django_extensions',
    'rest_framework.authtoken',
    'store',
    'corsheaders',
]

# Middleware
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    
    # CORS Middleware (optional)
    'corsheaders.middleware.CorsMiddleware',
    
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

# URL Configuration
ROOT_URLCONF = 'eshiroflex.urls'

# Templates
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],  # Optional for custom templates
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

# WSGI Application
WSGI_APPLICATION = 'eshiroflex.wsgi.application'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.getenv('DB_NAME', 'neondb'),  # Database name from Neon
        'USER': os.getenv('DB_USER', 'neondb_owner'),  # User from Neon
        'PASSWORD': os.getenv('DB_PASSWORD', 'npg_0Xxb1VYBUZWK'),  # Extracted password
        'HOST': os.getenv('DB_HOST', 'ep-late-lab-a5o3tzn2-pooler.us-east-2.aws.neon.tech'),  # Host from Neon
        'PORT': os.getenv('DB_PORT', '5432'),  # Default PostgreSQL port
        'OPTIONS': {
            'sslmode': 'require',  # Ensures secure connection
        },
    }
}


# Authentication
AUTH_USER_MODEL = 'store.User'


REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.TokenAuthentication',
        'rest_framework.authentication.SessionAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
    'DEFAULT_PARSER_CLASSES': [
        'rest_framework.parsers.JSONParser',
    ],
}

# Password Validation
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

# Language & Timezone
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# Static & Media Files
STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'static')

# Default Auto Field
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# 🚀 Email Settings (For Reset Password)
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'  # Use console backend for testing
EMAIL_HOST = 'smtp@gmail.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = os.getenv('EMAIL_HOST_USER', 'eshiroflex@gmail.com')
EMAIL_HOST_PASSWORD = os.getenv('EMAIL_HOST_PASSWORD', 'buri wktu cqwo putk')

# Debugging Email (Optional for Local Testing)
if DEBUG:
    EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'

CORS_ALLOW_ALL_ORIGINS = True 

CORS_ALLOW_CREDENTIALS = True

# CORS (For frontend connection)
CORS_ALLOWED_ORIGINS = [
    "https://eshiroflex-git-eshiroflex-ericamonacillos-projects.vercel.app",
    "http://localhost:5173",  # Change based on frontend URL
    "http://127.0.0.1:5173",
    "http://eshiroflex.zapto.org"
]

# CSRF Trusted Origins
CSRF_TRUSTED_ORIGINS = [
    "http://localhost:3000",
    "http://eshiroflex.zapto.org"
]
