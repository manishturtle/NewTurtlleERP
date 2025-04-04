# settings.py
"""
Django settings for KeyProductSettings project.

Generated by 'django-admin startproject' using Django 4.2.10.
Modified for django_tenants multi-tenancy.
"""

from pathlib import Path
from datetime import timedelta
import os # Recommended for environment variables

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# --- Secrets and Debugging ---
# SECURITY WARNING: keep the secret key used in production secret!
# Consider using environment variables for secrets
SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY', 'django-insecure-8f_ln2-aly%)49y!u=*en82-i$feq0(6#y5*sbu3(9*6p4)ysg') # Example using os.environ

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = os.environ.get('DJANGO_DEBUG', 'True') == 'True'

ALLOWED_HOSTS = os.environ.get('DJANGO_ALLOWED_HOSTS', 'localhost,127.0.0.1,0.0.0.0').split(',')


# --- Application definition ---

# Define Custom User Model *before* app lists
AUTH_USER_MODEL = 'ecomm_superadmin.User'

# Combined INSTALLED_APPS for development
# Define which apps are shared (in public schema) and which are tenant-specific
SHARED_APPS = (
    'django_tenants',  # mandatory
    'ecomm_superadmin',  # app containing your tenant model
    'django.contrib.contenttypes',
    'django.contrib.auth',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.admin',
    'django.contrib.staticfiles',
    'corsheaders',
    'rest_framework',
    'rest_framework.authtoken',     # Links to ecomm_superadmin.User (shared)
    'rest_framework_simplejwt', # Links to ecomm_superadmin.User (shared)
  
    
)

TENANT_APPS = (
    #'django.contrib.contenttypes',
    #'django.contrib.auth',
    #'django.contrib.sessions',
    #'django.contrib.messages',
    #'django.contrib.admin',
    #'django.contrib.staticfiles',
    #'rest_framework',
    #'rest_framework.authtoken',
    #'rest_framework_simplejwt',
    #'corsheaders',
    'ecomm_tenant.ecomm_tenant_admins',
    'ecomm_inventory',
    'ecomm_product',  # Product management app
    # 'ecomm_tenant_crmclients',  # Commented out non-existent app
)

INSTALLED_APPS = list(SHARED_APPS) + [app for app in TENANT_APPS if app not in SHARED_APPS]

# --- Middleware ---
# Order matters! TenantMiddleware must be first
MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',  # This should be at the top
    'ecomm_tenant.ecomm_tenant_admins.middleware.TenantRoutingMiddleware',  # Custom middleware
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'ecomm_superadmin.middleware.CSRFExemptAPIMiddleware',  # Our custom CSRF exempt middleware
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    # 'ecomm_superadmin.middleware.TenantRoutingMiddleware', # REMOVE or COMMENT OUT your custom middleware
]

# --- URL Configuration ---
# ROOT_URLCONF is used for requests to tenant schemas (with tenant slug)
#ROOT_URLCONF = 'KeyProductSettings.urls'
# PUBLIC_SCHEMA_URLCONF is used for requests to the public tenant (no tenant slug)
#PUBLIC_SCHEMA_URLCONF = 'KeyProductSettings.urls_public' # You MUST create this file!

# --- Templates ---
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'templates')],
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

# --- WSGI ---
WSGI_APPLICATION = 'KeyProductSettings.wsgi.application'


# --- Database ---
# https://docs.djangoproject.com/en/4.2/ref/settings/#databases
# Configure for PostgreSQL with django_tenants
DATABASES = {
    'default': {
        'ENGINE': 'django_tenants.postgresql_backend', # Correct engine for django_tenants
        'NAME': os.environ.get('DB_NAME', 'turtleerp'), # Use lowercase to match existing DB
        'USER': os.environ.get('DB_USER', 'postgres'),
        'PASSWORD': os.environ.get('DB_PASSWORD', 'Qu1ckAss1st@123'),
        'HOST': os.environ.get('DB_HOST', 'localhost'),
        'PORT': os.environ.get('DB_PORT', '5432'),
    }
}

"""DATABASES = {
    'default': {
 
        'USER': 'postgres', # Ensure this is correct
        'PASSWORD': 'India@123', # Replace with the real password
        'HOST': 'localhost', # Ensure this is correct
        'PORT': '5432',      # Ensure this is correct
        'NAME': 'turtleerp', # Ensure this database exists
    }
}"""


# --- Password validation ---
# https://docs.djangoproject.com/en/4.2/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# --- Internationalization ---
# https://docs.djangoproject.com/en/4.2/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


# --- Media files (user-uploaded content) ---
MEDIA_URL = '/media/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')

# --- Static files (CSS, JavaScript, Images) ---
STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')

# Add a directory for shared static files
STATICFILES_DIRS = [
    os.path.join(BASE_DIR, 'static'),
]

# --- Default primary key field type ---
# https://docs.djangoproject.com/en/4.2/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# --- Rest Framework ---
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
        'rest_framework.authentication.SessionAuthentication',
        'rest_framework.authentication.BasicAuthentication',
    ),
    'DEFAULT_PERMISSION_CLASSES': (
        'rest_framework.permissions.IsAuthenticated',
    ),
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 10,
}

# --- Simple JWT ---
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(days=1),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=7),
    'ROTATE_REFRESH_TOKENS': False,
    'BLACKLIST_AFTER_ROTATION': True,
    'ALGORITHM': 'HS256',
    'SIGNING_KEY': SECRET_KEY,
    'VERIFYING_KEY': None,
    'AUTH_HEADER_TYPES': ('Bearer',),
    'USER_ID_FIELD': 'id',
    'USER_ID_CLAIM': 'user_id',
    'AUTH_TOKEN_CLASSES': ('rest_framework_simplejwt.tokens.AccessToken',),
    'TOKEN_TYPE_CLAIM': 'token_type',
}

# --- CORS ---
# Configure CORS to allow requests from your frontend
CORS_ALLOW_CREDENTIALS = True

# Explicitly list allowed origins for better security
CORS_ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://localhost:3001",
    "http://localhost:3002",
    "http://localhost:8000",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:3001",
    "http://127.0.0.1:3002",
    "http://127.0.0.1:8000",
]

# CSRF settings
CSRF_COOKIE_SECURE = False  # Set to True in production with HTTPS
CSRF_COOKIE_HTTPONLY = False  # Allow JavaScript to access the cookie
CSRF_USE_SESSIONS = False  # Store CSRF token in cookie, not session
CSRF_TRUSTED_ORIGINS = [
    "http://localhost:3000",
    "http://localhost:3001",
    "http://localhost:3002", 
    "http://localhost:8000",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:3001",
    "http://127.0.0.1:3002",
    "http://127.0.0.1:8000",
]

# Allow all CORS headers and methods for development
CORS_ALLOW_ALL_ORIGINS = True  # Enable this for development to accept requests from all origins

CORS_ALLOW_HEADERS = [
    'accept',
    'accept-encoding',
    'authorization',
    'content-type',
    'dnt',
    'origin',
    'user-agent',
    'x-csrftoken',
    'x-requested-with',
    'x-platform-admin',
    'x-tenant-admin',
    'x-tenant-name',
    'X-Tenant-Admin',
    'X-Tenant-Name'
]

CORS_ALLOW_METHODS = [
    'DELETE',
    'GET',
    'OPTIONS',
    'PATCH',
    'POST',
    'PUT',
]

# Enable CORS for all URLs
CORS_URLS_REGEX = r'^.*$'

# --- Django Tenants Configuration ---
TENANT_MODEL = 'ecomm_superadmin.Tenant'  # app.Model containing tenant
TENANT_DOMAIN_MODEL = 'ecomm_superadmin.Domain'  # app.Model containing domains

# Tenant subfolder configuration
TENANT_SUBFOLDER_PREFIX = 'api'  # Prefix for subfolders
TENANT_SUBFOLDER_URLS = True  # Enable subfolder-based URLs

TENANT_LIMIT_SET_CALLS = False

# Configure tenant URLs
PUBLIC_SCHEMA_URLCONF = 'KeyProductSettings.urls_public'  # URLs for the public schema
ROOT_URLCONF = 'KeyProductSettings.urls'  # URLs for tenant schemas

# Function to get tenant URL
def get_tenant_url(tenant_slug):
    """
    Return the full URL for a tenant based on the current environment
    """
    if DEBUG:
        return f"http://localhost:8000/{tenant_slug}"
    else:
        return f"https://yourdomain.com/{tenant_slug}"


# --- Logging ---
# Configure logging for better debugging and production monitoring
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {message}',
            'style': '{',
        },
        'simple': {
            'format': '{levelname} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
       # 'file': {
       #     'level': 'INFO',
       #     'class': 'logging.FileHandler',
       #     'filename': os.path.join(BASE_DIR, 'logs/django.log'),
       #     'formatter': 'verbose',
       # },
    },
    'loggers': {
        
        'django': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': True,
        },
        'django.request': {
            'handlers': ['console'],
            'level': 'DEBUG',
            'propagate': False,
        },
        'django_tenants': {
            'handlers': ['console'],
            'level': 'DEBUG',
            'propagate': False,
        },
    },
}

DATABASE_ROUTERS = (
    'django_tenants.routers.TenantSyncRouter',
)
