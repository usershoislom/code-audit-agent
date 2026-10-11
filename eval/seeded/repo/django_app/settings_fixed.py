import os

INSTALLED_APPS = ["django.contrib.auth", "django.contrib.contenttypes", "notes"]
SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]
DEBUG = os.environ.get("DJANGO_DEBUG") == "1"
ALLOWED_HOSTS = os.environ.get("DJANGO_ALLOWED_HOSTS", "").split(",")
ROOT_URLCONF = "notes.urls"
