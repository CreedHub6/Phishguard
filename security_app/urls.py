from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('url-scanner/', views.url_scanner, name='url_scanner'),
    path('password-checker/', views.password_checker, name='password_checker'),
    path('email-checker/', views.email_checker, name='email_checker'),
    path('scan-history/', views.scan_history, name='scan_history'),
]
