from django.shortcuts import render
from django.http import JsonResponse 
from django.utils.decorators import method_decorator
from django.views import View
import json
from .utils.url_scanner import scan_url
from .utils.password_checker import check_password_strength
from .utils.email_analyzer import analyze_email
from .models import ScanHistory

def index(request):
    # Get recent scans for dashboard
    recent_scans = ScanHistory.objects.all().order_by('-created_at')[:5] if ScanHistory.objects.exists() else []
    return render(request, 'index.html', {'recent_scans': recent_scans})

def url_scanner(request):
    result = None
    if request.method == 'POST':
        url = request.POST.get('url')
        if url:
            result = scan_url(url)
            # Save to history
            ScanHistory.objects.create(
                scan_type='url',
                content=url,
                result=result
            )
    return render(request, 'url_scanner.html', {'result': result})


def password_checker(request):
    result = None
    if request.method == 'POST':
        password = request.POST.get('password')
        if password:
            result = check_password_strength(password)
            # Save to history
            ScanHistory.objects.create(
                scan_type='password',
                content=password[:3] + '*' * (len(password) - 3),  # Partial masking
                result=result
            )
    return render(request, 'password_checker.html', {'result': result})

def email_checker(request):
    result = None
    if request.method == 'POST':
        email_content = request.POST.get('email_content')
        if email_content:
            result = analyze_email(email_content)
            # Save to history
            ScanHistory.objects.create(
                scan_type='email',
                content=email_content[:100] + '...' if len(email_content) > 100 else email_content,
                result=result
            )
    return render(request, 'email_checker.html', {'result': result})

def scan_history(request):
    """View scan history"""
    scans = ScanHistory.objects.all().order_by('-created_at')
    return render(request, 'scan_history.html', {'scans': scans})
