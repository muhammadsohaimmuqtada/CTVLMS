import requests
import re
import sys
import time
import os
from bs4 import BeautifulSoup

BASE_URL = 'http://localhost:8000'
ADMIN_EMAIL = os.environ.get('CTVLMS_TEST_ADMIN_EMAIL')
ADMIN_PASSWORD = os.environ.get('CTVLMS_TEST_ADMIN_PASSWORD')
session = requests.Session()

def get_csrf_token(html):
    soup = BeautifulSoup(html, 'html.parser')
    token_input = soup.find('input', {'name': 'csrf_token'})
    if token_input:
        return token_input['value']
    return None

def test_login():
    print("[*] Testing Login...")
    resp = session.get(f"{BASE_URL}/?page=login")
    if resp.status_code != 200:
        print(f"[-] Failed to load login page. Status: {resp.status_code}")
        return False
    
    csrf_token = get_csrf_token(resp.text)
    if not csrf_token:
        print("[-] Could not find CSRF token on login page.")
        return False
    
    # Attempt login
    login_data = {
        'csrf_token': csrf_token,
        'email': ADMIN_EMAIL,
        'password': ADMIN_PASSWORD
    }
    
    # Use allow_redirects=False to catch the redirect to dashboard
    resp_post = session.post(f"{BASE_URL}/?page=login", data=login_data, allow_redirects=False)
    
    if resp_post.status_code in [301, 302] and 'dashboard' in resp_post.headers.get('Location', ''):
        print("[+] Login successful! Redirected to dashboard.")
        return True
    else:
        print(f"[-] Login failed. Status: {resp_post.status_code}")
        return False

def test_page(page_name):
    print(f"[*] Testing {page_name}...")
    resp = session.get(f"{BASE_URL}/?page={page_name}")
    
    if resp.status_code == 200:
        if 'Fatal error' in resp.text or 'Parse error' in resp.text or 'Uncaught PDOException' in resp.text:
            print(f"[-] PHP Error found on {page_name}!")
            return False
        print(f"[+] {page_name} loaded successfully.")
        return True
    else:
        print(f"[-] Failed to load {page_name}. Status: {resp.status_code}")
        return False

def main():
    if not ADMIN_EMAIL or not ADMIN_PASSWORD:
        print('Set CTVLMS_TEST_ADMIN_EMAIL and CTVLMS_TEST_ADMIN_PASSWORD for live HTTP tests.')
        sys.exit(2)
    # Wait for server to be up
    for _ in range(5):
        try:
            requests.get(BASE_URL)
            break
        except requests.ConnectionError:
            time.sleep(1)
            
    if not test_login():
        sys.exit(1)
        
    pages_to_test = [
        'dashboard',
        'reports',
        'users/list',
        'assets/list',
        'vulnerabilities/list',
        'asset_vulns/list',
        'threat_actors/list',
        'iocs/list',
        'incidents/list',
        'engagements/list',
        'findings/list',
        'remediations/list',
        'audit_log/list'
    ]
    
    success = True
    for page in pages_to_test:
        if not test_page(page):
            success = False
            
    if success:
        print("\n[+] All core pages tested successfully!")
        sys.exit(0)
    else:
        print("\n[-] Some tests failed.")
        sys.exit(1)

if __name__ == '__main__':
    main()
