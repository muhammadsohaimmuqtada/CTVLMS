import requests
import json
from bs4 import BeautifulSoup
import sys

BASE_URL = 'http://localhost:8000'
session = requests.Session()

results = []

def get_csrf(html):
    soup = BeautifulSoup(html, 'html.parser')
    t = soup.find('input', {'name': 'csrf_token'})
    return t['value'] if t else ''

def log_test(name, req, res_status, res_text):
    results.append({
        "Test": name,
        "Request": req,
        "Expected Status": res_status,
        "Actual Result": res_text
    })

# 1. Login as Viewer
resp = session.get(f"{BASE_URL}/?page=login")
csrf = get_csrf(resp.text)
resp_post = session.post(f"{BASE_URL}/?page=login", data={'csrf_token': csrf, 'email': 'viewer@ctvlms.local', 'password': 'Admin@123'}, allow_redirects=False)

# Test A: RBAC Bypass (Viewer tries to access Admin audit log)
resp_rbac = session.get(f"{BASE_URL}/?page=audit_log/list", allow_redirects=False)
log_test("RBAC Bypass (Viewer -> Admin Page)", "GET /?page=audit_log/list", "301/302 Redirect (Access Denied)", f"Status: {resp_rbac.status_code}, Location: {resp_rbac.headers.get('Location')}")

# Test B: CSRF Rejection (Viewer tries to POST to dashboard or somewhere with bad token)
# Let's use a standard POST form. We'll try to delete an asset (even though we're a viewer, CSRF should trigger first).
bad_csrf_data = {'csrf_token': 'invalid_token_123', 'delete_id': '1'}
resp_csrf = session.post(f"{BASE_URL}/?page=assets/list", data=bad_csrf_data, allow_redirects=False)
body = resp_csrf.text
log_test("CSRF Rejection", "POST /?page=assets/list (csrf_token=invalid_token_123)", "Die/Error message", f"Status: {resp_csrf.status_code}, Body snippet: {body[:60].strip()}")

# Test C: Illegal lifecycle transition (We need to be Vuln_Manager or Admin to edit)
# Login as Admin
session.cookies.clear()
resp = session.get(f"{BASE_URL}/?page=login")
csrf = get_csrf(resp.text)
session.post(f"{BASE_URL}/?page=login", data={'csrf_token': csrf, 'email': 'admin@ctvlms.local', 'password': 'Admin@123'}, allow_redirects=False)

# Get form to get valid CSRF
resp = session.get(f"{BASE_URL}/?page=asset_vulns/form&id=1")
csrf = get_csrf(resp.text)
# Try to move an asset_vuln to 'Verified_Closed' without remediation details
illegal_transition_data = {
    'csrf_token': csrf,
    'assetID': '1',
    'vulnID': '1',
    'status': 'Verified_Closed',
    'discoveredDate': '2024-01-01',
    'dueDate': '',
    'closedDate': '',
    'notes': 'Illegal transition test'
}
resp_trans = session.post(f"{BASE_URL}/?page=asset_vulns/form&id=15", data=illegal_transition_data, allow_redirects=False)
error_caught = "Cannot move to Verified_Closed" in resp_trans.text
log_test("Illegal Lifecycle Transition (Discovered -> Verified_Closed without verification)", 
         "POST /?page=asset_vulns/form&id=15 (status=Verified_Closed)", 
         "Validation Error Rendered", 
         f"Status: {resp_trans.status_code}, Caught Error: {error_caught}")

# Test D: SQL Injection String
# Try putting ' OR 1=1; -- in a GET parameter and POST parameter
sqli_str = "' OR 1=1; --"
resp_sqli = session.get(f"{BASE_URL}/?page=assets/list&search={sqli_str}", allow_redirects=False)
log_test("SQL Injection String in Search", f"GET /?page=assets/list&search={sqli_str}", "200 OK (Safely escaped/handled)", f"Status: {resp_sqli.status_code}, Fatal Error: {'Fatal error' in resp_sqli.text}")

# Output markdown table
print("| Test Scenario | Request Sent | Expected Behavior | Actual Response |")
print("|---|---|---|---|")
for r in results:
    print(f"| {r['Test']} | `{r['Request']}` | {r['Expected Status']} | {r['Actual Result']} |")
