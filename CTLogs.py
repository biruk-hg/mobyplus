import json
import requests
from datetime import datetime
from collections import defaultdict

class CTLogs:
    def __init__(self):
        self.cert_data = defaultdict(list)
    
    # Fetch list of available CT logs
    def fetch_log_list(self):
        url = "https://www.gstatic.com/ct/log_list/v3/all_logs_list.json"
        response = requests.get(url)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Error fetching log list: {response.status_code}")
            return None

    # Fetch CT log entries from a specific log URL
    def fetch_ct_log_entries(self, log_url, start=0, end=10):
        url = f"{log_url}ct/v1/get-entries"
        params = {'start': start, 'end': end}
        response = requests.get(url, params=params)
        if response.status_code == 200:
            return response.json().get('entries', [])
        else:
            print(f"Error fetching entries from {log_url}: {response.status_code}")
            return []

    # Parse and structure certificate data
    def parse_certificates(self, certificates):
        for cert in certificates:
            domain = cert.get('domain', 'Unknown')
            cert_type = cert.get('type', 'Unknown')
            ca_issuer = cert.get('issuer', 'Unknown')
            issued_date = cert.get('issued_date')
            expiration_date = cert.get('expiration_date')
            
            issued_date = datetime.strptime(issued_date, "%Y-%m-%dT%H:%M:%SZ") if issued_date else None
            expiration_date = datetime.strptime(expiration_date, "%Y-%m-%dT%H:%M:%SZ") if expiration_date else None
            
            self.cert_data[domain].append({
                'type': cert_type,
                'issuer': ca_issuer,
                'issued_date': issued_date,
                'expiration_date': expiration_date
            })

    # Analyze patterns in certificate data to support conjectures
    def analyze_patterns(self):
        results = {
            'frequent_ca_changes': [],
            'suspicious_ev_downgrades': [],
            'rapid_cert_reissuance': [],
            'ev_cert_usage': [],
            'dv_cert_reissuance': []
        }
        
        for domain, certs in self.cert_data.items():
            ca_changes = 0
            last_ca = None
            ev_downgrades = 0
            cert_reissues = 0
            dv_reissues = 0
            ev_count = 0
            cert_timeline = sorted(certs, key=lambda x: (x['issued_date'] is not None, x['issued_date']))

            for cert in cert_timeline:
                if last_ca and cert['issuer'] != last_ca:
                    ca_changes += 1
                last_ca = cert['issuer']
                
                if cert['type'] == 'EV':
                    ev_count += 1
                elif cert['type'] == 'DV':
                    dv_reissues += 1
                
                if cert['type'] == 'DV' and any(c['type'] == 'EV' for c in certs):
                    ev_downgrades += 1
                
                if cert['issued_date'] and cert['expiration_date']:
                    duration = (cert['expiration_date'] - cert['issued_date']).days
                    if duration < 30:
                        cert_reissues += 1

            if ca_changes > 2:
                results['frequent_ca_changes'].append(domain)
            if ev_downgrades > 0:
                results['suspicious_ev_downgrades'].append(domain)
            if cert_reissues > 1:
                results['rapid_cert_reissuance'].append(domain)
            if ev_count > 0:
                results['ev_cert_usage'].append(domain)
            if dv_reissues > 1:
                results['dv_cert_reissuance'].append(domain)
        
        return results
    