# Pseudocode for extracting data from CT Logs

# Import necessary libraries (json, requests for HTTP requests, datetime for date handling, defaultdict for organizing data)

Class CTLogs:
    # Initialize the class
    Function __init__:
        - Initialize cert_data as a defaultdict that maps each domain to a list of its certificates

    # Fetch list of available CT logs
    Function fetch_log_list:
        - Define the URL to the CT log list JSON file
        - Send a GET request to the URL
        - If the response is successful (status code 200):
            - Return the JSON content containing a list of CT logs
        - Else:
            - Print an error message with the response status code
            - Return None

    # Fetch CT log entries from a specific log URL
    Function fetch_ct_log_entries(log_url, start=0, end=10):
        - Construct the URL by appending "ct/v1/get-entries" to log_url
        - Define parameters (start and end) to specify the range of entries
        - Send a GET request to the URL with parameters
        - If the response is successful (status code 200):
            - Extract and return the entries list from the JSON response
        - Else:
            - Print an error message with the response status code
            - Return an empty list

    # Parse and structure certificate data
    Function parse_certificates(certificates):
        - For each certificate in the certificates list:
            - Extract the domain, type (EV or DV), issuer, issued_date, and expiration_date
            - Convert issued_date and expiration_date to datetime objects if they exist; otherwise, leave them as None
            - Append a dictionary of these details to cert_data under the domain key

    # Analyze patterns in certificate data to support conjectures
    Function analyze_patterns:
        - Initialize an empty results dictionary with keys for each type of pattern to detect:
            - "frequent_ca_changes", "suspicious_ev_downgrades", "rapid_cert_reissuance", "ev_cert_usage", and "dv_cert_reissuance"
        
        - For each domain in cert_data:
            - Initialize counters for CA changes, EV downgrades, reissuance, and counts of EV/DV certificates
            - Sort the certificates for the domain by issued_date, placing entries with None dates at the end
            
            - For each certificate in the sorted certificates list:
                - If the current certificate's issuer differs from the last one, increment the CA change counter
                - Track EV and DV certificates, counting EV and DV reissuances
                - Check for downgrades (any DV certificate following an EV certificate)
                - If both issued_date and expiration_date are defined:
                    - Calculate the duration between issuance and expiration
                    - If duration is less than 30 days, increment the rapid reissuance counter
            
            - After iterating through certificates:
                - Add the domain to results lists based on defined thresholds for CA changes, downgrades, reissuances, etc.

        - Return the results dictionary with the list of flagged domains for each pattern
