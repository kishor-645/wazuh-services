#!/usr/bin/env python3
"""
AlienVault OTX Threat Intelligence Feed Updater for Wazuh
Fetches IoCs from OTX and creates Wazuh CDB lists
"""

import sys
import os
import json
import time
import logging
import pwd, grp
from datetime import datetime, timedelta

try:
    from OTXv2 import OTXv2
    import requests
except ImportError as e:
    print(f"Error importing required modules: {e}")
    print("Please install: pip3 install OTXv2 requests")
    sys.exit(1)

# Configuration
OTX_API_KEY = os.environ.get('OTX_API_KEY', '')
LISTS_DIR = '/var/ossec/etc/otx'
LOG_FILE = '/var/ossec/logs/otx_integration.log'

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)

def setup_otx_client():
    """Initialize OTX client"""
    if not OTX_API_KEY:
        logging.error("OTX_API_KEY environment variable not set")
        return None
    
    try:
        otx = OTXv2(OTX_API_KEY)
        logging.info("OTX client initialized successfully")
        return otx
    except Exception as e:
        logging.error(f"Failed to initialize OTX client: {e}")
        return None


def fetch_malware_hashes(otx, days_back=1, max_results=1000):
    """Fetch malware file hashes from OTX"""
    logging.info(f"Fetching malware hashes from last {days_back} days...")
    hashes = []
    
    try:
        # Use getsince with limit for better performance
        since_date = (datetime.now() - timedelta(days=days_back)).isoformat()
        pulses = otx.getsince(since_date, limit=50)  # Limit to 50 recent pulses
        
        count = 0
        for pulse in pulses:
            if count >= max_results:
                break
                
            for indicator in pulse.get('indicators', []):
                if count >= max_results:
                    break
                    
                if indicator.get('type') in ['FileHash-MD5', 'FileHash-SHA1', 'FileHash-SHA256']:
                    hash_value = indicator.get('indicator', '').lower()
                    pulse_name = pulse.get('name', 'unknown')
                    
                    if hash_value and len(hash_value) >= 32:
                        hashes.append(f"{hash_value}:otx_{pulse_name.replace(' ', '_').replace(',', '_')}")
                        count += 1
        
        logging.info(f"Fetched {len(hashes)} malware hashes")
        return hashes
        
    except Exception as e:
        logging.error(f"Error fetching malware hashes: {e}")
        return []

def fetch_malicious_ips(otx, days_back=1, max_results=1000):
    """Fetch malicious IP addresses from OTX"""
    logging.info(f"Fetching malicious IPs from last {days_back} days...")
    ips = []
    
    try:
        since_date = (datetime.now() - timedelta(days=days_back)).isoformat()
        pulses = otx.getsince(since_date, limit=50)  # Limit to 50 recent pulses
        
        count = 0
        for pulse in pulses:
            if count >= max_results:
                break
                
            for indicator in pulse.get('indicators', []):
                if count >= max_results:
                    break
                    
                if indicator.get('type') == 'IPv4':
                    ip = indicator.get('indicator', '')
                    pulse_name = pulse.get('name', 'unknown')
                    
                    if ip and not ip.startswith(('10.', '192.168.', '172.16.')):
                        ips.append(f"{ip}:otx_{pulse_name.replace(' ', '_').replace(',', '_')}")
                        count += 1
        
        logging.info(f"Fetched {len(ips)} malicious IPs")
        return ips
        
    except Exception as e:
        logging.error(f"Error fetching malicious IPs: {e}")
        return []

def fetch_malicious_domains(otx, days_back=1, max_results=1000):
    """Fetch malicious domains from OTX"""
    logging.info(f"Fetching malicious domains from last {days_back} days...")
    domains = []
    
    try:
        since_date = (datetime.now() - timedelta(days=days_back)).isoformat()
        pulses = otx.getsince(since_date, limit=50)  # Limit to 50 recent pulses
        
        count = 0
        for pulse in pulses:
            if count >= max_results:
                break
                
            for indicator in pulse.get('indicators', []):
                if count >= max_results:
                    break
                    
                if indicator.get('type') in ['domain', 'hostname']:
                    domain = indicator.get('indicator', '')
                    pulse_name = pulse.get('name', 'unknown')
                    
                    if domain and '.' in domain:
                        domains.append(f"{domain}:otx_{pulse_name.replace(' ', '_').replace(',', '_')}")
                        count += 1
        
        logging.info(f"Fetched {len(domains)} malicious domains")
        return domains
        
    except Exception as e:
        logging.error(f"Error fetching malicious domains: {e}")
        return []



def write_cdb_list(filename, data, header_comment):
    """Write data to CDB list file"""
    filepath = os.path.join(LISTS_DIR, filename)
    
    try:
        with open(filepath, 'w') as f:
            f.write(f"# {header_comment}\n")
            f.write(f"# Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Total entries: {len(data)}\n\n")
            
            for entry in data:
                f.write(f"{entry}\n")
        
        # Set proper permissions for Wazuh
        try:
            ossec_uid = pwd.getpwnam('wazuh').pw_uid
            ossec_gid = grp.getgrnam('wazuh').gr_gid
            os.chown(filepath, ossec_uid, ossec_gid)
        except (KeyError, OSError):
            # Fallback: try common Wazuh user IDs or leave as root readable
            os.chmod(filepath, 0o644)  # Make readable by all
            logging.warning(f"Could not set ossec ownership for {filename}, set to world-readable")
            return
            
        os.chmod(filepath, 0o640)
        logging.info(f"Successfully wrote {len(data)} entries to {filename}")
        
    except Exception as e:
        logging.error(f"Error writing to {filename}: {e}")


def main():
    """Main function"""
    logging.info("Starting OTX threat intelligence update...")
    
    # Setup OTX client
    otx = setup_otx_client()
    if not otx:
        sys.exit(1)
    
    # Create lists directory if it doesn't exist
    os.makedirs(LISTS_DIR, exist_ok=True)
    os.chown(LISTS_DIR, pwd.getpwnam("wazuh").pw_uid, grp.getgrnam("wazuh").gr_gid)
    
    # Fetch and write malware hashes
    malware_hashes = fetch_malware_hashes(otx, days_back=60)
    if malware_hashes:
        write_cdb_list('otx-malware-hashes', malware_hashes, 
                    'AlienVault OTX Malware File Hashes')

    # Fetch and write malicious IPs  
    malicious_ips = fetch_malicious_ips(otx, days_back=60)
    if malicious_ips:
        write_cdb_list('otx-malicious-ips', malicious_ips, 
                    'AlienVault OTX Malicious IP Addresses')

    # Fetch and write malicious domains
    malicious_domains = fetch_malicious_domains(otx, days_back=60)
    if malicious_domains:
        write_cdb_list('otx-malicious-domains', malicious_domains, 
                    'AlienVault OTX Malicious Domains')

    
    logging.info("OTX threat intelligence update completed successfully")
    
    # Print summary
    total_indicators = len(malware_hashes) + len(malicious_ips) + len(malicious_domains)
    print(f"Summary:")
    print(f"- Malware Hashes: {len(malware_hashes)}")
    print(f"- Malicious IPs: {len(malicious_ips)}")
    print(f"- Malicious Domains: {len(malicious_domains)}")
    print(f"- Total Indicators: {total_indicators}")

if __name__ == "__main__":
    main()
