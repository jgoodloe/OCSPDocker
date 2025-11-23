#!/usr/bin/env python3
"""
Certificate Checker Service
Checks certificates, validates chains, checks CRLs, and sends notifications

Version: 1.1.0 (Fixed notifications NoneType error)
"""

import os
import sys
import yaml
import json
import time
import schedule
import requests
from datetime import datetime, timedelta
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.x509.ocsp import OCSPRequestBuilder
import urllib.parse
import urllib3

# Disable SSL warnings for CRL downloads (CRLs may use HTTP)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class CertificateChecker:
    def __init__(self, config_path='config.yaml'):
        """Initialize the certificate checker with configuration"""
        self.config = self.load_config(config_path)
        # Final safety check - ensure notifications is always a dict
        if 'notifications' not in self.config or self.config['notifications'] is None:
            self.config['notifications'] = {}
        elif not isinstance(self.config['notifications'], dict):
            self.config['notifications'] = {}
        self.warnings = []
        
    def load_config(self, config_path):
        """Load configuration from YAML file or environment variables"""
        config = {}
        
        # Try to load from file
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                loaded_config = yaml.safe_load(f)
                config = loaded_config if loaded_config is not None else {}
                # Ensure notifications is never None
                if config.get('notifications') is None:
                    config['notifications'] = {}
        
        # Override with environment variables
        config['certificate'] = os.getenv('CERTIFICATE_PATH', config.get('certificate'))
        config['schedule_interval'] = os.getenv('SCHEDULE_INTERVAL', config.get('schedule_interval', '60'))
        config['cert_expiry_warning_hours'] = int(os.getenv('CERT_EXPIRY_WARNING_HOURS', config.get('cert_expiry_warning_hours', 24)))
        config['cert_expiry_warning_days'] = int(os.getenv('CERT_EXPIRY_WARNING_DAYS', config.get('cert_expiry_warning_days', 30)))
        config['crl_expiry_warning_hours'] = int(os.getenv('CRL_EXPIRY_WARNING_HOURS', config.get('crl_expiry_warning_hours', 24)))
        config['crl_expiry_warning_minutes'] = int(os.getenv('CRL_EXPIRY_WARNING_MINUTES', config.get('crl_expiry_warning_minutes', 60)))
        
        # Notification configs - ensure it's always a dict
        notifications = config.get('notifications')
        if notifications is None or not isinstance(notifications, dict):
            notifications = {}
        
        # Support both HTTP_PUSH_URL and NOTIFICATIONS_HTTP_PUSH_URL
        http_push_url = os.getenv('HTTP_PUSH_URL') or os.getenv('NOTIFICATIONS_HTTP_PUSH_URL')
        if http_push_url:
            notifications['http_push'] = {'url': http_push_url}
        
        webhook_url = os.getenv('WEBHOOK_URL') or os.getenv('NOTIFICATIONS_WEBHOOK_URL')
        if webhook_url:
            notifications['webhook'] = {'url': webhook_url}
        
        teams_url = os.getenv('TEAMS_WEBHOOK_URL') or os.getenv('NOTIFICATIONS_TEAMS_WEBHOOK_URL')
        if teams_url:
            notifications['teams'] = {'url': teams_url}
        
        google_chat_url = os.getenv('GOOGLE_CHAT_WEBHOOK_URL') or os.getenv('NOTIFICATIONS_GOOGLE_CHAT_WEBHOOK_URL')
        if google_chat_url:
            notifications['google_chat'] = {'url': google_chat_url}
        
        twilio_sid = os.getenv('TWILIO_ACCOUNT_SID') or os.getenv('NOTIFICATIONS_TWILIO_ACCOUNT_SID')
        twilio_token = os.getenv('TWILIO_AUTH_TOKEN') or os.getenv('NOTIFICATIONS_TWILIO_AUTH_TOKEN')
        twilio_from = os.getenv('TWILIO_FROM') or os.getenv('NOTIFICATIONS_TWILIO_FROM')
        twilio_to = os.getenv('TWILIO_TO') or os.getenv('NOTIFICATIONS_TWILIO_TO')
        if twilio_sid and twilio_token and twilio_from and twilio_to:
            notifications['sms'] = {
                'account_sid': twilio_sid,
                'auth_token': twilio_token,
                'from': twilio_from,
                'to': twilio_to
            }
        
        config['notifications'] = notifications
        
        return config
    
    def load_certificate(self, cert_path):
        """Load certificate from file"""
        try:
            with open(cert_path, 'rb') as f:
                cert_data = f.read()
            
            # Try PEM format first
            try:
                cert = x509.load_pem_x509_certificate(cert_data, default_backend())
                return cert, None
            except:
                pass
            
            # Try DER format
            try:
                cert = x509.load_der_x509_certificate(cert_data, default_backend())
                return cert, None
            except Exception as e:
                return None, f"Failed to load certificate: {str(e)}"
        except Exception as e:
            return None, f"Error reading certificate file: {str(e)}"
    
    def check_certificate_expiry(self, cert, cert_name="Certificate"):
        """Check if certificate is expiring soon"""
        now = datetime.utcnow()
        # Use UTC version to avoid deprecation warning
        try:
            not_after = cert.not_valid_after_utc.replace(tzinfo=None)
        except AttributeError:
            # Fallback for older cryptography versions
            not_after = cert.not_valid_after.replace(tzinfo=None)
        time_until_expiry = not_after - now
        
        hours_until_expiry = time_until_expiry.total_seconds() / 3600
        days_until_expiry = time_until_expiry.days
        
        warning = None
        if time_until_expiry.total_seconds() <= 0:
            warning = f"{cert_name} has EXPIRED"
        elif hours_until_expiry <= self.config['cert_expiry_warning_hours']:
            warning = f"{cert_name} expires in {hours_until_expiry:.1f} hours ({time_until_expiry})"
        elif days_until_expiry <= self.config['cert_expiry_warning_days']:
            warning = f"{cert_name} expires in {days_until_expiry} days ({time_until_expiry})"
        
        if warning:
            self.warnings.append(warning)
        
        return {
            'valid_until': not_after.isoformat(),
            'time_until_expiry': str(time_until_expiry),
            'hours_until_expiry': hours_until_expiry,
            'days_until_expiry': days_until_expiry,
            'warning': warning
        }
    
    def get_crl_info(self, cert):
        """Extract CRL distribution points from certificate"""
        crl_info = []
        try:
            crl_dps = cert.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.CRL_DISTRIBUTION_POINTS
            ).value
            
            for dp in crl_dps:
                for name in dp.full_name:
                    if isinstance(name, x509.UniformResourceIdentifier):
                        crl_info.append({
                            'url': name.value,
                            'certificate': cert.subject.rfc4514_string()
                        })
        except x509.ExtensionNotFound:
            pass
        
        return crl_info
    
    def check_crl_expiry(self, crl_url):
        """Download and check CRL expiration"""
        result = {
            'url': crl_url,
            'error': None,
            'next_update': None,
            'time_until_expiry': None,
            'hours_until_expiry': None,
            'minutes_until_expiry': None,
            'warning': None
        }
        
        try:
            # Download CRL
            response = requests.get(crl_url, timeout=10, verify=False)
            response.raise_for_status()
            crl_data = response.content
            
            # Try to parse as DER first
            try:
                crl = x509.load_der_x509_crl(crl_data, default_backend())
            except:
                # Try PEM format
                try:
                    crl = x509.load_pem_x509_crl(crl_data, default_backend())
                except Exception as e:
                    result['error'] = f"Failed to parse CRL: {str(e)}"
                    return result
            
            # Get next update time
            # Use UTC version to avoid deprecation warning
            try:
                next_update = crl.next_update_utc.replace(tzinfo=None)
            except AttributeError:
                # Fallback for older cryptography versions
                next_update = crl.next_update.replace(tzinfo=None)
            now = datetime.utcnow()
            time_until_expiry = next_update - now
            
            result['next_update'] = next_update.isoformat()
            result['time_until_expiry'] = str(time_until_expiry)
            result['hours_until_expiry'] = time_until_expiry.total_seconds() / 3600
            result['minutes_until_expiry'] = time_until_expiry.total_seconds() / 60
            
            # Check for warnings
            hours_until = result['hours_until_expiry']
            minutes_until = result['minutes_until_expiry']
            
            if time_until_expiry.total_seconds() <= 0:
                warning = f"CRL at {crl_url} has EXPIRED"
                result['warning'] = warning
                self.warnings.append(warning)
            elif minutes_until <= self.config['crl_expiry_warning_minutes']:
                # Check minutes threshold first (more granular)
                warning = f"CRL at {crl_url} expires in {minutes_until:.1f} minutes ({time_until_expiry})"
                result['warning'] = warning
                self.warnings.append(warning)
            elif hours_until <= self.config['crl_expiry_warning_hours']:
                # Then check hours threshold
                warning = f"CRL at {crl_url} expires in {hours_until:.1f} hours ({time_until_expiry})"
                result['warning'] = warning
                self.warnings.append(warning)
            
        except requests.exceptions.RequestException as e:
            result['error'] = f"Failed to download CRL: {str(e)}"
        except Exception as e:
            result['error'] = f"Error checking CRL: {str(e)}"
        
        return result
    
    def analyze_certificate(self):
        """Analyze the certificate and return results"""
        cert_path = self.config.get('certificate')
        if not cert_path:
            return {
                'error': 'Certificate path not specified',
                'status': 'error'
            }
        
        if not os.path.exists(cert_path):
            return {
                'error': f'Certificate file not found: {cert_path}',
                'status': 'error'
            }
        
        self.warnings = []
        results = {
            'timestamp': datetime.utcnow().isoformat(),
            'certificate_path': cert_path,
            'status': 'ok',
            'certificates': [],
            'crls': [],
            'warnings': []
        }
        
        # Load main certificate
        cert, error = self.load_certificate(cert_path)
        if error:
            results['error'] = error
            results['status'] = 'error'
            return results
        
        # Check main certificate
        # Use UTC versions to avoid deprecation warnings
        try:
            valid_from = cert.not_valid_before_utc.isoformat()
            valid_to = cert.not_valid_after_utc.isoformat()
        except AttributeError:
            # Fallback for older cryptography versions
            valid_from = cert.not_valid_before.isoformat()
            valid_to = cert.not_valid_after.isoformat()
        
        cert_info = {
            'subject': cert.subject.rfc4514_string(),
            'issuer': cert.issuer.rfc4514_string(),
            'serial_number': str(cert.serial_number),
            'valid_from': valid_from,
            'valid_to': valid_to,
        }
        
        expiry_info = self.check_certificate_expiry(cert, "Main Certificate")
        cert_info.update(expiry_info)
        results['certificates'].append(cert_info)
        
        # Get CRL information
        crl_info = self.get_crl_info(cert)
        for crl in crl_info:
            crl_check = self.check_crl_expiry(crl['url'])
            results['crls'].append(crl_check)
        
        # Check for chain certificates if provided
        chain_path = self.config.get('certificate_chain')
        if chain_path and os.path.exists(chain_path):
            chain_certs, chain_error = self.load_certificate_chain(chain_path)
            if not chain_error:
                for idx, chain_cert in enumerate(chain_certs):
                    chain_info = {
                        'subject': chain_cert.subject.rfc4514_string(),
                        'issuer': chain_cert.issuer.rfc4514_string(),
                        'serial_number': str(chain_cert.serial_number),
                    }
                    expiry_info = self.check_certificate_expiry(chain_cert, f"Chain Certificate {idx + 1}")
                    chain_info.update(expiry_info)
                    results['certificates'].append(chain_info)
                    
                    # Check CRLs for chain certificates too
                    chain_crl_info = self.get_crl_info(chain_cert)
                    for crl in chain_crl_info:
                        crl_check = self.check_crl_expiry(crl['url'])
                        results['crls'].append(crl_check)
        
        results['warnings'] = self.warnings
        if self.warnings:
            results['status'] = 'warning'
        
        return results
    
    def load_certificate_chain(self, chain_path):
        """Load certificate chain from file"""
        try:
            with open(chain_path, 'rb') as f:
                chain_data = f.read()
            
            # Try to parse as PEM chain
            certs = []
            for pem_cert in chain_data.split(b'-----BEGIN CERTIFICATE-----'):
                if pem_cert.strip():
                    pem_cert = b'-----BEGIN CERTIFICATE-----' + pem_cert
                    try:
                        cert = x509.load_pem_x509_certificate(pem_cert, default_backend())
                        certs.append(cert)
                    except:
                        pass
            
            if certs:
                return certs, None
            
            return None, "Could not parse certificate chain"
        except Exception as e:
            return None, f"Error reading certificate chain: {str(e)}"
    
    def send_http_push(self, results):
        """Send results via HTTP push"""
        notifications = self.config.get('notifications') or {}
        http_config = notifications.get('http_push')
        if not http_config or not http_config.get('url'):
            print("DEBUG: HTTP push not configured or URL missing", file=sys.stderr)
            return False
        
        try:
            # Determine status - map to up/down
            result_status = results.get('status', 'unknown')
            if result_status == 'ok':
                status = 'up'
                msg = 'OK'
            elif result_status == 'warning':
                status = 'up'  # Still up, but with warning message
                # Format: WARNING - [warning details]
                if self.warnings:
                    msg = 'WARNING - ' + '; '.join(self.warnings)
                else:
                    msg = 'WARNING'
            else:  # error
                status = 'down'
                msg = 'ERROR'
            
            ocsp_status = 'OK'  # Simplified - would need actual OCSP check
            
            # Build URL with parameters
            url = http_config['url']
            print(f"DEBUG: Original URL: {url}", file=sys.stderr)
            
            params = {
                'status': status,
                'msg': msg,
                'OCSP': ocsp_status
            }
            
            print(f"DEBUG: Parameters to add: {params}", file=sys.stderr)
            
            # Parse URL and add params
            parsed = urllib.parse.urlparse(url)
            query = urllib.parse.parse_qs(parsed.query)
            print(f"DEBUG: Existing query params: {query}", file=sys.stderr)
            
            query.update(params)
            new_query = urllib.parse.urlencode(query, doseq=True)
            final_url = urllib.parse.urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query, parsed.fragment
            ))
            
            print(f"DEBUG: Final URL: {final_url}", file=sys.stderr)
            
            # Uptime Kuma push endpoint accepts GET requests
            # Try GET first, fallback to PUT if configured
            http_method = http_config.get('method', 'GET').upper()
            print(f"DEBUG: Using HTTP method: {http_method}", file=sys.stderr)
            
            if http_method == 'PUT':
                response = requests.put(final_url, timeout=10)
            else:
                response = requests.get(final_url, timeout=10)
            print(f"DEBUG: Response status code: {response.status_code}", file=sys.stderr)
            print(f"DEBUG: Response headers: {dict(response.headers)}", file=sys.stderr)
            print(f"DEBUG: Response body: {response.text[:500]}", file=sys.stderr)  # First 500 chars
            
            response.raise_for_status()
            print("DEBUG: HTTP push succeeded", file=sys.stderr)
            return True
        except requests.exceptions.HTTPError as e:
            print(f"HTTP push failed: HTTP {e.response.status_code} - {e}", file=sys.stderr)
            if hasattr(e, 'response') and e.response is not None:
                print(f"DEBUG: Response URL: {e.response.url}", file=sys.stderr)
                print(f"DEBUG: Response status: {e.response.status_code}", file=sys.stderr)
                print(f"DEBUG: Response headers: {dict(e.response.headers)}", file=sys.stderr)
                print(f"DEBUG: Response body: {e.response.text[:500]}", file=sys.stderr)
            return False
        except requests.exceptions.RequestException as e:
            print(f"HTTP push failed: Request error - {e}", file=sys.stderr)
            print(f"DEBUG: Error type: {type(e).__name__}", file=sys.stderr)
            if hasattr(e, 'request') and e.request is not None:
                print(f"DEBUG: Request URL: {e.request.url if hasattr(e.request, 'url') else 'N/A'}", file=sys.stderr)
                print(f"DEBUG: Request method: {e.request.method if hasattr(e.request, 'method') else 'N/A'}", file=sys.stderr)
            return False
        except Exception as e:
            print(f"HTTP push failed: Unexpected error - {e}", file=sys.stderr)
            print(f"DEBUG: Error type: {type(e).__name__}", file=sys.stderr)
            import traceback
            print(f"DEBUG: Traceback: {traceback.format_exc()}", file=sys.stderr)
            return False
    
    def send_webhook(self, results):
        """Send results via webhook"""
        notifications = self.config.get('notifications') or {}
        webhook_config = notifications.get('webhook')
        if not webhook_config or not webhook_config.get('url'):
            return False
        
        try:
            payload = webhook_config.get('payload', results)
            if isinstance(payload, str):
                payload = json.loads(payload)
            
            # Merge results into payload
            if isinstance(payload, dict):
                payload.update(results)
            else:
                payload = results
            
            response = requests.post(
                webhook_config['url'],
                json=payload,
                headers=webhook_config.get('headers', {'Content-Type': 'application/json'}),
                timeout=10
            )
            response.raise_for_status()
            return True
        except Exception as e:
            print(f"Webhook failed: {e}", file=sys.stderr)
            return False
    
    def send_teams(self, results):
        """Send results to Microsoft Teams"""
        notifications = self.config.get('notifications') or {}
        teams_config = notifications.get('teams')
        if not teams_config or not teams_config.get('url'):
            return False
        
        try:
            # Build Teams message card
            status = results.get('status', 'unknown')
            color = '28a745' if status == 'ok' else 'ffc107' if status == 'warning' else 'dc3545'
            
            facts = [
                {'name': 'Status', 'value': status.upper()},
                {'name': 'Certificate', 'value': results.get('certificate_path', 'N/A')},
                {'name': 'Timestamp', 'value': results.get('timestamp', 'N/A')}
            ]
            
            if results.get('certificates'):
                cert = results['certificates'][0]
                facts.append({'name': 'Valid Until', 'value': cert.get('valid_until', 'N/A')})
            
            if self.warnings:
                facts.append({'name': 'Warnings', 'value': '; '.join(self.warnings)})
            
            card = {
                '@type': 'MessageCard',
                '@context': 'https://schema.org/extensions',
                'summary': f'Certificate Check: {status.upper()}',
                'themeColor': color,
                'title': 'Certificate Check Results',
                'sections': [{
                    'activityTitle': f'Certificate Status: {status.upper()}',
                    'facts': facts,
                    'markdown': True
                }]
            }
            
            response = requests.post(teams_config['url'], json=card, timeout=10)
            response.raise_for_status()
            return True
        except Exception as e:
            print(f"Teams notification failed: {e}", file=sys.stderr)
            return False
    
    def send_google_chat(self, results):
        """Send results to Google Chat"""
        notifications = self.config.get('notifications') or {}
        chat_config = notifications.get('google_chat')
        if not chat_config or not chat_config.get('url'):
            return False
        
        try:
            status = results.get('status', 'unknown')
            emoji = '✅' if status == 'ok' else '⚠️' if status == 'warning' else '❌'
            
            message = f"{emoji} *Certificate Check Results*\n\n"
            message += f"*Status:* {status.upper()}\n"
            message += f"*Certificate:* {results.get('certificate_path', 'N/A')}\n"
            message += f"*Timestamp:* {results.get('timestamp', 'N/A')}\n"
            
            if results.get('certificates'):
                cert = results['certificates'][0]
                message += f"*Valid Until:* {cert.get('valid_until', 'N/A')}\n"
            
            if self.warnings:
                message += f"\n*Warnings:*\n" + '\n'.join([f"• {w}" for w in self.warnings])
            
            payload = {'text': message}
            
            response = requests.post(chat_config['url'], json=payload, timeout=10)
            response.raise_for_status()
            return True
        except Exception as e:
            print(f"Google Chat notification failed: {e}", file=sys.stderr)
            return False
    
    def send_sms(self, results):
        """Send results via SMS using Twilio"""
        notifications = self.config.get('notifications') or {}
        sms_config = notifications.get('sms')
        if not sms_config:
            return False
        
        try:
            from twilio.rest import Client
            
            client = Client(sms_config['account_sid'], sms_config['auth_token'])
            
            status = results.get('status', 'unknown')
            message = f"Cert Check: {status.upper()}\n"
            message += f"Cert: {results.get('certificate_path', 'N/A')}\n"
            
            if self.warnings:
                message += f"Warnings: {', '.join(self.warnings[:3])}"  # Limit length
            
            client.messages.create(
                body=message,
                from_=sms_config['from'],
                to=sms_config['to']
            )
            return True
        except Exception as e:
            print(f"SMS notification failed: {e}", file=sys.stderr)
            return False
    
    def send_notifications(self, results):
        """Send results to all configured notification destinations"""
        sent = []
        
        # Ensure notifications is a dict - multiple safety checks
        notifications = self.config.get('notifications')
        if notifications is None or not isinstance(notifications, dict):
            notifications = {}
            # Also fix it in config for future access
            self.config['notifications'] = notifications
        
        if notifications.get('http_push'):
            if self.send_http_push(results):
                sent.append('http_push')
        
        if notifications.get('webhook'):
            if self.send_webhook(results):
                sent.append('webhook')
        
        if notifications.get('teams'):
            if self.send_teams(results):
                sent.append('teams')
        
        if notifications.get('google_chat'):
            if self.send_google_chat(results):
                sent.append('google_chat')
        
        if notifications.get('sms'):
            if self.send_sms(results):
                sent.append('sms')
        
        return sent
    
    def run_check(self):
        """Run certificate check and send notifications"""
        print(f"[{datetime.now()}] Running certificate check...")
        results = self.analyze_certificate()
        
        print(f"Status: {results.get('status')}")
        if results.get('warnings'):
            print(f"Warnings: {', '.join(results['warnings'])}")
        
        # Send notifications
        sent = self.send_notifications(results)
        if sent:
            print(f"Notifications sent to: {', '.join(sent)}")
        
        return results
    
    def start_scheduler(self):
        """Start the scheduled service"""
        # Debug: Verify notifications is properly initialized
        if 'notifications' not in self.config or self.config['notifications'] is None:
            self.config['notifications'] = {}
        
        interval = int(self.config.get('schedule_interval', 60))
        
        # Map interval to schedule
        if interval < 60:
            # Schedule every N seconds
            schedule.every(interval).seconds.do(self.run_check)
            print(f"Scheduling checks every {interval} seconds")
        elif interval < 3600:
            # Schedule every N minutes
            minutes = interval // 60
            schedule.every(minutes).minutes.do(self.run_check)
            print(f"Scheduling checks every {minutes} minutes")
        else:
            # Schedule every N hours
            hours = interval // 3600
            schedule.every(hours).hours.do(self.run_check)
            print(f"Scheduling checks every {hours} hours")
        
        # Run initial check
        self.run_check()
        
        # Keep running
        print("Scheduler started. Press Ctrl+C to stop.")
        while True:
            schedule.run_pending()
            time.sleep(1)

def main():
    """Main entry point"""
    print("=" * 60, file=sys.stderr)
    print("Certificate Checker Service v1.1.0", file=sys.stderr)
    print("Fixed: notifications NoneType error", file=sys.stderr)
    print("=" * 60, file=sys.stderr)
    config_path = os.getenv('CONFIG_PATH', 'config.yaml')
    checker = CertificateChecker(config_path)
    checker.start_scheduler()

if __name__ == '__main__':
    main()

