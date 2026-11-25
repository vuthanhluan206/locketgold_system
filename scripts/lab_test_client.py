"""
Controlled Research Lab Test Client for LocketGold Entitlement & HTTPS Inspection.
Connects to the Research Lab endpoint (either over HTTP/HTTPS or an explicit Lab Root CA trust bundle),
queries `/api/lab/subscribers/<account_id>`, verifies headers and CustomerInfo payload,
and prints a formatted Entitlement Diagnostic Report.

Usage:
  python -m scripts.lab_test_client --url https://locketgold.vuthanhluan.bond --account-id 4Vee1rBLoJN9TDjql9xPzDEuf5D2 --token lkg_dev_...
"""
import argparse
import json
import sys
import httpx


def format_entitlement_report(account_id: str, status_code: int, headers: dict, payload: dict) -> dict:
    """Parse a Research Lab response and extract the verified entitlement status for display."""
    sub = payload.get('subscriber', {}) if isinstance(payload, dict) else {}
    entitlements = sub.get('entitlements', {}) if isinstance(sub, dict) else {}
    gold = entitlements.get('Gold') if isinstance(entitlements, dict) else None
    lab_status = headers.get('x-lab-entitlement-status', 'unknown')
    lab_state = headers.get('x-lab-entitlement-state', 'unknown')

    return {
        'account_id': account_id,
        'http_status': status_code,
        'lab_entitlement_status': lab_status,
        'lab_entitlement_state': lab_state,
        'gold_active': bool(gold and isinstance(gold, dict) and gold.get('expires_date')),
        'product_identifier': gold.get('product_identifier') if isinstance(gold, dict) else None,
        'expires_date': gold.get('expires_date') if isinstance(gold, dict) else None,
        'raw_entitlements': entitlements,
        'scope_disclaimer': 'SIMULATED_LAB_ENTITLEMENT_ONLY (Not an official Locket or App Store purchase verification)',
    }


def run_client(base_url: str, account_id: str, token: str, ca_cert_path: str | None = None) -> dict:
    verify = ca_cert_path if ca_cert_path else True
    headers = {'Authorization': f'Bearer {token}', 'User-Agent': 'LocketGoldLabTestClient/3.0'}
    with httpx.Client(base_url=base_url.rstrip('/'), verify=verify, timeout=10.0) as client:
        resp = client.get(f'/api/lab/subscribers/{account_id}', headers=headers)
        data = resp.json() if resp.headers.get('content-type', '').startswith('application/json') else {}
        return format_entitlement_report(account_id, resp.status_code, dict(resp.headers), data)


def main():
    parser = argparse.ArgumentParser(description='LocketGold Research Lab Test Client')
    parser.add_argument('--url', default='http://127.0.0.1:8000', help='Base URL of the Research Lab')
    parser.add_argument('--account-id', required=True, help='Account ID / UID to query')
    parser.add_argument('--token', required=True, help='Device enrollment token (lkg_dev_*) or Subscriber token')
    parser.add_argument('--ca-cert', default=None, help='Optional path to Lab Root CA PEM for TLS verification')
    args = parser.parse_args()

    report = run_client(args.url, args.account_id, args.token, args.ca_cert)
    print(json.dumps(report, indent=2, ensure_ascii=False))
    sys.exit(0 if report['http_status'] == 200 else 1)


if __name__ == '__main__':
    main()
