import datetime
import hashlib
import json
import os
import subprocess
import tempfile
import time
from typing import Dict, Any, Optional
from urllib.parse import urlparse
import requests
from google.cloud import storage

# GCP Bucket configuration
BUCKET_NAME = os.environ.get("BUCKET_NAME", "bwg3-qwiklabs-gcp-04-702410113001")
PROJECT_ID = os.environ.get("GOOGLE_CLOUD_PROJECT", "qwiklabs-gcp-04-702410113001")


def inspect_and_capture_url(url: str) -> Dict[str, Any]:
    """Inspects a target URL, resolves redirects to find final destination,
    fetches HTTP metadata/headers, and takes a headless browser screenshot.

    Args:
        url: The web URL to inspect (e.g. 'https://example.com').

    Returns:
        A dictionary containing destination_url, status_code, title, redirect_chain,
        screenshot_local_path, and initial_signals.
    """
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    redirect_chain = []
    destination_url = url
    status_code = 0
    server = ""
    content_type = ""
    page_text_snippet = ""

    # 1. Resolve redirects and fetch HTTP headers/content
    try:
        session = requests.Session()
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
        })
        resp = session.get(url, timeout=12, allow_redirects=True, verify=False)
        destination_url = resp.url
        status_code = resp.status_code
        server = resp.headers.get("Server", "Unknown")
        content_type = resp.headers.get("Content-Type", "")
        
        for r in resp.history:
            redirect_chain.append({"url": r.url, "status_code": r.status_code})
        redirect_chain.append({"url": destination_url, "status_code": status_code})

        # Simple title and text snippet
        body_text = resp.text
        if "<title>" in body_text and "</title>" in body_text:
            title = body_text.split("<title>")[1].split("</title>")[0].strip()
        else:
            title = "No Title"

        # Text snippet for threat cues
        clean_text = " ".join(body_text[:4000].split())
        page_text_snippet = clean_text[:500]

    except Exception as e:
        return {
            "input_url": url,
            "destination_url": destination_url,
            "error": f"Failed to reach URL: {str(e)}",
            "redirect_chain": redirect_chain,
            "screenshot_local_path": None,
        }

    # 2. Capture screenshot using headless chrome
    scan_id = hashlib.md5(f"{url}_{time.time()}".encode()).hexdigest()[:12]
    temp_dir = tempfile.gettempdir()
    screenshot_file = os.path.join(temp_dir, f"scan_{scan_id}.png")

    try:
        cmd = [
            "/usr/bin/google-chrome",
            "--headless",
            "--no-sandbox",
            "--disable-gpu",
            "--disable-dev-shm-usage",
            f"--screenshot={screenshot_file}",
            "--window-size=1280,800",
            destination_url,
        ]
        subprocess.run(cmd, timeout=20, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        screenshot_file = None

    return {
        "scan_id": scan_id,
        "input_url": url,
        "destination_url": destination_url,
        "status_code": status_code,
        "server": server,
        "content_type": content_type,
        "title": title,
        "redirect_chain": redirect_chain,
        "page_snippet": page_text_snippet,
        "screenshot_local_path": screenshot_file if (screenshot_file and os.path.exists(screenshot_file)) else None,
    }


def store_scan_result(
    scan_id: str,
    input_url: str,
    destination_url: str,
    verdict: str,
    category: str,
    explanation: str,
    screenshot_local_path: Optional[str] = None
) -> Dict[str, Any]:
    """Stores the scan metadata and screenshot into Cloud Storage and persists the audit record.

    Args:
        scan_id: Unique identifier for the scan.
        input_url: The initial URL submitted.
        destination_url: The final landing URL after redirects.
        verdict: 'Good', 'Suspicious', or 'Malicious'.
        category: E.g., 'Clean', 'Phishing / Credential Harvesting', 'Malware', 'Scam / Deceptive', 'Defacement'.
        explanation: Detailed reasoning for the verdict.
        screenshot_local_path: Path to the locally captured screenshot PNG.

    Returns:
        A dict with the public screenshot URL and confirmation of persistent storage.
    """
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    gcs_screenshot_url = ""

    try:
        client = storage.Client(project=PROJECT_ID)
        bucket = client.bucket(BUCKET_NAME)

        # 1. Upload screenshot if available, or generate web capture
        blob_path = f"screenshots/{scan_id}.png"
        blob = bucket.blob(blob_path)
        if screenshot_local_path and os.path.exists(screenshot_local_path):
            blob.upload_from_filename(screenshot_local_path, content_type="image/png")
            gcs_screenshot_url = f"https://storage.googleapis.com/{BUCKET_NAME}/{blob_path}"
        else:
            # Fallback for cloud runner containers without Chrome binary: capture destination web preview
            try:
                preview_api = f"https://image.thum.io/get/width/1024/crop/800/{destination_url}"
                img_resp = requests.get(preview_api, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
                if img_resp.status_code == 200 and len(img_resp.content) > 1000:
                    blob.upload_from_string(img_resp.content, content_type="image/png")
                    gcs_screenshot_url = f"https://storage.googleapis.com/{BUCKET_NAME}/{blob_path}"
            except Exception:
                pass

        # 2. Save scan log record in Cloud Storage
        record = {
            "scan_id": scan_id,
            "timestamp": timestamp,
            "input_url": input_url,
            "destination_url": destination_url,
            "verdict": verdict,
            "category": category,
            "explanation": explanation,
            "screenshot_url": gcs_screenshot_url,
        }
        record_blob = bucket.blob(f"scans/{scan_id}.json")
        record_blob.upload_from_string(json.dumps(record, indent=2), content_type="application/json")

        # 3. Persist record into BigQuery
        stored_in_bq = False
        try:
            from google.cloud import bigquery
            bq_client = bigquery.Client(project=PROJECT_ID, location="US")
            table = bq_client.get_table(f"{PROJECT_ID}.linkguard_data.url_scans")
            row = (
                record["scan_id"],
                record["timestamp"],
                record["input_url"],
                record["destination_url"],
                record["verdict"],
                record["category"],
                record["explanation"],
                record["screenshot_url"],
            )
            errors = bq_client.insert_rows(table, [row])
            if not errors:
                stored_in_bq = True
        except Exception:
            pass

        return {
            "status": "success",
            "scan_id": scan_id,
            "screenshot_url": gcs_screenshot_url,
            "timestamp": timestamp,
            "stored_in_gcs": True,
            "stored_in_bq": stored_in_bq,
        }

    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
            "scan_id": scan_id,
        }


def lookup_scan_history(domain_or_url: str) -> Dict[str, Any]:
    """Look up past scans for a domain or URL in the audit storage.

    Args:
        domain_or_url: Domain name (e.g. 'example.com') or URL string to look up.

    Returns:
        List of matching previous scan records.
    """
    matches = []
    try:
        client = storage.Client(project=PROJECT_ID)
        bucket = client.bucket(BUCKET_NAME)
        blobs = bucket.list_blobs(prefix="scans/")

        for blob in blobs:
            if blob.name.endswith(".json"):
                data = json.loads(blob.download_as_text())
                if (domain_or_url.lower() in data.get("input_url", "").lower() or
                    domain_or_url.lower() in data.get("destination_url", "").lower()):
                    matches.append(data)
                    if len(matches) >= 5:
                        break

        return {"domain_or_url": domain_or_url, "match_count": len(matches), "history": matches}
    except Exception as e:
        return {"error": str(e), "history": []}
