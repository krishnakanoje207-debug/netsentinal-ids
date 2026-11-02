"""Local exact-URL comparison; browser history never leaves this process."""
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import urlopen

SOURCE = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"
FEED = Path(__file__).resolve().parents[4] / "lab/local/out/site-risk.json"


def digest(url: str) -> str:
    return hashlib.sha256(url.encode("utf-8")).hexdigest()


def load_feed(path: Path = FEED) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        at = datetime.fromisoformat(data["fetched_at"])
        age = (datetime.now(timezone.utc) - at).total_seconds()
        data["freshness"] = "fresh" if 0 <= age < 86400 else "stale"
        return data
    except (OSError, ValueError, KeyError, TypeError):
        return {"freshness": "unavailable", "url_hashes": []}


def assess(url: str, feed: dict) -> str:
    matched = digest(url) in feed.get("url_hashes", [])
    if feed["freshness"] != "fresh":
        return "Phishing feed stale or unavailable; reputation unknown"
    if matched:
        return "WARNING: exact URL matches OpenPhish community phishing feed; avoid this site"
    return "No exact URL match in limited OpenPhish feed; safety remains unassessed"


def refresh() -> None:
    """Fixed public feed request, never includes browser history. Personal research only."""
    with urlopen(SOURCE, timeout=20) as response:
        raw = response.read(4_000_001)
    if len(raw) > 4_000_000:
        raise ValueError("Phishing feed exceeds bounded download size")
    urls = [line.strip() for line in raw.decode("utf-8").splitlines() if line.startswith(("http://", "https://"))]
    if not urls:
        raise ValueError("Phishing feed contained no URLs")
    data = {"source": "OpenPhish community feed", "source_url": SOURCE,
            "terms_url": "https://openphish.com/terms.html",
            "coverage": "Limited community phishing feed; exact URL match only. Non-commercial personal/academic research use.",
            "fetched_at": datetime.now(timezone.utc).isoformat(), "entries": len(urls),
            "url_hashes": [digest(url) for url in urls]}
    FEED.parent.mkdir(parents=True, exist_ok=True)
    temp = FEED.with_suffix(".tmp")
    temp.write_text(json.dumps(data), encoding="utf-8")
    os.replace(temp, FEED)
    print(f"Refreshed {len(urls)} OpenPhish entries at {data['fetched_at']}; history was not transmitted.")


if __name__ == "__main__":
    if "--if-due" in sys.argv:
        if not FEED.with_name("site-risk-opt-in").exists():
            sys.exit(0)
        existing = load_feed()
        try:
            age = (datetime.now(timezone.utc) - datetime.fromisoformat(existing["fetched_at"])).total_seconds()
            if 0 <= age < 12 * 3600:
                sys.exit(0)
        except (KeyError, TypeError, ValueError):
            pass
    refresh()
