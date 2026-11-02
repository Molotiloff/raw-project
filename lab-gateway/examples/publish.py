"""Send one synthetic event to the isolated laboratory gateway."""
import json
import os
from urllib.request import Request, urlopen

url = os.environ.get("LAB_GATEWAY_URL", "http://127.0.0.1:8000")
token = os.environ["LAB_PRODUCER_TOKEN"]
body = json.dumps({"object_id": "demo", "payload": {"message": "synthetic event"}}).encode()
request = Request(url + "/events", body, {"Authorization": "Bearer " + token, "Content-Type": "application/json"})
with urlopen(request, timeout=5) as response:
    print(response.read().decode())
