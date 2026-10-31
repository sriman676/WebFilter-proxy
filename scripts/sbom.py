#!/usr/bin/env python3
"""CycloneDX 1.5 SBOM from Cargo.lock (stdlib only; fallback when cargo-cyclonedx is absent).

  sbom.py [Cargo.lock] > sbom.cdx.json
"""
import json
import sys
import tomllib
import uuid
from datetime import datetime, timezone

lock = tomllib.load(open(sys.argv[1] if len(sys.argv) > 1 else "Cargo.lock", "rb"))
components = []
for p in sorted(lock["package"], key=lambda p: (p["name"], p["version"])):
    c = {"type": "library", "name": p["name"], "version": p["version"],
         "purl": f"pkg:cargo/{p['name']}@{p['version']}", "bom-ref": f"{p['name']}@{p['version']}"}
    if "checksum" in p:
        c["hashes"] = [{"alg": "SHA-256", "content": p["checksum"]}]
    if "source" not in p:
        c["type"] = "application"
    components.append(c)
print(json.dumps({
    "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
    "serialNumber": f"urn:uuid:{uuid.uuid4()}",
    "metadata": {"timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                 "tools": [{"name": "scripts/sbom.py"}]},
    "components": components,
}, indent=1))
