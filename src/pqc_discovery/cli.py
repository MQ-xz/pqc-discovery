import argparse
import concurrent.futures
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import statistics
import struct
import sys
import threading
import time
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone
from . import __version__


VERSION = __version__
RULESET = "pqc-discovery-1"
PROFILES = {"classical": "X25519:P-256", "hybrid_preferred": "X25519MLKEM768:X25519:P-256",
            "hybrid_required": "X25519MLKEM768", "pq_only": "MLKEM768"}
MAX_BYTES = 25 * 1024 * 1024
MAX_HOSTS = 256
WEB_PORTS = (443, 8443, 9443)
NONWEB_PORTS = (465, 636, 853, 993, 995, 3389, 5061, 5671, 8883)
LIMITATIONS = "Sampled endpoints only; hybrid key exchange is not PQ authentication or organization-wide readiness."
_rate_lock = threading.Lock()
_next_request = 0.0


def now():
    return datetime.now(timezone.utc).isoformat()


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def save(path, value):
    encoded = json.dumps(value, separators=(",", ":"), allow_nan=False)
    if len(encoded.encode()) + 1 > MAX_BYTES:
        raise ValueError("artifact exceeds 25 MiB; split the approved scope")
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    with temporary.open("x") as output:
        os.chmod(temporary, 0o600)
        output.write(encoded + "\n")
    temporary.replace(path)


def rows(path, values):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    with temporary.open("x") as output:
        os.chmod(temporary, 0o600)
        for value in values:
            output.write(json.dumps(value, separators=(",", ":"), allow_nan=False) + "\n")
    temporary.replace(path)


def read(path):
    with Path(path).open("rb") as source:
        data = source.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("input exceeds 25 MiB")
    return json.loads(data)


def domain(value):
    value = value.lower().rstrip(".").encode("idna").decode("ascii")
    if len(value) > 253 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", value):
        raise ValueError("invalid domain")
    if any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-") for label in value.split(".")):
        raise ValueError("invalid domain labels")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise ValueError("domain scope cannot be an IP address")


def paced():
    global _next_request
    with _rate_lock:
        delay = max(0, _next_request - time.monotonic())
        time.sleep(delay)
        _next_request = time.monotonic() + 0.25


def discover(args):
    root = domain(args.scope)
    names = {root}
    coverage = []
    if args.hosts:
        if args.hosts.stat().st_size > MAX_BYTES:
            raise ValueError("tool output exceeds 25 MiB")
        names.update(args.hosts.read_text().splitlines())
        status = int(args.hosts.with_suffix(".status").read_text())
        coverage.append({"source": "subfinder", "status": "completed" if status == 0 else "failed",
                         "detail": "Passive providers depend on available credentials."})
    try:
        url = "https://crt.sh/?" + urllib.parse.urlencode({"q": "%." + root, "output": "json"})
        with urllib.request.urlopen(url, timeout=30) as response:
            data = response.read(10 * 1024 * 1024 + 1)
        if len(data) > 10 * 1024 * 1024:
            raise ValueError("CT response limit exceeded")
        entries = json.loads(data)
        for entry in entries:
            names.update(entry.get("name_value", "").splitlines())
        coverage.append({"source": "crt.sh", "status": "completed", "detail": "Point-in-time CT lookup, not continuous monitoring."})
    except (OSError, ValueError, TypeError, AttributeError) as error:
        coverage.append({"source": "crt.sh", "status": "failed", "detail": type(error).__name__})
    accepted, excluded = [], []
    for name in [root] + sorted(names - {root}):
        reason = "outside domain boundary"
        try:
            name = domain(name)
            if name == root or name.endswith("." + root):
                if len(accepted) < MAX_HOSTS:
                    accepted.append(name)
                    continue
                reason = "host limit reached"
        except ValueError:
            reason = "invalid or wildcard hostname; not expanded"
        excluded.append({"asset": name[:253], "reason": reason})
    save(args.out / "discovery.json", {"root": root, "hosts": accepted, "coverage": coverage, "excluded": excluded})


def resolve(args):
    import dns.exception
    import dns.resolver
    data = read(args.out / "discovery.json")
    endpoints, excluded = [], data["excluded"]
    resolver = dns.resolver.Resolver()
    resolver.timeout, resolver.lifetime = 2, 4
    for host in data["hosts"]:
        found = set()
        for kind in ("A", "AAAA"):
            paced()
            try:
                found.update(str(answer) for answer in resolver.resolve(host, kind))
            except dns.exception.DNSException as error:
                data["coverage"].append({"source": host + ":" + kind, "status": "no_answer", "detail": type(error).__name__})
        for address in sorted(found):
            ip = ipaddress.ip_address(address)
            if not ip.is_global:
                excluded.append({"asset": host + "@" + address, "reason": "non-public address; not probed"})
                continue
            endpoints.append({"host": host, "ip": address})
    if len(endpoints) > 1024:
        raise ValueError("resolved address limit exceeded")
    save(args.out / "resolved.json", {"root": data["root"], "endpoints": endpoints, "coverage": data["coverage"]})
    rows(args.out / "excluded.jsonl", excluded)


def ports(args):
    data = read(args.out / "resolved.json")
    ports_to_scan = NONWEB_PORTS + (22,) if args.nonweb else WEB_PORTS
    def check(item):
        endpoint, port = item
        paced()
        try:
            with socket.create_connection((endpoint["ip"], port), timeout=3):
                return {**endpoint, "port": port, "status": "open"}
        except OSError as error:
            return {**endpoint, "port": port, "status": type(error).__name__}
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        checked = list(pool.map(check, ((ep, port) for ep in data["endpoints"] for port in ports_to_scan)))
    save(args.out / "ports.json", {**data, "ports": checked})


def receive(sock, size):
    result = b""
    while len(result) < size:
        chunk = sock.recv(size - len(result))
        if not chunk:
            raise OSError("unexpected close")
        result += chunk
    return result


def prepare_probes(args):
    data = read(args.out / "ports.json")
    endpoints = [{key: ep[key] for key in ("host", "ip", "port")} for ep in data["ports"] if ep["status"] == "open" and ep["port"] != 22]
    if len(endpoints) > 256:
        raise ValueError("more than 256 open TLS endpoints; split the approved scope")
    for name in ("rdp-ready.tsv", "openssl.done", "transcripts/completed", "rdp-completed"):
        (args.out / name).unlink(missing_ok=True)
    save(args.out / "rdp-targets.json", [ep for ep in endpoints if ep["port"] == 3389])
    plan = []
    for endpoint in endpoints:
        domain(endpoint["host"])
        address = ipaddress.ip_address(endpoint["ip"])
        if not address.is_global or not 1 <= endpoint["port"] <= 65535:
            raise ValueError("probe endpoint must have a public IP and valid port")
        target = f"[{address}]:{endpoint['port']}" if address.version == 6 else f"{address}:{endpoint['port']}"
        for profile, attempt in [(profile, attempt) for attempt in range(1, 4) for profile in PROFILES] + [("baseline", 1)]:
            plan.append({"endpoint": endpoint, "profile": profile, "attempt": attempt, "target": target})
    save(args.out / "probe-plan.json", plan)
    with (args.out / "probe-plan.tsv").open("w") as output:
        for index, item in enumerate(plan):
            output.write(f"{index}\t{item['target']}\t{item['endpoint']['host']}\t{PROFILES.get(item['profile'], 'baseline')}\n")


def parse_tls(endpoint, profile, attempt, output, status, elapsed_ms, observed_at):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    try:
        outcome = "timeout" if status == 124 else "failed"
        if "SSL_CONF_cmd" in output or "Unknown option" in output:
            raise RuntimeError("OpenSSL does not support the requested probe profile")
        match = re.search(r"(?:Server Temp Key|Peer Temp Key|Negotiated TLS1.3 group):\s*([^,\n]+)", output)
        group = match.group(1).strip() if match else "unknown"
        negotiated = re.search(r"New, (TLSv[\d.]+), Cipher is ([^\s]+)", output)
        finished = bool(re.search(r"<<<.*Handshake.*Finished", output))
        if finished and negotiated and negotiated.group(2) != "(NONE)":
            outcome = "success"
        elif outcome != "timeout":
            outcome = "tls_alert" if re.search(r"<<<.*Alert", output) else "transport_error"
        certs = []
        for pem in re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", output, re.S)[:16]:
            cert = x509.load_pem_x509_certificate(pem.encode())
            certs.append({"fingerprint": cert.fingerprint(hashes.SHA256()).hex(),
                          "signature_oid": cert.signature_algorithm_oid.dotted_string,
                          "signature": cert.signature_algorithm_oid._name,
                          "public_key_type": cert.public_key_algorithm_oid._name,
                          "not_after": cert.not_valid_after_utc.isoformat()})
        lengths = [int(value, 16) for value in re.findall(r">>>.*Handshake \[length ([0-9a-fA-F]+)\], ClientHello", output)]
        verify = re.search(r"Verify return code: (\d+)", output)
        alert = re.findall(r"<<<[^\n]*Alert[^\n]*", output)
        observation = {**endpoint, "profile": profile, "attempt": attempt, "observed_at": observed_at,
                       "outcome": outcome, "group": group, "protocol": negotiated.group(1) if negotiated else "unknown",
                       "cipher": negotiated.group(2) if negotiated else "unknown", "client_hello_bytes": sum(lengths),
                       "client_hello_count": len(lengths), "process_elapsed_ms": elapsed_ms,
                       "certificate_verify_code": int(verify.group(1)) if verify else -1,
                       "alert": alert[-1] if alert else "", "certificates": certs,
                       "transcript_sha256": hashlib.sha256(output.encode()).hexdigest(), "tool_version": VERSION}
        observation["evidence_id"] = digest(observation)
        return observation
    except (OSError, ValueError) as error:
        observation = {**endpoint, "profile": profile, "attempt": attempt, "observed_at": observed_at, "outcome": "transport_error",
                       "group": "unknown", "protocol": "unknown", "cipher": "unknown", "client_hello_bytes": 0,
                       "client_hello_count": 0, "process_elapsed_ms": elapsed_ms,
                       "certificate_verify_code": -1, "alert": type(error).__name__, "certificates": [],
                       "transcript_sha256": "", "tool_version": VERSION}
        observation["evidence_id"] = digest(observation)
        return observation


def probe(args):
    data = read(args.out / "ports.json")
    if not (args.transcripts / "completed").is_file():
        raise RuntimeError("OpenSSL collection did not complete")
    if any(ep["port"] == 3389 and ep["status"] == "open" for ep in data["ports"]) and not (args.out / "rdp-completed").is_file():
        raise RuntimeError("RDP bridge did not complete")
    plan = read(args.out / "probe-plan.json")
    observations = []
    for index, item in enumerate(plan):
        transcript = args.transcripts / str(index)
        status, elapsed, observed_at = transcript.with_suffix(".status").read_text().strip().split("\t")
        if int(status) not in (0, 1, 124):
            raise RuntimeError("OpenSSL invocation failed before evidence collection")
        observations.append(parse_tls(item["endpoint"], item["profile"], item["attempt"],
                                      transcript.with_suffix(".txt").read_text(errors="replace"),
                                      int(status), int(elapsed), observed_at))
    bundle = {"schema": "pqc-discovery-evidence-1", "run_id": str(uuid.uuid4()), "observed_at": now(),
              "scope": data["root"], "ruleset": RULESET, "openssl": (args.transcripts / "version.txt").read_text().strip(),
              "coverage": data["coverage"], "ports": data["ports"], "observations": observations}
    save(args.out / "evidence.json", bundle)


def validate_bundle(bundle):
    if bundle.get("schema") != "pqc-discovery-evidence-1":
        raise ValueError("unsupported evidence schema")
    domain(bundle["scope"])
    observations = bundle["observations"]
    if not isinstance(observations, list) or len(observations) > 100000:
        raise ValueError("invalid observation list")
    for observation in observations:
        expected = observation.get("evidence_id")
        if digest({k: v for k, v in observation.items() if k != "evidence_id"}) != expected:
            raise ValueError("evidence integrity check failed (hashes are not authenticity signatures)")
        if observation["profile"] not in (*PROFILES, "baseline") or observation["outcome"] not in ("success", "timeout", "tls_alert", "transport_error"):
            raise ValueError("invalid probe result")
        host = domain(observation["host"])
        if host != bundle["scope"] and not host.endswith("." + bundle["scope"]):
            raise ValueError("observation outside declared domain")
        ipaddress.ip_address(observation["ip"])
        if type(observation["port"]) is not int or not 1 <= observation["port"] <= 65535:
            raise ValueError("invalid port")
    return bundle


def classifications(bundle):
    grouped = {}
    for obs in bundle["observations"]:
        grouped.setdefault((obs["host"], obs["ip"], obs["port"]), []).append(obs)
    result = []
    for (host, address, port), observations in sorted(grouped.items()):
        profiles = {name: [o for o in observations if o["profile"] == name] for name in (*PROFILES, "baseline")}
        def consistent(name, outcome):
            values = profiles[name]
            return len(values) == 3 and {o["attempt"] for o in values} == {1, 2, 3} and all(o["outcome"] == outcome for o in values)
        def hybrid(name):
            return consistent(name, "success") and all(o["group"].lower() == "x25519mlkem768" for o in profiles[name])
        state, reason = "INCONCLUSIVE", "Insufficient or inconsistent observations; no intolerance claim."
        if hybrid("hybrid_preferred") and hybrid("hybrid_required"):
            state, reason = "HYBRID_ACTIVE", "X25519MLKEM768 negotiated in all preferred and required repeats."
        elif hybrid("hybrid_required"):
            state, reason = "HYBRID_AVAILABLE", "Hybrid negotiation succeeded when required; preference is not consistently hybrid."
        elif consistent("classical", "success") and consistent("hybrid_required", "tls_alert"):
            state, reason = "TESTED_GROUP_REJECTED", "TLS 1.3 classical control succeeds; X25519MLKEM768-only offer receives repeatable TLS alerts. Other PQ groups untested."
        elif consistent("classical", "success") and all(o["outcome"] in ("timeout", "transport_error") for o in profiles["hybrid_required"]) and len(profiles["hybrid_required"]) == 3:
            state, reason = "POSSIBLE_INTOLERANCE", "Repeated transport failures for hybrid-required with working controls; network or middlebox cause not established."
        elif profiles["baseline"] and profiles["baseline"][0]["outcome"] == "success" and profiles["baseline"][0]["protocol"] != "TLSv1.3":
            state, reason = "LEGACY_TLS_OBSERVED", "Baseline negotiated older TLS; failed TLS 1.3 probes do not prove PQ intolerance."
        result.append({"asset": host, "ip": address, "port": port, "classification": state, "reason": reason,
                       "pq_only": "MLKEM768_NEGOTIATED" if consistent("pq_only", "success") and all(o["group"] == "MLKEM768" for o in profiles["pq_only"]) else "NOT_ESTABLISHED",
                       "ruleset": RULESET, "evidence_ids": [o["evidence_id"] for o in observations]})
    return result


def classify(args):
    bundle = validate_bundle(read(args.out / "evidence.json"))
    results = classifications(bundle)
    rows(args.out / "classifications.jsonl", results)
    findings = []
    for row in results:
        if row["classification"] in ("TESTED_GROUP_REJECTED", "POSSIBLE_INTOLERANCE", "LEGACY_TLS_OBSERVED"):
            findings.append({"rule_id": row["classification"], "title": row["classification"].replace("_", " ").title(),
                             "asset": row["asset"], "location": f"{row['ip']}:{row['port']}", "severity": "low",
                             "description": row["reason"], "evidence": row["evidence_ids"], "ruleset": RULESET})
    rows(args.out / "findings.jsonl", findings)
    rows(args.out / "observations.jsonl", [{**{key: o[key] for key in ("host", "ip", "port", "profile", "attempt", "observed_at", "outcome", "group", "protocol", "cipher", "client_hello_bytes", "process_elapsed_ms", "certificate_verify_code", "evidence_id")}, "alert": o["alert"]} for o in bundle["observations"]])
    certificates = {}
    for obs in bundle["observations"]:
        for cert in obs["certificates"]:
            key = (obs["host"], obs["port"], cert["fingerprint"])
            certificates[key] = {"host": obs["host"], "port": obs["port"], **cert}
    rows(args.out / "certificates.jsonl", certificates.values())
    bundle["baseline"] = results
    bundle["ruleset"] = RULESET
    save(args.out / "export.json", bundle)


def report(args):
    bundle = validate_bundle(read(args.out / "export.json"))
    results = bundle["baseline"]
    assessed = [r for r in results if r["classification"] != "INCONCLUSIVE"]
    active = sum(r["classification"] == "HYBRID_ACTIVE" for r in results)
    metrics = [{"metric": "sampled_endpoints", "value": str(len(results)), "basis": LIMITATIONS},
               {"metric": "conclusive_endpoints", "value": str(len(assessed)), "basis": "All other endpoints remain unknown."},
               {"metric": "hybrid_active_percent_of_all_sampled", "value": str(round(100 * active / len(results), 1)) if results else "not assessed", "basis": "Not an organization readiness score; unknowns remain in denominator."},
               {"metric": "organization_readiness", "value": "not assessed", "basis": "Requires owners, data lifetimes, vendor and migration evidence."}]
    rows(args.out / "scorecard.jsonl", metrics)
    rows(args.out / "board.jsonl", metrics + [{"metric": "discovery_coverage", "value": json.dumps(bundle["coverage"]), "basis": "Provider failures reduce discovery coverage."}])
    rows(args.out / "heatmap.jsonl", [{"asset": r["asset"], "port": r["port"], "classification": r["classification"], "impact": "requires data sensitivity and retention", "effort": "requires owner estimate"} for r in results])
    rows(args.out / "vendor.jsonl", [{"asset": r["asset"], "port": r["port"], "vendor": "unattributed", "status": "requires diligence", "question": "Confirm TLS termination owner, ML-KEM roadmap, certificate/signing dependencies and rollout plan."} for r in results])
    budgets = []
    for row in results:
        for profile in PROFILES:
            samples = [o for o in bundle["observations"] if o["host"] == row["asset"] and o["ip"] == row["ip"] and o["port"] == row["port"] and o["profile"] == profile and o["outcome"] == "success"]
            budgets.append({"asset": row["asset"], "ip": row["ip"], "port": row["port"], "profile": profile, "successful_samples": len(samples),
                            "median_client_hello_bytes": str(statistics.median(o["client_hello_bytes"] for o in samples)) if samples else "not measured",
                            "median_process_elapsed_ms": str(statistics.median(o["process_elapsed_ms"] for o in samples)) if samples else "not measured",
                            "pilot_exit": "not assessed: process time includes connection and shutdown; not handshake latency; no budget supplied"})
    rows(args.out / "budget.jsonl", budgets)
    components = {}
    for obs in bundle["observations"]:
        if obs["outcome"] == "success" and obs["group"] != "unknown":
            name = obs["group"]
            components[name] = {"type": "cryptographic-asset", "bom-ref": "algorithm:" + name, "name": name,
                                "cryptoProperties": {"assetType": "algorithm"}}
        for cert in obs["certificates"]:
            name = cert["fingerprint"]
            components[name] = {"type": "cryptographic-asset", "bom-ref": "certificate:" + name, "name": "X.509 " + name,
                                "cryptoProperties": {"assetType": "certificate"},
                                "properties": [{"name": "pqc-discovery:signature-oid", "value": cert["signature_oid"]}]}
    bom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": "urn:uuid:" + str(uuid.uuid4()), "version": 1,
           "components": list(components.values())}
    save(args.out / "cbom.json", bom)
    rows(args.out / "cbom.jsonl", [{"format": "CycloneDX 1.6", "components": len(components), "document": json.dumps(bom), "coverage": LIMITATIONS}])


def ssh(args):
    data = read(args.out / "ports.json")
    result = []
    for ep in data["ports"]:
        if ep["port"] != 22 or ep["status"] != "open":
            continue
        paced()
        row = {"host": ep["host"], "ip": ep["ip"], "port": 22, "kex": [], "host_keys": [], "status": "inconclusive", "pq_offer": "unknown"}
        try:
            with socket.create_connection((ep["ip"], 22), timeout=8) as sock:
                sock.sendall(b"SSH-2.0-pqc_discovery_0.2\r\n")
                for _ in range(50):
                    line = b""
                    while not line.endswith(b"\n") and len(line) < 255:
                        line += receive(sock, 1)
                    if line.startswith(b"SSH-2.0-"):
                        break
                else:
                    raise ValueError("no SSH2 identification")
                header = receive(sock, 5)
                length, padding = struct.unpack(">IB", header)
                if not 6 <= length <= 35000 or not 4 <= padding < length - 1:
                    raise ValueError("invalid SSH packet")
                payload = receive(sock, length - 1)[:-padding]
                if len(payload) < 17 or payload[0] != 20:
                    raise ValueError("expected SSH KEXINIT")
                offset, lists = 17, []
                for _ in range(10):
                    size = struct.unpack(">I", payload[offset:offset + 4])[0]
                    offset += 4
                    if offset + size > len(payload):
                        raise ValueError("invalid SSH name-list")
                    lists.append(payload[offset:offset + size].decode("ascii").split(","))
                    offset += size
                row.update(kex=lists[0], host_keys=lists[1], status="advertised_only_no_authentication",
                           pq_offer="hybrid advertised" if any("mlkem" in k or "sntrup" in k for k in lists[0]) else "no recognized hybrid advertised")
        except (OSError, ValueError, struct.error):
            pass
        result.append(row)
    rows(args.out / "ssh.jsonl", result)


def dnssec(args):
    import dns.exception
    import dns.flags
    import dns.resolver
    data = read(args.out / "resolved.json")
    resolver = dns.resolver.Resolver()
    resolver.timeout, resolver.lifetime = 2, 4
    resolver.use_edns(edns=0, ednsflags=dns.flags.DO, payload=1232)
    result = []
    for host in sorted({data["root"], *(e["host"] for e in data["endpoints"])}):
        for record_type in ("DNSKEY", "RRSIG"):
            paced()
            try:
                response = resolver.resolve(host, record_type)
                for record in response:
                    result.append({"host": host, "record_type": record_type, "algorithm": int(record.algorithm), "status": "observed", "validation": "algorithm inventory only; chain of trust not validated"})
            except dns.exception.DNSException as error:
                result.append({"host": host, "record_type": record_type, "algorithm": -1, "status": type(error).__name__, "validation": "No answer does not establish an unsigned parent zone."})
    rows(args.out / "dnssec.jsonl", result)


def prepare_repo(args):
    parsed = urllib.parse.urlsplit(args.scope)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("repository scope must be an HTTPS URL without credentials, query or fragment")
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "repository-url.txt").write_text(args.scope + "\n")


PATTERNS = {
    "algorithms": r"\b(?:RSA|ECDSA|ECDH|Ed25519|Ed448|X25519|X448|DSA|AES|SHA-?1|SHA-?256|SHA-?384|SHA-?512|MD5|ML[-_]?KEM(?:768|1024|512)?|ML[-_]?DSA|SLH[-_]?DSA|Kyber|Dilithium|Falcon|sphincs)\b",
    "dependencies": r"\b(?:openssl|boringssl|libressl|bouncycastle|cryptography|pyopenssl|pycryptodome|crypto-js|node-forge|libsodium|sodium|ring|rustls|crypto/tls|crypto/rsa|golang.org/x/crypto|pqcrypto|liboqs|oqs)\b",
    "signing": r"\b(?:cosign|sigstore|jarsigner|apksigner|codesign|gpg|gitsign|signtool|SignTool|signingConfig|signingConfigs|maven-gpg-plugin)\b",
    "tls_config": r"\b(?:ssl_protocols|ssl_ciphers|ssl_certificate|ssl_ecdh_curve|TLSv1\.[0-3]|MinVersion|MaxVersion|CurvePreferences|tls\.Config|SSLCertificateFile|SSLCipherSuite|SSLProtocol|javax.net.ssl.keyStore)\b",
}
MANIFESTS = {"go.mod": "go", "go.sum": "go", "package.json": "javascript", "package-lock.json": "javascript", "yarn.lock": "javascript", "pnpm-lock.yaml": "javascript", "requirements.txt": "python", "pyproject.toml": "python", "poetry.lock": "python", "uv.lock": "python", "pom.xml": "java", "build.gradle": "java", "build.gradle.kts": "java", "Cargo.toml": "rust", "Cargo.lock": "rust", "packages.config": "dotnet", "packages.lock.json": "dotnet"}


def select_blobs(args):
    if (args.out / "repository-tree.bin").stat().st_size > MAX_BYTES:
        raise ValueError("tool output exceeds 25 MiB")
    listing = (args.out / "repository-tree.bin").read_bytes().decode("utf-8", "replace")
    selected, skipped, total = [], 0, 0
    for entry in listing.split("\x00"):
        if not entry:
            continue
        metadata, path = entry.split("\t", 1)
        mode, kind, oid, size = metadata.split()
        if kind != "blob" or mode not in ("100644", "100755") or int(size) > 2 * 1024 * 1024 or len(selected) >= 20000 or total + int(size) > 100 * 1024 * 1024:
            skipped += 1
            continue
        if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", oid):
            raise ValueError("invalid Git object ID")
        selected.append({"path": path, "oid": oid, "size": int(size)})
        total += int(size)
    save(args.out / "repository-manifest.json", {"files": selected, "skipped": skipped})
    (args.out / "repository-objects.txt").write_text("".join(item["oid"] + "\n" for item in selected))


def inventory(args):
    manifest = read(args.out / "repository-manifest.json")
    results = {key: [] for key in (*PATTERNS, "keys")}
    counts = {"files_scanned": 0, "files_skipped": manifest["skipped"], "bytes_scanned": 0}
    commit = (args.out / "repository-commit.txt").read_text().strip()
    with args.blobs.open("rb") as source:
        for item in manifest["files"]:
            path = item["path"]
            header = source.readline().decode().strip().split()
            if header != [item["oid"], "blob", str(item["size"])]:
                raise ValueError("Git blob artifact does not match repository manifest")
            raw = source.read(item["size"])
            if len(raw) != item["size"] or source.read(1) != b"\n":
                raise ValueError("incomplete Git blob artifact")
            counts["files_scanned"] += 1
            counts["bytes_scanned"] += len(raw)
            suffix = Path(path).suffix.lower()
            text = raw.decode("utf-8", "replace")
            private = bool(re.search(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----", text))
            if private or suffix in (".key", ".p12", ".pfx", ".jks", ".keystore", ".pem", ".crt", ".cer"):
                results["keys"].append({"path": path, "line": 0, "match": "private key marker" if private else "key or certificate container", "ecosystem": "unknown", "confidence": "metadata only; not decrypted", "commit": commit})
            if b"\x00" in raw or private:
                continue
            ecosystem = MANIFESTS.get(Path(path).name, "dotnet" if suffix == ".csproj" else "unknown")
            for category, pattern in PATTERNS.items():
                if category == "dependencies" and ecosystem == "unknown":
                    continue
                for number, line in enumerate(text.splitlines(), 1):
                    for match in sorted(set(re.findall(pattern, line, re.I))):
                        results[category].append({"path": path, "line": number, "match": match, "ecosystem": ecosystem, "confidence": "heuristic reference; use and reachability unverified", "commit": commit})
                        if len(results[category]) > 50000:
                            raise ValueError("inventory match limit exceeded")
    for category, values in results.items():
        rows(args.out / (category + ".jsonl"), values)
    rows(args.out / "repo_summary.jsonl", [{"category": category, "matches": len(values), "files_scanned": counts["files_scanned"], "files_skipped": counts["files_skipped"], "commit": commit,
                                            "coverage": "Six ecosystem manifest heuristics; no code, hooks, checkout, builds or dependencies executed. No private key or source lines emitted. History, submodules and encrypted containers unassessed."} for category, values in results.items()])


def stage(args):
    root = Path(args.scope_root).resolve()
    source = (root / args.scope).resolve()
    if source == root or not source.is_relative_to(root) or Path(args.scope).is_absolute():
        raise ValueError("evidence scope must stay beneath the scope storage root")
    data = read(source)
    if data.get("schema") == "pqc-discovery-comparison-1":
        before, after = validate_bundle(data["before"]), validate_bundle(data["after"])
        if before["scope"] != after["scope"] or before["run_id"] == after["run_id"]:
            raise ValueError("posture comparison requires two distinct runs of the same scope")
        save(args.out / "before.json", before)
        save(args.out / "evidence.json", after)
    else:
        validate_bundle(data)
        save(args.out / "before.json", data)
        save(args.out / "evidence.json", data)


def diff(args):
    before = validate_bundle(read(args.out / "before.json"))
    after = validate_bundle(read(args.out / "evidence.json"))
    temporal = before["run_id"] != after["run_id"]
    previous = classifications(before) if temporal else before.get("baseline")
    if previous is None:
        raise ValueError("offline ruleset comparison requires baseline classifications from export.json")
    key = lambda r: (r["asset"], r["ip"], r["port"])
    old, new = {key(r): r for r in previous}, {key(r): r for r in classifications(after)}
    changes = []
    for endpoint in sorted(old.keys() | new.keys()):
        left, right = old.get(endpoint), new.get(endpoint)
        prior, current = left["classification"] if left else "NOT_OBSERVED", right["classification"] if right else "NOT_OBSERVED"
        changes.append({"asset": endpoint[0], "ip": endpoint[1], "port": endpoint[2], "before": prior, "after": current,
                        "kind": "observation_drift" if temporal else "ruleset_reclassification", "changed": str(prior != current).lower(),
                        "before_ruleset": RULESET if temporal else before.get("ruleset", "unknown"), "after_ruleset": RULESET,
                        "note": "Missing observations do not prove remediation; uploads are not authenticated evidence."})
    rows(args.out / "drift.jsonl", changes)


def doctor(args):
    import cryptography
    import dns
    print(json.dumps({"version": VERSION, "ruleset": RULESET, "cryptography": cryptography.__version__, "dnspython": dns.__version__}))


def main():
    parser = argparse.ArgumentParser(description="Bounded PQC evidence discovery and offline classification; no organization readiness claims.")
    parser.add_argument("--version", action="version", version=VERSION)
    parser.add_argument("command", choices=("discover", "resolve", "ports", "prepare_probes", "probe", "classify", "report", "ssh", "dnssec", "prepare_repo", "select_blobs", "inventory", "stage", "diff", "doctor"))
    parser.add_argument("--out", type=Path)
    parser.add_argument("--scope")
    parser.add_argument("--scope-root", default=os.environ.get("SCOPE_STORAGE_PATH", str(Path(os.environ["STORAGE_PATH"]) / "scopes") if os.environ.get("STORAGE_PATH") else "."))
    parser.add_argument("--hosts", type=Path)
    parser.add_argument("--transcripts", type=Path)
    parser.add_argument("--blobs", type=Path)
    parser.add_argument("--nonweb", action="store_true")
    args = parser.parse_args()
    if args.command != "doctor" and args.out is None:
        parser.error("--out is required for this command")
    if args.out:
        args.out = args.out.resolve()
    if args.command in ("discover", "prepare_repo", "stage") and not args.scope:
        parser.error("--scope is required for this command")
    if args.command == "probe" and args.transcripts is None:
        parser.error("--transcripts is required for probe")
    if args.command == "inventory" and args.blobs is None:
        parser.error("--blobs is required for inventory")
    globals()[args.command](args)


def entrypoint():
    try:
        main()
    except Exception as error:
        print(f"PQC operation failed: {type(error).__name__}: {error if isinstance(error, (ValueError, RuntimeError)) else 'check input and worker dependencies'}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(entrypoint())
