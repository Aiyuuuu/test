#!/usr/bin/env python3
"""
WARNING: This file intentionally contains insecure patterns for educational use only.
Run only in a safe sandbox. Do NOT copy these patterns into production code.
Each insecure pattern is annotated with CWE references and a short comment.
"""

import os
import subprocess
import sqlite3
import hashlib
import pickle
import socket
import tempfile
import random
import requests  # used to show insecure TLS handling (do not actually call external hosts)
from http.server import BaseHTTPRequestHandler, HTTPServer

# 1) CWE-089: SQL Injection
def sql_injection(username):
    # Builds SQL by string concat; attacker can inject SQL via username.
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT);")
    cur.execute("INSERT INTO users (name) VALUES ('alice')")
    # Vulnerable query:
    query = "SELECT id FROM users WHERE name = '%s';" % username
    print("Executing SQL:", query)
    cur.execute(query)  # CWE-89

# 2) CWE-078: OS Command Injection
def os_command_injection(user_cmd):
    # Directly passes untrusted string to shell; attacker can run arbitrary commands.
    os.system("echo Running user command && " + user_cmd)  # CWE-78

# 3) CWE-094: Code Injection (eval)
def eval_untrusted(user_expr):
    # Evaluates arbitrary Python from user
    print("Result:", eval(user_expr))  # CWE-94

# 4) CWE-502: Deserialization of Untrusted Data
def unsafe_deserialize(serialized_bytes):
    # Using pickle.loads on untrusted data is dangerous (it can execute arbitrary code)
    obj = pickle.loads(serialized_bytes)  # CWE-502
    print("Deserialized:", obj)

# 5) CWE-798: Use of Hard-coded Credentials
def hardcoded_credentials():
    # Hard-coded credentials embedded in code
    username = "admin"
    password = "P@ssw0rd123"  # CWE-798
    print("Using credentials:", username, password)

# 6) CWE-327 / CWE-328: Use of a Broken or Risky Cryptographic Algorithm
def weak_hash(password):
    # MD5 is broken for security purposes (fast, collision-prone)
    h = hashlib.md5(password.encode()).hexdigest()  # CWE-327
    print("MD5(password) =", h)

# 7) CWE-319 / CWE-311: Cleartext Transmission of Sensitive Information / Sensitive Data over Insecure Channel
def send_plaintext(host, port, secret):
    # Sends secret over an unencrypted socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    s.sendall(secret.encode())  # CWE-319/CWE-311
    s.close()

# 8) CWE-022: Path Traversal
def path_traversal_read(filename):
    # Reads user-supplied filename without sanitization; can access arbitrary files via ../
    with open(filename, 'r') as fh:  # CWE-22
        return fh.read()

# 9) CWE-200 / CWE-532: Information Exposure (logging secrets)
def leak_secrets():
    secret = "SECRET_TOKEN_ABC123"
    # Logging a secret to stdout/logs
    print("DEBUG: secret is", secret)  # CWE-200 / CWE-532

# 10) CWE-377 / CWE-379: Insecure Temporary File (race condition)
def insecure_tempfile():
    # tempfile.mktemp is insecure because of race conditions
    name = tempfile.mktemp(prefix="tmpdemo_")  # CWE-377
    f = open(name, "w")  # race window: another process could create this file
    f.write("temporary data\n")
    f.close()
    print("Wrote insecure temp file:", name)

# 11) CWE-434: Unrestricted File Upload (dangerous file types allowed)
def save_uploaded_file(uploaded_filename, file_bytes):
    # Saves anything uploaded without checking type, path, or size
    with open(uploaded_filename, "wb") as out:  # CWE-434
        out.write(file_bytes)
    print("Saved uploaded file:", uploaded_filename)

# 12) CWE-732: Incorrect Permission Assignment for Critical Resource
def create_world_writable_file(name):
    # Creates file with overly permissive permissions (0777) enabling tampering
    with open(name, "w") as f:
        f.write("dangerous content\n")
    os.chmod(name, 0o777)  # CWE-732
    print("Created world-writable:", name)

# 13) CWE-601: Open Redirect
def open_redirect(target_url):
    # Redirects to URL supplied by user without validation (in a real web handler this is dangerous)
    print("Redirecting to", target_url)  # CWE-601

# 14) CWE-338: Use of Cryptographically Weak PRNG
def weak_token():
    # Uses random.random (not cryptographically secure) to generate tokens
    token = str(int(random.random() * 10**9))  # CWE-338
    print("Weak token:", token)
    return token

# 15) CWE-295: Improper Certificate Validation (Skipping TLS verification)
def insecure_tls_request(url):
    # Disables certificate verification — subject to MITM.
    # (DO NOT actually call arbitrary URLs with verify=False outside sandbox)
    r = requests.get(url, verify=False)  # CWE-295
    print("Status (insecure TLS):", r.status_code)

# 16) CWE-94 variant: exec on user input
def exec_payload(payload):
    # Another code-execution sink using exec
    exec(payload)  # CWE-94

# 17) CWE-789: Memory Resource Exhaustion (Denial of Service via user-provided size)
def allocate_from_user(n):
    # Allocates a list of user-provided size without validation; can exhaust memory
    data = [0] * int(n)  # CWE-789
    print("Allocated list of length", len(data))

# 18) CWE-522 / CWE-312: Storing Sensitive Information in Cleartext (on disk)
def store_password_cleartext(path, pwd):
    with open(path, "w") as f:  # CWE-312 / CWE-522
        f.write("password=" + pwd + "\n")
    print("Stored password on disk (cleartext):", path)

# Minimal demonstration (DO NOT use inputs from real users)
if __name__ == "__main__":
    print("Insecure demo starting... DO NOT RUN ON PRODUCTION")

    # 1: SQL injection
    sql_injection("alice'; DROP TABLE users; --")

    # 2: OS command injection
    os_command_injection("; echo hacked; /bin/true")

    # 3: eval
    try:
        eval_untrusted("__import__('os').system('echo eval executed')")
    except Exception as e:
        print("eval failed (as expected in some envs):", e)

    # 4: unsafe deserialize (demonstrative: we create a malicious pickle payload)
    # For safety we won't craft a truly malicious payload here, but the usage below is the point.
    try:
        unsafe_deserialize(pickle.dumps({"ok": True}))
    except Exception as e:
        print("pickle demo error:", e)

    # 5: hard-coded credentials
    hardcoded_credentials()

    # 6: weak hash
    weak_hash("password123")

    # 7: send plaintext (won't actually connect in many envs; user should sandbox)
    # send_plaintext("127.0.0.1", 9999, "supersecret")

    # 8: path traversal read (commented to avoid accidental disclosure)
    # print(path_traversal_read("../../etc/passwd"))

    # 9: leak secrets
    leak_secrets()

    # 10: insecure tempfile
    insecure_tempfile()

    # 11: save uploaded file (we use a safe test name)
    save_uploaded_file("uploaded_test.bin", b"dummy content")

    # 12: create world-writable file
    create_world_writable_file("public_file.txt")

    # 13: open redirect
    open_redirect("http://evil.example.com/?q=phish")

    # 14: weak token
    weak_token()

    # 15: insecure TLS request (do NOT call external URLs in an untrusted environment)
    # insecure_tls_request("https://example.com")

    # 16: exec
    try:
        exec_payload("print('exec ran')")
    except Exception as e:
        print("exec error:", e)

    # 17: allocate from user (commented out to avoid actual exhaustion)
    # allocate_from_user(10**8)

    # 18: store password in cleartext
    store_password_cleartext("clear_pw.txt", "mysecret")

    print("Demo finished (if it ran).")
