#!/usr/bin/env python3
"""
FIDO2 Shim for Crispkey - Python interface to YubiKey using fido2-tools.
"""

import sys
import json
import os
import subprocess
import tempfile

RP_ID = "crispkey"


def parse_devices():
    """List connected FIDO2 devices."""
    try:
        result = subprocess.run(
            ["fido2-token", "-L"], capture_output=True, text=True, timeout=5
        )
        if result.returncode != 0:
            return {"error": result.stderr}

        devices = []
        for line in result.stdout.strip().split("\n"):
            if line:
                devices.append(
                    {
                        "vendor": "/dev/hidraw1",
                        "product": line.split(":", 1)[-1].strip(),
                        "path": "/dev/hidraw1",
                    }
                )
        return {"devices": devices}
    except Exception as e:
        return {"error": str(e)}


def find_device():
    """Find first FIDO2 device."""
    try:
        result = subprocess.run(
            ["fido2-token", "-L"], capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip().split("\n")[0].split(":")[0].strip()
    except:
        pass
    return "/dev/hidraw1"


def enroll(pin, user_id, challenge):
    """Enroll a new credential using fido2-cred."""
    try:
        import base64
        import hashlib

        challenge_bytes = (
            bytes.fromhex(challenge) if isinstance(challenge, str) else challenge
        )
        user_id_bytes = bytes.fromhex(user_id) if isinstance(user_id, str) else user_id

        client_data = {
            "type": "webauthn.create",
            "challenge": base64.b64encode(challenge_bytes).decode(),
            "origin": "crispkey://localhost",
        }
        client_data_json = json.dumps(client_data, separators=(",", ":"))
        client_data_hash = base64.b64encode(
            hashlib.sha256(client_data_json.encode()).digest()
        ).decode()
        user_id_b64 = base64.b64encode(user_id_bytes).decode()

        input_data = f"{client_data_hash}\n{RP_ID}\ncrispkey\n{user_id_b64}\n"

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix="_in") as f:
            f.write(input_data)
            temp_in = f.name
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix="_out") as f:
            temp_out = f.name

        try:
            # Use stdin directly for PIN - the tool reads from stdin
            proc = subprocess.Popen(
                [
                    "fido2-cred",
                    "-M",
                    "-i",
                    temp_in,
                    "-o",
                    temp_out,
                    find_device(),
                    "es256",
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            # Send PIN followed by newline
            stdout, stderr = proc.communicate(input=pin + "\n", timeout=30)

            if proc.returncode != 0:
                err = stderr or stdout
                if "PIN" in err.upper():
                    return {"error": "PIN_REQUIRED"}
                return {"error": err.strip() or "Enrollment failed"}

            # Read output - format is:
            # 1. clientDataHash (base64)
            # 2. rpId
            # 3. format (e.g., "packed")
            # 4. authData (base64)
            # 5. credentialId (base64)
            # 6. signature (base64)
            # 7. attestation certificate (optional)
            try:
                output = open(temp_out).read()
            except:
                output = stdout

            lines = output.strip().split("\n")
            if len(lines) >= 5:
                cred_id = lines[4].strip()
                pub_key = lines[3].strip()  # authData contains the public key
                return {"credential_id": cred_id, "public_key": pub_key, "rp_id": RP_ID}
            return {"error": "Failed to parse credential", "output": output[:200]}
        finally:
            for f in [temp_in, temp_out]:
                try:
                    os.unlink(f)
                except:
                    pass
    except Exception as e:
        return {"error": str(e)}


def authenticate(credential_id, challenge, rp_id=None):
    """Authenticate using fido2-assert."""
    try:
        import base64

        rp_id = rp_id or RP_ID

        # Handle both hex and base64 input
        if isinstance(credential_id, str):
            try:
                cred_id_bytes = bytes.fromhex(credential_id)
            except:
                cred_id_bytes = base64.b64decode(credential_id)
        else:
            cred_id_bytes = credential_id

        if isinstance(challenge, str):
            try:
                challenge_bytes = bytes.fromhex(challenge)
            except:
                challenge_bytes = base64.b64decode(challenge)
        else:
            challenge_bytes = challenge

        challenge_b64 = base64.b64encode(challenge_bytes).decode()

        # Use files instead of stdin
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix="_in") as f_in:
            f_in.write(
                f"{challenge_b64}\n{rp_id}\n{base64.b64encode(cred_id_bytes).decode()}\n"
            )
            temp_in = f_in.name
        with tempfile.NamedTemporaryFile(
            mode="w", delete=False, suffix="_out"
        ) as f_out:
            temp_out = f_out.name

        try:
            device = find_device()
            result = subprocess.run(
                ["fido2-assert", "-G", "-i", temp_in, "-o", temp_out, device],
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode != 0:
                return {"error": result.stderr or result.stdout}

            try:
                output = open(temp_out).read()
            except:
                output = result.stdout

            lines = output.strip().split("\n")
            # Format: clientDataHash, rpId, authData, signature
            if len(lines) >= 4:
                auth_data = lines[2].strip()
                sig = lines[3].strip()
                return {
                    "auth_data": auth_data,
                    "signature": sig,
                    "client_data_json": json.dumps(
                        {
                            "type": "webauthn.get",
                            "challenge": challenge_b64,
                            "origin": "crispkey://localhost",
                            "crossOrigin": False,
                        }
                    ),
                    "credential_id": credential_id,
                }
            return {"error": "Failed to parse assertion", "output": output[:200]}
        finally:
            for f in [temp_in, temp_out]:
                try:
                    os.unlink(f)
                except:
                    pass
    except Exception as e:
        return {"error": str(e)}


def handle_command(cmd):
    action = cmd.get("action")
    if action == "list_devices":
        return parse_devices()
    elif action == "enroll":
        return enroll(
            cmd.get("pin", ""), cmd.get("user_id", "0000"), cmd.get("challenge", "")
        )
    elif action == "authenticate":
        return authenticate(
            cmd.get("credential_id", ""), cmd.get("challenge", ""), cmd.get("rp_id")
        )
    elif action == "credential_info":
        return {"rp_id": cmd.get("rp_id", RP_ID), "info": "N/A"}
    return {"error": "Unknown action"}


def main():
    while True:
        try:
            line = sys.stdin.readline()
            if not line:
                break
            print(json.dumps(handle_command(json.loads(line.strip()))), flush=True)
        except Exception as e:
            print(json.dumps({"error": str(e)}), flush=True)


if __name__ == "__main__":
    main()
