# Docker outer-profile manifest

`compose.prod.yaml` only receives Docker `security_opt` strings; Compose cannot
tell whether a host profile was reviewed or whether a file changed after
review. Production operators therefore keep a root-owned, non-writable JSON
manifest beside the host deployment and validate it before startup:

```bash
python scripts/validate_docker_outer_profiles.py \
  --manifest /etc/khaos/docker/outer-profiles.json
docker compose --file compose.prod.yaml up --build --wait
```

The manifest must contain the exact values exported to the Compose process and
SHA-256 digests for the source files:

```json
{
  "schema_version": 1,
  "profiles": {
    "seccomp": {
      "option": "seccomp=/etc/khaos/docker/seccomp.json",
      "sha256": "<64 lowercase hex characters>"
    },
    "apparmor": {
      "option": "apparmor=khaos-agent",
      "source": "/etc/apparmor.d/khaos-agent",
      "sha256": "<64 lowercase hex characters>"
    },
    "systempaths": {"option": "systempaths=default"}
  }
}
```

The validator rejects symlinks, non-regular or group/world-writable files on
POSIX hosts, option drift, missing digests, `systempaths=unconfined`, and all
`*=unconfined` values in production mode. Windows `st_mode` values do not
represent NTFS ACLs, so this Docker/POSIX preflight does not treat synthetic
Windows mode bits as an ACL oracle; Windows ACL enforcement remains in the
native sandbox/service boundary. The disposable
`scripts/compose-security-e2e.sh` path is the only caller allowed to pass
`--disposable`; it is explicitly non-production evidence.

Khaos intentionally does not ship one universal seccomp/AppArmor profile:
nested user-namespace and mount behavior varies by host kernel and Docker
runtime. The manifest is the deployment-specific review and hash boundary;
the real composition probe still has to pass before production execution is
accepted.
