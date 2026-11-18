# ssh_known_hosts_kit

Parse a single line (or a whole file) of an OpenSSH `known_hosts` file into a `KnownHost` record with the hostname field, key type, decoded key bytes, and optional marker.

```python
from ssh_known_hosts_kit import parse_known_host
from ssh_known_hosts_kit.core import parse_known_hosts

record = parse_known_host("@revoked host1,host2 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAECAw=")
assert record.marker == "@revoked"
assert record.hosts == "host1,host2"
assert record.key_type == "ssh-ed25519"
assert isinstance(record.key, bytes)

for record in parse_known_hosts("host1 ssh-rsa AAAAB3NzaC1yc2E="):
    print(record.hosts, record.hashed)
```

## Why this exists

Most tools that read `known_hosts` either shell out to `ssh-keygen -F` or
reimplement the format badly.  The format is small enough to parse directly,
which avoids a subprocess and makes the result easy to test.  The trade-off
is that hashed hostnames stay hashed: we return the literal `|1|salt|hash`
token and let the caller decide whether to match it.  Reversing the hash is
not possible, so pretending otherwise would be a lie.

## The awkward edge

The key material is base64.  Real files are padded, but hand-edited files and
some exporters are not.  We accept both by adding padding before decoding,
and we raise `KnownHostsError` for genuinely invalid base64 rather than
silently returning empty bytes.  A line with a marker but no hostname is also
rejected, because there is nothing useful to do with it.
