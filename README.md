# sksac

sksac - SSH Key Server Access Checker is a fast, concurrent tool for auditing SSH private keys against servers.


## Installation

```bash
go install github.com/AliHzSec/sksac@latest
```

## Usage

```
sksac [flags]

Flags:

INPUT:
   -i,  -identity-file string   Path to SSH private key
   -h,  -host string            Single target host (e.g. 1.1.1.1 or host.com:2222)
   -hl, -host-list string       File with one host per line
   -u,  -username string        Single SSH username
   -ul, -username-list string   File with one username per line

ENUMERATION:
   -t,  -threads int            Number of concurrent threads (default 10)
   -a,  -access-only            Only show hosts with access

OUTPUT:
   -s,  -silent                 Silent mode (no banner, no progress)
   -o,  -output                 Save results to file
   -op, -output-path string     Directory to save output file (use with -o)
   -d,  -debug                  Show raw SSH output
   -nc, -no-color               Disable colors
```

## Examples

Check a single host with a single username:

```bash
sksac -i ~/.ssh/id_ed25519 -h 192.168.1.10 -u root
```

Check a single host on a non-default port:

```bash
sksac -i ~/.ssh/id_ed25519 -h 192.168.1.10:2222 -u root
```

Check a list of servers against a list of usernames with 100 threads:

```bash
sksac -i ~/.ssh/id_ed25519 -hl servers.txt -ul usernames.txt -t 100
```

Only show servers where access was successful:

```bash
sksac -i ~/.ssh/id_ed25519 -hl servers.txt -ul usernames.txt -t 100 -access-only
```

Silent mode — output only, no banner or progress bar (useful for piping):

```bash
sksac -i ~/.ssh/id_ed25519 -hl servers.txt -ul usernames.txt -t 100 -a -s
```

Save results to a file:

```bash
sksac -i ~/.ssh/id_ed25519 -hl servers.txt -ul usernames.txt -t 100 -a -o
```

## Input Formats

**Host list** — one entry per line, port is optional (defaults to 22):

```
192.168.1.10
192.168.1.11:2222
server.example.com
server.example.com:4328
```

**Username list** — one username per line, validated against POSIX standard:

```
root
ubuntu
deploy
git
```

## How It Works

For each combination of host and username, sksac runs:

```bash
ssh -i KEY -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o BatchMode=yes -o ConnectTimeout=5 -p PORT -T USER@HOST 'exit'
```

If the connection succeeds (exit code 0), access is confirmed and the target is reported as accessible.

## Notes

- SSH key file must have permissions set to `600`. sksac will refuse to run otherwise.
- Usernames are validated against the POSIX / IEEE 1003.1-2001 standard. Invalid entries in a username list are silently skipped.
- Hostnames are resolved using the system default DNS resolver.
- Total targets checked = number of hosts x number of usernames.

## License

MIT
