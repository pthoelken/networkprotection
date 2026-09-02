# Network Protection

Network Protection maintains several source-IP blocklists in dedicated Linux
`ipset` sets and applies them through isolated `iptables`/`ip6tables` chains. A
systemd timer refreshes the data after boot and every 24 hours.

The managed sources are:

- the blocklist.de IPv4 bad-IP list plus a local custom blacklist;
- configurable country blocks generated from DB-IP Country Lite;
- current IPv4 and IPv6 prefixes announced by Spamhaus ASN-DROP networks;
- a local IPv4/IPv6 whitelist that overrides all three managed block sources.

## Supported systems

The package targets systemd-based Debian and Ubuntu systems using `iptables`
and `ipset`. It installs these runtime dependencies automatically: `bash`,
`curl`, `gzip`, `ipset`, `iptables`, `python3`, and `util-linux`.

## Install or upgrade with one command

Each version tag publishes a GitHub Release with a stable package name. Install
or upgrade the latest release with this Bash one-liner:

```bash
curl -fsSL 'https://github.com/pthoelken/networkprotection/releases/latest/download/networkprotection_all.deb' -o /tmp/networkprotection.deb && sudo apt-get install -y /tmp/networkprotection.deb
```

Change the GitHub owner or repository in the URL when using a fork. Private
repositories require an authenticated download. After installation, inspect the
version and start the first update manually:

```bash
/opt/networkprotection/networkprotection.sh --version
sudo systemctl start networkprotection.service
sudo systemctl status networkprotection.service
```

Run the same one-liner for every later upgrade. The package supports systems
previously installed with `install.sh` as well as older package versions:

- executables below `/opt/networkprotection` are updated;
- `/etc/networkprotection/networkprotection.conf` is never overwritten;
- the custom blacklist and whitelist are never overwritten;
- missing configuration files are created from the current defaults;
- unchanged legacy systemd units from `install.sh` are migrated to the
  package-owned units, while locally customized overrides are preserved;
- the timer remains enabled across upgrades.

The Debian package uses epoch `1`, so version `1:1.0.0` also upgrades cleanly
from any legacy date-based package version such as `2026.07.27-6`.

The package does not immediately run a firewall refresh during installation,
which makes upgrades safer over SSH. The timer schedules the first refresh two
minutes after it is activated, or it can be triggered with the command above.

## IP and CIDR whitelist

The whitelist is enabled by default and stored at:

```text
/etc/networkprotection/whitelist.txt
```

Add one IPv4 address, IPv6 address, or CIDR per line. Blank lines and comments
are allowed. Plain addresses are treated as `/32` for IPv4 or `/128` for IPv6.

```text
# Keep China blocked, except for this exact host
203.0.113.10/32

# Allow a complete partner network
198.51.100.0/24

# IPv6 is supported as well
2001:db8:1234::/48
```

For example, `BLOCK_COUNTRIES="CN,RU,IR"` continues to block all generated
Chinese networks except a matching address or subnet in the whitelist. The
same exception also takes precedence over the bad-IP and ASN-DROP sets.

Whitelist entries create a `RETURN` rule at the beginning of the dedicated
Network Protection chain. This is intentional: matching traffic skips only
this project's block rules and then continues through the remaining `INPUT`
rules. It is not globally accepted and can still be blocked by Fail2ban,
CrowdSec, or another firewall rule.

After editing the file, apply and verify it:

```bash
sudo systemctl start networkprotection.service
sudo ipset list networkprotection_allow_v4
sudo ipset list networkprotection_allow_v6
```

The complete whitelist is validated before activation. Networks are
canonicalized, deduplicated, and collapsed. Both new sets are prepared before
they replace the active IPv4/IPv6 pair. If validation or loading fails, the
previous valid whitelist stays active.

## Configuration

The main configuration is:

```text
/etc/networkprotection/networkprotection.conf
```

Common settings are:

```bash
ENABLE_WHITELIST=yes
WHITELIST_FILE="/etc/networkprotection/whitelist.txt"

ENABLE_IP_BLOCKLIST=yes
BLOCKLIST_URL="https://lists.blocklist.de/lists/all.txt"
CUSTOM_LIST_FILE="/etc/networkprotection/custom-blacklist.txt"
MIN_BLOCKLIST_ENTRIES=1000

ENABLE_GEO_BLOCKLIST=yes
BLOCK_COUNTRIES="CN,RU,IR,KP,BY,BR,IN,ID,VN,PK,BD,TH"

ENABLE_ASN_DROP=yes
ASN_DROP_RIPESTAT_WORKERS=4
```

New settings have safe defaults in the executable, so an existing configuration
does not need to be replaced during an upgrade. To disable the exception layer,
set `ENABLE_WHITELIST=no`.

## Firewall behavior

The service owns only its named ipsets, the `NETWORKPROTECTION` chain in each
address family, and a commented jump from `INPUT` to that chain. It does not
flush foreign chains, stop other security tools, or write a global
`iptables-save` snapshot.

The IPv4 chain is evaluated in this order:

1. whitelist: `RETURN`;
2. external and local bad-IP list: `DROP`;
3. GeoIP country list: `DROP`;
4. Spamhaus ASN-DROP IPv4 list: `DROP`.

The IPv6 chain evaluates the IPv6 whitelist before Spamhaus ASN-DROP IPv6. New
block and allow sets are populated in the background and activated with
`ipset swap`, avoiding an empty protection window during routine updates.

The service uses the standard `-m set --match-set ... src` matcher. It does not
require `xt_geoip`, xtables-addons, DKMS, kernel headers, or MOK enrollment.

## Verify an installation

Perform the first run in an existing SSH session and check the resulting rules:

```bash
sudo journalctl -u networkprotection.service -n 100 --no-pager
sudo iptables -L INPUT -n --line-numbers
sudo iptables -L NETWORKPROTECTION -n -v
sudo ip6tables -L INPUT -n --line-numbers
sudo ip6tables -L NETWORKPROTECTION -n -v
sudo systemctl list-timers networkprotection.timer
```

The jump marked `networkprotection: entry` should be at position 1. Whitelist
rules must appear before every Network Protection `DROP` rule.

## Build the Debian package locally

On Debian or Ubuntu:

```bash
sudo apt-get install -y dpkg-dev
./packaging/build-deb.sh
sudo apt-get install -y ./dist/networkprotection_$(cat VERSION)_all.deb
```

The build produces a versioned package and the stable
`dist/networkprotection_all.deb` artifact used by GitHub Actions and Releases.

## GitHub Actions and versioning

The project follows Semantic Versioning. `VERSION` is the single source of
truth, releases use tags such as `v1.0.0`, and user-visible changes are recorded
in `CHANGELOG.md`.

Release procedure:

1. update `VERSION` to `MAJOR.MINOR.PATCH`;
2. update `CHANGELOG.md`;
3. commit and push the change;
4. create and push the matching `vMAJOR.MINOR.PATCH` tag.

The GitHub Actions workflow runs on pushes to `main`, pull requests, version
tags, and manual dispatches. It runs ShellCheck, Python unit tests, mocked
firewall tests, builds the `.deb`, and verifies an upgrade-style installation.
A tag workflow fails when the Git tag and `VERSION` do not match.

Every workflow run uploads both package names as Actions artifacts. Matching
version tags additionally create a GitHub Release and upload the same files as
release assets; the stable release asset powers the installation one-liner:

```text
dist/networkprotection_1.0.0_all.deb
dist/networkprotection_all.deb
```

## Install from a source checkout

The legacy installer remains available for development or migration testing:

```bash
sudo ./install.sh
```

It preserves existing configuration, blacklist, and whitelist files. Production
systems should use the Debian package so future upgrades are tracked by `dpkg`.

## Run the test suite

```bash
python3 -m unittest discover -s tests -p 'test_*.py' -v
tests/test_geoip_to_cidrs.sh
tests/test_networkprotection_asndrop.sh
tests/test_networkprotection_whitelist.sh
```
