## Vultr provider for octoDNS

An [octoDNS](https://github.com/octodns/octodns/) provider that targets [Vultr](https://www.vultr.com/api/#tag/dns)'s DNS service.

### Installation

#### Command line

```
pip install octodns-vultr
```

#### requirements.txt/setup.py

Pinning specific versions or SHAs is recommended to avoid unplanned upgrades.

##### Versions

```
# Start with the latest versions and don't just copy what's here
octodns==0.9.14
octodns-vultr==0.0.1
```

##### SHAs

```
# Start with the latest/specific versions and don't just copy what's here
-e git+https://git@github.com/octodns/octodns.git@9da19749e28f68407a1c246dfdf65663cdc1c422#egg=octodns
-e git+https://git@github.com/octodns/octodns-vultr.git@ec9661f8b335241ae4746eea467a8509205e6a30#egg=octodns_vultr
```

### Configuration

```yaml
providers:
  vultr:
    class: octodns_vultr.VultrProvider
    # A Vultr API v2 personal access token with DNS access,
    # https://my.vultr.com/settings/#settingsapi
    token: env/VULTR_API_KEY
```

### Support Information

#### Records

VultrProvider supports A, AAAA, CAA, CNAME, MX, NS, SRV, SSHFP, and TXT records. PTR is not supported — Vultr's API doesn't offer it. Root/apex NS records are not supported either: Vultr's API rejects creating an NS record at a name that already has other record types, which the zone apex normally does, so root NS management is left alone.

TTLs are clamped to Vultr's supported range (60-172800 seconds) rather than rejected, with a warning logged (or an exception raised, if `strict_supports` is enabled) whenever that happens.

#### Dynamic

VultrProvider does not support dynamic records.

### Development

See the [/script/](/script/) directory for some tools to help with the development process. They generally follow the [Script to rule them all](https://github.com/github/scripts-to-rule-them-all) pattern. Most useful is `./script/bootstrap` which will create a venv and install both the runtime and development related requirements. It will also hook up a pre-commit hook that covers most of what's run by CI.
