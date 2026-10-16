# muse-bootstrap

One-line bootstrap that turns a Windows machine into a Muse outpost:
installs OpenSSH, generates the machine's own tunnel key on-box, enrolls
it with a one-time 6-character device code, and wires up the reverse
tunnel + Remote Desktop. The private key never leaves the machine.

**Run it** (admin PowerShell):

```
irm https://cdn.jsdelivr.net/gh/hookjk100/muse-bootstrap@main/bootstrap.ps1 | iex
```

Landing page: https://muse.naowall.com

Public by design — this repo contains no secrets, only a public key and
addresses. Machine credentials are created locally on each machine.
