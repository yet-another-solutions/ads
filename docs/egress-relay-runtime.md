# Private relay runtime component

`ads-ptp-relay` runs as a trusted ordinary container, separately from either
Kata VM. It creates only its own private network namespace, WireGuard interface,
VXLAN endpoint and unnumbered bridge. The node CNI subsequently contributes the
local VM veth. There is no mock endpoint, host filesystem/runtime-socket mount,
Kubernetes client, policy dispatcher, proxy or execution API.

## Configuration and authority

An immutable root-owned mode-0600 or mode-0400 configuration binds Pod UID,
attachment generation, sandbox UUID and guest/egress role to pair-local private
and tunnel addresses, exact peer public key, MTU, ports, VNI and packet budget.
Pod UID and generation must match injected trusted environment values.
Duplicate/unknown fields, invalid UUIDs, noncanonical/non-RFC1918 addresses,
overlapping topology, zero/noncanonical keys and unbounded rates are rejected.
The manager must provision these inputs and two distinct private keys for each
new generation; that manager integration is not implemented by this component.

The WireGuard private key is a separate protected file, never an argument,
environment value, diagnostic response or journal field. Use immutable
single-file mounts rather than writable/symlinked projected paths. Server TLS
certificate and key are separate from WireGuard and interception credentials.
TLS is loaded on the main thread before any network mutation.

Required trusted-container privileges are SYS_ADMIN for its private namespace
and child proc mount, NET_ADMIN for its network devices/rules, and NET_RAW for
bounded health probes. Rootfs can remain read-only; `/run` is private writable
Pod storage. No hostNetwork/hostPID, privileged mode, hostPath, API token or
shared host namespace is required. The real-kernel CI proof uses explicit
AppArmor/seccomp Unconfined profiles with only those capabilities; lab profile
compatibility must be proved separately, not silently broadened.

## Transport and filtering

WireGuard is created in the relay's ordinary CNI namespace, then moved to its
private namespace. Its UDP socket retains the CNI birthplace, while original
frames remain on the private bridge/VXLAN path
([WireGuard namespace integration](https://www.wireguard.com/netns/)).
The guest relay initiates to the injected numeric Service IPv4/port with a
25-second keepalive; the egress relay learns only the authenticated peer endpoint.
There is one peer, one exact tunnel /32 AllowedIPs and explicit peer route.

For the IPv4-only encapsulation contract, WireGuard MTU is transport MTU minus
60 and private MTU is transport MTU minus 110. The supplied transport MTU must
come from observed path MTU, not merely the NIC's nominal value. VXLAN remote,
VNI and destination port are fixed; dynamic remote learning is disabled, and
the sole flood destination is checked before setup completes.

Private IPv4 routing is disabled and IPv6 is disabled before link creation.
There is no default route, bridge address, bridge-to-CNI port, NAT or forwarding
fallback. Private local input/output admits only the exact WireGuard peer's
VXLAN and bounded ICMP health traffic. Bridge input/output drops local frames.
Bridge forwarding admits only the two intended ports, exact role MACs,
ARP for the pair endpoints, and IPv4 with a fixed guest source or guest
destination. Proxy reply source addresses remain intact. IPv6, VLAN and other
EtherTypes have no allowance. ARP is bounded to 20 packets/second with burst 40;
IPv4 has the configured per-direction packet budget and twice-rate burst.
These transport checks do not replace DNS/application authorization.

## Health and lifecycle

The only HTTP endpoint is TLS `/health`, returning empty 200 or 503. The
manager-controlled network policy must limit it to the paired IPC and required
kubelet probe path. At most four connections are processed concurrently, with
three-second socket/check deadlines and an absolute six-second connection
deadline covering TLS, headers and the check; slow headers cannot extend it.
Client input is not logged.

Health checks private namespace identity, bridge membership, link state, exact
local/peer keys and AllowedIPs, then sends a bounded ICMP probe over WireGuard.
The authenticated response proves the session remains usable after idle/rekey.
Health never modifies interfaces, routes, keys or peers. Socket startup is not
session health: `/health` is deliberately 503 before the peer is reachable.
Relays must have no WireGuard-dependent readiness or startup probe. Kubelet
liveness and IPC call the same health endpoint, with a bounded initial liveness
delay so Service bootstrap is not circular.

Setup writes nonsecret intent before effects and records namespace identities.
Cleanup validates the original namespace and creation group before destruction;
foreign/replaced or busy namespaces fail closed. Shutdown closes bounded HTTP
workers before removing the owned namespace. A stopped journal remains for
node/lifecycle observation. An existing state directory is not silently reused:
container/pair recovery must advance through manager-owned replacement, not
adopt stale private attachments or rotate credentials in place.

## Proof boundary

Unit tests cover rejected configuration, key handling, frame-filter generation,
bounded read-only health, real TLS responses and fail-fast TLS. The GitHub
kernel proof starts two real relay processes with isolated CNI/mount/private
namespaces, attaches native endpoint namespaces with the production CNI, and
checks session health, bidirectional private Ethernet, spoof rejection, no
transport bypass, wrong-key failure/recovery and peer shutdown/cleanup.

That fixture does not prove Kubernetes Service selection, node attestation,
Kata TAP/TC or inner Podman handoff, manager pair replacement, packet capture
absence under Cilium, policy enforcement or full application acceptance.
Those remain explicit live/integration gates, as does deployment of this runtime.
