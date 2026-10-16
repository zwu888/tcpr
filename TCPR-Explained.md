---
title: TCPR — TCP Recovery Explained
tags:
  - networking
  - tcp
  - linux-kernel
  - netfilter
  - fault-tolerance
  - research
created: 2026-10-16
source: Cornell TCPR project
aliases:
  - TCPR
  - TCP Recovery
---

# TCPR — TCP Recovery

> [!abstract] One-sentence summary
> TCPR keeps a long-lived TCP connection alive while **one endpoint's application process crashes and restarts**, without the *peer* ever noticing or needing any modification. It does this with a tiny crash-survivable checkpoint + a sequence-number `delta` + a middlebox that fabricates handshake/ack/reset packets.

## Table of Contents
- [[#The Big Picture]]
- [[#Code Layout]]
- [[#1. The Recovery Mechanism (the core trick)]]
- [[#2. Connection Teardown — fin, checkpoint, and done]]
- [[#3. Kernel Dispatch Path]]
- [[#4. Userspace Control Protocol & Demo]]
- [[#5. Ideal Use Cases]]
- [[#6. Known Bugs / Rough Edges]]
- [[#7. Building Non-Trivial Demos]]
- [[#Appendix A — File-by-File Code Deep Dive]]
- [[#Glossary]]

---

## The Big Picture

Normally, if a server process dies, the kernel's TCP state is lost and the connection breaks (RST). TCPR puts a small "proxy" on a separate box (a gateway/bridge/middlebox) that keeps just enough extra state so that after the application restarts, the connection can be silently re-established with the peer none the wiser.

```
  peer  <------ TCP ------>  [ TCPR middlebox ]  <------ TCP ------>  application
                             (kernel module +                        (the recoverable
                              userspace tools)                         endpoint)
```

### Architecture

```mermaid
flowchart LR
    subgraph PEER["Peer host (unmodified)"]
        P["Peer app<br/>sees a stable,<br/>never-broken TCP conn"]
    end

    subgraph MB["TCPR middlebox (in-path)"]
        direction TB
        KM["Kernel module<br/>(xtables TCPR target)"]
        FL["filter.c logic<br/>delta · checkpoint · synth packets"]
        ST[("Per-connection state<br/>tcpr_ip4 list<br/>keyed by 5-tuple + netns")]
        TOOLS["Userspace tools<br/>get | ack | done | put ...<br/>(UDP control protocol)"]
        KM --> FL
        FL --> ST
        TOOLS -. "UDP tcpr_ip4" .-> KM
    end

    subgraph APP["Application host (recoverable)"]
        A["App process<br/>may crash & restart"]
    end

    P <-- "TCP (peer seq space)" --> KM
    KM <-- "TCP (app seq space)" --> A

    classDef store fill:#f4f4f4,stroke:#888,stroke-dasharray:4 3;
    class ST store;
```

TCPR sits in the network path. It rewrites sequence numbers, ports, and addresses in both directions, and remembers what the application has durably acknowledged. When the app crashes and comes back, TCPR fabricates a SYN/ACK handshake with the restarted app, replays the right numbers, and the peer's connection continues uninterrupted.

> [!tip] The key idea in one sentence
> TCPR keeps a **"hard" checkpoint** of how far the peer's data has been acknowledged plus the peer's handshake options, and maintains a **sequence-number `delta`** between the app's pre-crash and post-crash connections — so when the app restarts, TCPR can replay a handshake and seamlessly splice the new app-side connection onto the peer's still-open connection.

---

## Code Layout

### `include/tcpr/` — shared headers (kernel + userspace via `#ifdef __KERNEL__`)

- **`types.h`** — core state structures:
  - `struct tcpr_hard` — the **"hard"** state that must survive a crash (ports, peer's MSS/window-scale/SACK options, the checkpointed ACK, done-reading/writing flags).
  - `struct tcpr` — full per-connection state: sequence `delta`, current ack/seq/fin/window, peer's ack/fin/window, status flags (`done`, `failed`, `syn_sent`).
  - `struct tcpr_ip4` — adds IPv4 addresses on top of `tcpr`; this is the unit exchanged with userspace tools.
- **`filter.h`** — the filtering API and the verdict enum (`DROP`, `DELIVER`, `ACKNOWLEDGE`, `RECOVER`, `RESET`).
- **`util.h`** — userspace helper prototypes.

### `module/` — kernel side (an iptables/xtables target called `TCPR`)

- **`filter.c`** — the **heart of the algorithm**, pure logic (compiles in kernel and userspace):
  - `tcpr_filter()` — packets from the **application** → peer.
  - `tcpr_filter_peer()` — packets from the **peer** → application.
  - `tcpr_update()` — merge externally-supplied state into a connection.
  - `tcpr_acknowledge()` / `tcpr_recover()` / `tcpr_reset()` — **synthesize** TCP packets.
  - `shorten()` — incremental one's-complement checksum fixups.
- **`module.c`** — Linux kernel glue. Registers an xtables target on `LOCAL_IN`/`LOCAL_OUT`, keeps a linked list of `connection` structs keyed by 5-tuple + network namespace, dispatches packets.
- **`libxt_TCPR.c`** — userspace iptables plugin so you can write `iptables ... -j TCPR --addr 192.0.2.1`.

### `src/` — userspace command-line tools (Unix filters over binary `tcpr_ip4` records)

| Tool | Role |
|------|------|
| `get SRCPORT [HOST PORT]` | fetch state from module → stdout |
| `put` | stdin → write state to module |
| `print` | pretty-print records (human readable) |
| `ack [N]` | advance `hard.ack` by N bytes (or all) |
| `done [rw]` | set done_reading/writing, or force `done` |
| `bind HOST PORT` | set the app's internal address/port |
| `kill` | set `failed = 1` |
| `util.c` | shared helpers (`resolve_address`, `connect_to_tcpr`, `get_tcpr_state`) |
| `chat.c`, `bridge.c`, `benchmark.c` | larger demo/test apps (`tcpr-chat` used in examples) |

### `examples/` — shell scripts using Linux network namespaces + a bridge
- `recover/` — simplest demo: failure and in-place recovery.
- `migrate/` — advanced demo: live migration to a replica.

### Build system
GNU autotools (`configure.ac`, `Makefile.am`) build the userspace tools and the xtables library; the kernel module is built separately with the kernel build system (`module/Makefile`).

---

## 1. The Recovery Mechanism (the core trick)

### The central problem
A TCP connection is identified by `(src IP, src port, dst IP, dst port)` and kept alive by two monotonically increasing sequence spaces. When the app crashes:
- The **peer** still thinks the connection is alive and keeps its sequence numbers.
- The **restarted app** opens a *brand new* socket with a random, unrelated ISN.

Letting the new SYN through would make the peer reject it (RST). TCPR must **bridge the two sequence-number spaces** so neither side notices.

### 1.1 The `delta`
`delta` is the offset between the application's sequence space and the peer's sequence space (app → peer). In normal operation `delta = 0`. Every app→peer packet is rewritten in `tcpr_filter`:

```c
// filter.c:101-103
check += shorten(~h->seq);
h->seq = htonl(ntohl(h->seq) - t->delta);   // subtract delta
check += shorten(h->seq);
```

The peer only ever sees `app_seq - delta`. Acks returning from the peer get `delta` **added** so the app sees them in its own space:

```c
// filter.c:193-195 (tcpr_filter_peer)
h->ack_seq = htonl(ntohl(h->ack_seq) + t->delta);
```

So the whole scheme reduces to: **when the app restarts, compute the `delta` that lines the new connection up with where the peer is, then fix up every packet from then on.**

```mermaid
flowchart LR
    subgraph APPSP["App sequence space"]
        AS["app_seq = S"]
        AA["app sees ack = A"]
    end

    subgraph XLATE["TCPR translation"]
        direction TB
        D1["data app → peer:<br/><b>seq = S − delta</b>"]
        D2["ack peer → app:<br/><b>ack = A + delta</b>"]
        CL["ack app → peer:<br/><b>clamped to hard.ack</b>"]
    end

    subgraph PEERSP["Peer sequence space"]
        PS["peer sees seq = S − delta"]
        PA["peer_ack / peer_fin"]
    end

    AS -->|subtract delta| D1 --> PS
    PA -->|add delta| D2 --> AA
    AA -. "outgoing ack" .-> CL --> PA

    NOTE["On recovery:<br/>delta = new_app_seq − peer.ack<br/>⇒ (S − delta) stays continuous<br/>for the peer across the crash"]
    XLATE -.-> NOTE

    classDef note fill:#fff8e1,stroke:#e0b000;
    class NOTE note;
```

### 1.2 Detecting a restart & computing `delta`
A restarted app sends a fresh **SYN** (`ack=0`). That's the trigger:

```c
// filter.c:62-78
if (!h->ack) {                  // SYN (no ACK bit)
    t->syn_sent = 1;
    if (t->peer.have_ack) {     // we already have an ESTABLISHED peer
        t->delta = ntohl(t->seq) - ntohl(t->peer.ack);  // <-- THE delta
        t->hard.done_writing = 0;
        t->have_fin = 0;
        return TCPR_RECOVER;    // RECOVERY, not a fresh connection
    } else {                    // brand-new connection, first time
        t->port = h->source;
        if (!t->hard.port) t->hard.port = h->source;
        t->hard.peer.port = h->dest;
        if (h->check) h->check = ~shorten(shorten(check));
        return TCPR_DELIVER;    // pass SYN through normally
    }
}
```

- `peer.have_ack == 0` → genuine first-time connection → `TCPR_DELIVER`.
- `peer.have_ack == 1` → a live peer that's been acking → a new SYN can only mean **crash + restart** → recovery.

`delta = new_app_seq − peer_expected_seq`, so afterwards `new_app_seq − delta == peer_expected_seq`. The peer never sees a gap.

### 1.3 Synthesizing the handshake — `tcpr_recover`
The new app waits for a SYN/ACK the real peer won't send, so TCPR fabricates it:

```c
// filter.c:246-282 (abridged)
void tcpr_recover(struct tcphdr *h, struct tcpr *t) {
    memset(h, 0, sizeof(*h));
    h->source  = t->hard.peer.port;              // pretend from the peer
    h->dest    = t->port;                         // to the app
    h->seq     = htonl(ntohl(t->hard.ack) - 1);   // peer's seq, -1 for SYN
    h->ack_seq = t->seq;                          // ack app's new ISN+1
    h->syn = 1; h->ack = 1; h->window = t->peer.win;
    // Replay the peer's ORIGINAL handshake options (saved in hard.peer):
    //   MSS, window scale, SACK-permitted
}
```

> [!important] Why options are saved
> `tcpr_filter_peer` recorded the peer's MSS/WS/SACK during the original handshake into `hard.peer` (crash-survivable). On recovery they're replayed so the restarted app negotiates an identical connection — otherwise the sequence arithmetic would corrupt.

### 1.4 How the kernel emits these packets
`filter.c` only fills in a `tcphdr`; `module.c` wraps it in IP and sends it:

```c
// module.c:174-220 (inject_tcp, abridged)
case TCPR_RECOVER:
    tcpr_recover(&packet.tcp, &c->state.tcpr);
    packet.ip.saddr = c->state.peer_address;  // looks like it's from the peer
    packet.ip.daddr = c->state.address;        // to the application
```

```c
// module.c:337-344 (dispatch)
tcpr_verdict = tcpr_filter(&c->state.tcpr, tcp, ...);
if (tcpr_verdict == TCPR_DELIVER) {
    fix_checksums(ip, tcp, ip->saddr, c->address);
    ip->saddr = c->address; verdict = NF_ACCEPT;   // mutate in place
} else if (tcpr_verdict != TCPR_DROP) {
    inject_tcp(c, tcpr_verdict, skb);              // RECOVER/RESET/ACKNOWLEDGE
}
```

- `TCPR_DELIVER` → mutate the real packet and `NF_ACCEPT`.
- `TCPR_RECOVER`/`RESET`/`ACKNOWLEDGE` → drop original, inject a synthesized packet.

### 1.5 The crash-surviving checkpoint — `hard.ack`
```c
struct tcpr_hard {
    uint16_t port;
    struct { uint16_t port, mss; uint8_t ws, sack_permitted; } peer;
    uint32_t ack;                 // CHECKPOINT: next byte expected from peer
    uint8_t done_reading, done_writing;
};
```

`hard.ack` may only advance once the app has **durably consumed** the peer's data. Otherwise, after a crash, recovery would tell the peer "I already got X..Y" that the app never processed → data lost.

TCPR clamps the app's outgoing acks to `hard.ack`:

```c
// filter.c:93-99
} else if (h->ack_seq != t->hard.ack) {
    if (size == (size_t)h->doff * 4) return TCPR_DROP;   // pure ack → suppress
    h->ack_seq = t->hard.ack;                            // clamp ack to checkpoint
}
```

The peer is told "I've got up to `hard.ack`" and no further, so it **retains** anything past the checkpoint and **retransmits** after recovery → the no-data-loss invariant.

### Full recovery sequence
1. **Normal:** `delta = 0`; filters pass packets, clamp acks to `hard.ack`, save peer options.
2. **Crash:** app dies; peer keeps buffering unacked data.
3. **Restart:** app sends fresh SYN.
4. **Detection:** `tcpr_filter` sees SYN + `peer.have_ack` → computes `delta` → `TCPR_RECOVER`.
5. **Fabricated handshake:** `tcpr_recover` builds SYN/ACK; module injects it; app reaches ESTABLISHED.
6. **Resume:** peer retransmits past `hard.ack`; `delta` translates everything. Neither stack learns a crash happened.

```mermaid
sequenceDiagram
    autonumber
    participant P as Peer
    participant T as TCPR middlebox
    participant A as Application

    Note over P,A: Normal operation (delta = 0)
    A->>T: data (seq = S)
    T->>P: data (seq = S - delta)
    P->>T: ack, saves MSS/WS/SACK in hard.peer
    T-->>A: ack (clamped to hard.ack)
    Note right of T: hard.ack only advances once<br/>app durably consumes data

    rect rgb(255, 235, 235)
    Note over A: CRASH
    A--xA: process dies, socket state lost
    Note over P: Peer unaffected,<br/>keeps buffering data past hard.ack
    end

    rect rgb(235, 245, 255)
    Note over A: RESTART (same 4-tuple)
    A->>T: SYN (fresh random ISN)
    Note right of T: peer.have_ack == 1<br/>delta = new_app_seq - peer.ack<br/>verdict = TCPR_RECOVER
    T-->>A: synthesized SYN/ACK<br/>(replays peer's saved options)
    A->>T: ACK  (now ESTABLISHED)
    end

    Note over P,A: Resume - peer never noticed
    P->>T: retransmit data past hard.ack
    T->>A: data (+ delta applied)
    A->>T: new data (seq = S')
    T->>P: data (seq = S' - delta)
```

---

## 2. Connection Teardown — fin, checkpoint, and done

Relevant state:
```c
uint32_t fin;        // seq of OUR fin (app→peer), in peer space
uint8_t  have_fin;
struct { uint32_t ack, fin; uint16_t win; uint8_t have_fin, have_ack; } peer;
uint8_t done;        // fully closed, safe to free
```

### App sends a FIN
```c
// filter.c:55-60
if (h->fin) {
    t->fin = htonl(ntohl(t->seq) + 1 - t->delta);  // our FIN seq, in peer space
    t->have_fin = 1;
    if (!t->hard.done_writing) t->failed = 1;       // FIN without being "done writing" = failure
}
```

### Peer sends a FIN
```c
// filter.c:174-177
if (h->fin) {
    t->peer.fin = htonl(ntohl(h->seq) + (h->syn?1:0) + 1 + size - h->doff*4);
    t->peer.have_fin = 1;
}
```

### The `done` condition (appears in 3 places)
```c
// filter.c:90-92 (and 183, and 231-233)
if (t->have_fin && t->peer.have_fin && t->peer.have_ack
    && t->peer.ack == t->fin        // peer acked OUR fin
    && t->peer.fin == t->hard.ack)  // we acked (to checkpoint) the PEER's fin
    t->done = 1;
```

> [!note] Why `hard.ack` (not live `ack`)
> `done` can't be set until the app has **durably** processed everything — same no-data-loss invariant. `tcpr_acknowledge` recomputes `done` after advancing `hard.ack`, since that may be the final event completing the close.

### What `done` triggers
```c
// module.c:345-349 (and 406-410, 296-297)
if (c->state.tcpr.done) { connection_done(c); }  // unlink + kfree
```

Orderly shutdown: tell TCPR "done writing" (so its FIN is clean, not failure) → FIN exchange completes → `done` flips once both sides' data is fully acked **and** checkpointed.

### Connection lifecycle

```mermaid
stateDiagram-v2
    [*] --> New: first SYN<br/>(connection_create)
    New --> Established: peer.have_ack set
    Established --> Established: data + clamped acks<br/>advance hard.ack

    Established --> Recovering: app SYN seen<br/>& peer.have_ack<br/>(delta computed)
    Recovering --> Established: synth SYN/ACK<br/>app re-established

    Established --> Closing: FIN exchange<br/>(done_writing set)
    Closing --> Done: have_fin & peer.have_fin<br/>& peer.ack==fin<br/>& peer.fin==hard.ack
    Done --> [*]: connection_done()

    Established --> Failed: RST seen, or FIN<br/>without done_writing,<br/>or kill tool
    Recovering --> Failed: RST during recovery
    Failed --> [*]: TCPR_RESET<br/>then freed
```

---

## 3. Kernel Dispatch Path

### Entry point
```c
// module.c:415-434
static unsigned int tcpr_tg(struct sk_buff *skb, const struct xt_action_param *par) {
    const uint32_t *address = par->targinfo;      // the --addr value, or 0
    struct net *net_ns = dev_net(skb->dev);
    if (!net_ns) net_ns = current->nsproxy->net_ns;
    if (!skb_try_make_writable(skb, skb->len)) return NF_DROP;
    if (*address) return tcpr_tg_application(skb, *address, net_ns);  // app side
    else          return tcpr_tg_peer(skb, net_ns);                   // peer side
}
```

The **`--addr` argument is the switch** (see `setup-tcpr`): the app-direction rule carries `--addr 192.0.2.1`; the peer-direction rule has none (`*address == 0`). The app rule matches **TCP and UDP** (UDP = the control protocol).

### Connection identity
Keyed by 5-tuple **plus network namespace**. Two lookups because a connection has two faces:
- `lookup_internal(...)` — matches on the app's **real** internal address/port.
- `lookup_external(...)` — matches on the **translated/stable** address/port the peer sees.

TCPR is doing NAT-like translation, so the same connection is found by different keys per direction.

### Three paths
1. **App → peer** (`tcpr_tg_application`): non-TCP → `tcpr_tg_update`; else `lookup_internal`, create on first SYN, run `tcpr_filter`, SNAT `ip->saddr` → stable addr on DELIVER.
2. **Peer → app** (`tcpr_tg_peer`): `lookup_external`; a `lookup_external(0, 0, ...)` template entry implements **listening sockets** (peer-initiated connections); run `tcpr_filter_peer`, DNAT `ip->daddr` → app's real addr, **re-inject via `inject_ip`** (always returns NF_DROP for original).
3. **Control** (`tcpr_tg_update`): UDP payload is a `tcpr_ip4`; find/create connection, run `tcpr_update`, reply with state or inject synthesized TCP.

```mermaid
flowchart TD
    START([skb enters TCPR target<br/>tcpr_tg]) --> ADDR{--addr set?<br/>*address != 0}

    ADDR -- "yes (app side)" --> PROTO{protocol?}
    ADDR -- "no (peer side)" --> PEER["tcpr_tg_peer<br/>lookup_external"]

    PROTO -- TCP --> APP["tcpr_tg_application<br/>lookup_internal"]
    PROTO -- UDP --> UPD["tcpr_tg_update<br/>parse tcpr_ip4"]

    APP --> AF["tcpr_filter()"]
    PEER --> PF["tcpr_filter_peer()"]
    UPD --> UF["tcpr_update()"]

    AF --> V{verdict}
    PF --> V
    UF --> V

    V -- DELIVER --> DLV["fix checksums + NAT addr<br/>NF_ACCEPT / re-inject"]
    V -- DROP --> DRP["NF_DROP"]
    V -- "RECOVER / RESET / ACKNOWLEDGE" --> INJ["inject_tcp()<br/>synthesize new packet"]

    DLV --> DONE{tcpr.done?}
    INJ --> DONE
    DONE -- yes --> FREE["connection_done()<br/>unlink + kfree"]
    DONE -- no --> OUT([return verdict])
    FREE --> OUT
    DRP --> OUT
```

---

## 4. Userspace Control Protocol & Demo

### Wire protocol — `tcpr_ip4` over UDP, request/reply
```c
// util.c connect_to_tcpr(): TCPR_HOST / TCPR_PORT env vars, SOCK_DGRAM
// util.c get_tcpr_state(): fill identifying fields, send, recv full state
```

```c
// filter.c:204-211 tcpr_update()
if (!u->port) {                  // empty port → it's a GET
    memcpy(u, t, sizeof(*u));     // return current state
    return TCPR_DELIVER;
}
// otherwise PUT: merge caller's hard state in
memcpy(&t->hard, &u->hard, sizeof(t->hard));
t->port = u->port; t->done = u->done; t->failed = u->failed;
```

### Tools compose with pipes (binary `tcpr_ip4` records)
```sh
tcpr-get 8888 | tcpr-print               # inspect a connection
tcpr-get 8888 | tcpr-ack | tcpr-put      # checkpoint all received data
tcpr-get 8888 | tcpr-kill | tcpr-put     # force a reset
tcpr-get 8888 | tcpr-done w | tcpr-put   # mark done writing before clean close
```

The `get | transform | put` pattern is the whole management model. `print` taps anywhere for debugging.

```mermaid
sequenceDiagram
    autonumber
    participant SH as Shell pipeline
    participant G as tcpr-get
    participant X as tcpr-ack / done / kill / bind
    participant PU as tcpr-put
    participant K as Kernel module

    Note over SH: tcpr-get 8888 | tcpr-ack | tcpr-put
    SH->>G: run with SRCPORT (+ optional HOST PORT)
    G->>K: UDP tcpr_ip4 (port == 0 ⇒ GET)
    K-->>G: tcpr_ip4 filled with live state
    G->>X: binary record on stdout → stdin
    Note right of X: mutate in memory only<br/>(advance hard.ack, set flags, ...)
    X->>PU: transformed binary record
    PU->>K: UDP tcpr_ip4 (port != 0 ⇒ PUT)
    Note right of K: tcpr_update() merges hard state,<br/>may emit ACK / RESET packet
```

### The demo (`examples/recover`)
```sh
# ./setup-network      # netns for peer + app, a bridge between them
# ./setup-tcpr         # modprobe tcpr; install iptables TCPR rules
                       # ./peer          (start the other endpoint)
# ./application        # start tcpr-chat in the app netns
    ... type back and forth ...   # normal TCP, delta = 0
^C                                 # KILL the app → simulated crash
# ./recover            # restart tcpr-chat with the SAME addrs
    ... more typing ...            # connection resumes! peer never noticed
^D                ^D               # clean close from both ends
# ./teardown-tcpr
# ./teardown-network
```

`application`/`recover` run the same command:
```sh
ip netns exec application tcpr-chat -b 192.0.2.1:8888 -c 192.0.2.2:9999 -t 192.0.2.2:7777 -v
# -b bind  -c connect-to-peer  -t TCPR control endpoint  -v verbose
```
Because `recover` reuses the identical 4-tuple, the new SYN hits the **existing** connection entry (`peer.have_ack` set) → `delta` computed → `TCPR_RECOVER` → fabricated SYN/ACK → session continues.

---

## 5. Ideal Use Cases

> [!success] Fits when all three hold
> 1. The connection is **long-lived** (reconnection cost matters).
> 2. You **can't change the peer** (or don't want to).
> 3. The recovering app can **rebuild its application state** from somewhere (TCPR recovers the *wire* connection, not your app's memory).

**Good fits**
1. **Transparent server failover/restart** — thousands of unmodified clients (browsers, appliances, IoT) stay connected across a crash/deploy.
2. **Long-lived, hard-to-reestablish connections** — DB replication, message brokers, log shippers, market-data feeds, streaming/telemetry, anything behind an expensive handshake (TLS/auth).
3. **Zero-downtime maintenance/upgrades** — restart/patch the app while connections ride through; extends to **live migration to a replica** (`examples/migrate`).
4. **Replicated / BFT services** (its research origin) — small externalizable stable state lets a replica take over a connection.
5. **Protecting unmodifiable or legacy clients** — peer needs no library/kernel/awareness.

> [!failure] Wrong tool when
> - You control **both** endpoints → use app-level reconnect, QUIC, or a resumable protocol.
> - **Short-lived** connections (typical HTTP) → just reconnect.
> - You expect **app memory** to be recovered automatically → TCPR does not checkpoint app state.
> - The checkpoint can't keep up / correctness is subtle → advancing `hard.ack` too early loses data, too late costs latency/memory.
> - **Modern encrypted transports** → QUIC is UDP; TCPR is a plain-TCP header-rewrite mechanism.

### Deployment reality check
- Needs an in-path **middlebox** running a custom kernel module + iptables target.
- That box holds the crash-survivable state → must itself be reliable (replicate/HA it).
- Per-packet rewrite cost + operational complexity, tied to Linux netfilter/xtables internals.

> [!quote] Honest framing
> TCPR is a clever **research system** for *transparent* TCP connection recovery. In 2026, if you're greenfield and control both ends, **QUIC connection migration** or an app-level resumable protocol solves much of the same problem more cleanly. TCPR's enduring niche is exactly what those can't touch — **unmodifiable peers and legacy TCP services that must survive endpoint failure.**

---

## 6. Known Bugs / Rough Edges

> [!warning] Latent issues spotted in the code
> - **`inject_ip` (module.c:136-153):** uses `skb` (`skb_reserve`) and `dev_net(oldskb->dev)` **before** `skb = alloc_skb(...)`. Lines 139-140 run against an uninitialized `skb`; duplicated `skb_reserve` looks like a bad patch/merge artifact. Correct order: compute `net`, `alloc_skb`, then `skb_reserve`.
> - **Use-after-free race:** `connection_done` frees the `connection` while code still holds `c->tcpr_lock`, which lives *inside* the freed struct (`/* XXX race */` comments at module.c:301, 350, 411).
> - **Peer path never uses `NF_ACCEPT`:** `tcpr_tg_peer` relies on drop-original + `inject_ip` copy; the default `verdict = NF_DROP` is never overwritten.
> - **Kernel-API churn:** hand-patched "Fix" comments around `ip_local_out` and namespace handling indicate sensitivity to kernel version.

---

## 7. Building Non-Trivial Demos

### 7.1 The mental model (what a demo must respect)

> [!important] TCPR recovers the **pipe**, not your **app's memory**
> TCPR restores the TCP connection and makes the peer retransmit everything past `hard.ack`. But the recovering process must know **where to resume**. `tcpr-chat` re-reads stdin from the *start* on restart, so a naïve `tcpr-chat < bigfile` + crash + rerun will **replay the file from byte 0** — the connection survives but the app state didn't.

A compelling demo therefore needs one of:
1. An app that **persists its own position** alongside the TCPR checkpoint — exactly what `tcpr-bridge` ([[#A.6 `src/bridge.c` — a *recoverable* two-client bridge]]) does via an `mmap`'d state file, **or**
2. A workload where "resume from scratch" is fine (a generator/benchmark, `tcpr-chat -g`), **or**
3. Protecting a **different component's** crash than the one producing the data.

The existing `examples/recover/setup-network` (two netns — `application`, `peer` — over a bridge, with the TCPR module on the host) is the right sandbox for all of these.

**Division of responsibility on crash:**

```mermaid
flowchart TB
    CRASH([Application process crashes]):::bad

    CRASH --> R["✅ TCPR restores automatically"]:::tcpr
    CRASH --> L["❌ Lost — app must handle"]:::app

    R --> R1["TCP connection (4-tuple)"]
    R --> R2["Sequence spaces via delta"]
    R --> R3["Peer's buffered data<br/>(retransmitted past hard.ack)"]
    R --> R4["Negotiated options<br/>MSS / WS / SACK"]

    L --> L1["App memory & variables"]
    L --> L2["Position in the stream<br/>(e.g. file offset)"]
    L --> L3["Un-flushed app buffers"]

    L --> FIX{{"Demo must bridge this gap"}}:::fix
    FIX --> F1["Persist position<br/>(tcpr-bridge mmap state)"]
    FIX --> F2["Resume-from-scratch OK<br/>(tcpr-chat -g generator)"]
    FIX --> F3["Crash a different component<br/>than the data source"]

    classDef bad fill:#ffe0e0,stroke:#c33;
    classDef tcpr fill:#e0f7e9,stroke:#2a7;
    classDef app fill:#fff4e0,stroke:#d90;
    classDef fix fill:#e8eeff,stroke:#46c;
```

### 7.2 Demo topology

```mermaid
flowchart LR
    subgraph HOST["Host (TCPR module loaded)"]
        subgraph APPNS["netns: application (192.0.2.1)"]
            APP["protected app<br/>tcpr-bridge / tcpr-chat"]
        end
        BR{{"bridge 'tcpr' 192.0.2.3<br/>iptables -j TCPR"}}
        subgraph PEERNS["netns: peer (192.0.2.2)"]
            P1["client / peer<br/>(nc, tcpr-chat)"]
        end
        APP <--> BR <--> P1
    end
    CTRL["control: TCPR_HOST=192.0.2.2 PORT=7777<br/>tcpr-get | ack | put | print"]
    CTRL -. "UDP intercepted by<br/>--physdev-in application -p udp" .-> BR
```

### 7.3 Demo 1 — Crash-proof relay with end-to-end integrity check *(recommended)*

The demo `bridge.c` was built for: a stateful relay crashes mid-transfer and both **unmodified `nc`** clients survive; a checksum proves no byte was lost.

**Network topology** (what `examples/relay/setup-network` + `setup-tcpr` build):

```mermaid
flowchart TB
    subgraph PEERNS["netns: peer — 192.0.2.2"]
        SND["nc sender<br/>&lt; /tmp/in.dat"]
        RCV["nc receiver<br/>&gt; /tmp/out.dat"]
        PE["eth0 (veth)"]
        SND --- PE
        RCV --- PE
    end

    subgraph HOST["host network namespace (TCPR module loaded)"]
        PVE["peereth (veth)"]
        BR{{"bridge: tcpr<br/>192.0.2.3/24"}}
        AVE["applicationeth (veth)"]
        IPT["iptables -t mangle FORWARD<br/>--physdev-in application → TCPR --addr 192.0.2.1<br/>--physdev-out application → TCPR"]
        PVE --- BR
        AVE --- BR
        BR -. "bridged FORWARD packets<br/>pass through TCPR target" .- IPT
    end

    subgraph APPNS["netns: application — 192.0.2.1"]
        AE["eth0 (veth)"]
        BRG["tcpr-bridge :8888<br/>state → /var/tmp/tcpr-bridge-*.state"]
        AE --- BRG
    end

    PE === PVE
    AE === AVE

    CTRL["control plane:<br/>TCPR_HOST=192.0.2.2 PORT=7777<br/>tcpr-get | ack | put | print"]
    CTRL -. "UDP, intercepted by the<br/>--physdev-in application -p udp rule" .-> IPT

    classDef svc fill:#eef7ff,stroke:#3a7;
    classDef net fill:#f7f7f7,stroke:#999;
    class BRG,SND,RCV svc;
    class BR,PVE,AVE,AE,PE net;
```

> [!note] How the control packets reach the module
> `tcpr-bridge` sends UDP to `192.0.2.2:7777`. That address just needs to **route out through the bridge** so the `--physdev-in application -p udp -j TCPR` rule catches it — the module intercepts the UDP, reads/merges the `tcpr_ip4`, and replies. The port/host are otherwise arbitrary.

```sh
# host
cd examples/recover && sudo ./setup-network && sudo ./setup-tcpr
head -c 200M /dev/urandom > /tmp/in.dat && sha256sum /tmp/in.dat

# the recoverable relay (application netns)
sudo ip netns exec application tcpr-bridge -b 192.0.2.1:8888 -t 192.0.2.2:7777

# receiver + sender clients (peer netns)
sudo ip netns exec peer sh -c 'nc 192.0.2.1 8888 > /tmp/out.dat'
sudo ip netns exec peer sh -c 'nc 192.0.2.1 8888 < /tmp/in.dat'

# ---- MID-TRANSFER: ^C the relay, then rerun the SAME command ----
sudo ip netns exec application tcpr-bridge -b 192.0.2.1:8888 -t 192.0.2.2:7777
#   -> sees /var/tmp/tcpr-bridge-*.state, recovering=1, re-binds + reconnects,
#      TCPR splices the connections back on, relaying continues.

sha256sum /tmp/out.dat   # MUST match /tmp/in.dat
```
Demonstrates **server restart transparent to unmodified clients** + the **no-data-loss invariant** (`bridge.c` advances `hard.ack` only after relaying each chunk, so the peer retransmits anything the crashed relay hadn't forwarded).

### 7.4 Demo 2 — Bulk throughput with mid-stream failover *(quantified)*

`tcpr-chat` has a load generator (`-g BYTES`), a sink (`-d`), and stats (`-v`).

```sh
# peer: sink + report
sudo ip netns exec peer tcpr-chat -b 192.0.2.2:9999 -d -v
# application: generate 1 GiB through TCPR, with checkpointing
sudo ip netns exec application tcpr-chat -b 192.0.2.1:8888 -c 192.0.2.2:9999 \
     -t 192.0.2.2:7777 -g 1073741824 -v
# ^C partway, then rerun to resume the stream
```
Add realism with `tc netem` on the bridge (`tc qdisc add dev tcpr root netem delay 20ms`) and compare Mbps before/after recovery. The repo's `netperf-2.4.5-tcpr.patch` lets you run a standard `TCP_STREAM`/`TCP_RR` benchmark through TCPR for **publication-style numbers**.

### 7.5 Demo 3 — Live migration to a replica *(extend `examples/migrate`)*

`examples/migrate` already migrates a connection between two application replicas via Open vSwitch + `tcpr-control` (`-s` save / `-r` restore + flow-table rewrite). Non-trivial extensions:
- Migrate **under active load** (combine with Demo 2) → zero connection drop.
- Chain `app1 → app2 → app1` to show repeatability.
- Kill `tcpr1` (the gateway's TCPR instance) to demonstrate the **middlebox-is-the-SPOF** failure mode (motivates HA'ing the TCPR box).

### 7.6 Demo 4 — Front an unmodified real service

Put a real server (echo/HTTP/Redis) in `application` and a real client in `peer`. Since the server doesn't speak the control protocol, use `tcpr-chat -C` (bypass checkpointing) as a shim, or drive checkpoints externally:

```sh
# advance the checkpoint for a live connection on port 8888:
TCPR_HOST=192.0.2.2 TCPR_PORT=7777 sh -c 'tcpr-get 8888 | tcpr-ack | tcpr-put'
# inspect state live:
TCPR_HOST=192.0.2.2 TCPR_PORT=7777 sh -c 'tcpr-get 8888 | tcpr-print'
```
> [!warning] Honest caveat
> Without app-integrated checkpointing you survive the *connection* but not the *application state* — best for stateless/idempotent services.

### 7.7 Making it "demo-grade"

- **Visual proof:** side pane running `watch -n0.5 'TCPR_HOST=192.0.2.2 TCPR_PORT=7777 sh -c "tcpr-get 8888 | tcpr-print"'` so the audience *sees* `delta`, `hard.ack`, and the `failed`/`done` flags flip at crash/recovery.
- **Packet proof:** `sudo ip netns exec peer tcpdump -ni eth0 tcp` shows the peer never sees a RST or re-handshake — just a brief pause then continued flow.
- **Automate it:** wrap each as `setup / run / fault / recover / verify / teardown` scripts mirroring `examples/*`, with `verify` = the sha256 compare.

> [!tip] Quick-start checklist
> 1. `apt-get install autoconf libtool iptables-dev` → `autoreconf -i` → build userspace + xtables lib.
> 2. Build + `insmod`/`modprobe tcpr`; confirm with `modinfo tcpr`.
> 3. `./setup-network && ./setup-tcpr` (from `examples/recover`).
> 4. Run a demo above; watch state with `tcpr-get | tcpr-print`.
> 5. `./teardown-tcpr && ./teardown-network` to clean up.

---

## Appendix A — File-by-File Code Deep Dive

> [!info] Scope
> Sections 1–4 explain the *concepts*. This appendix walks every source file **function by function** with the exact behavior and gotchas, so you can read the tree top to bottom.

### A.1 `module/filter.c` — the portable core logic

Compiles both in-kernel and in userspace (no kernel-only calls), so the same algorithm is testable off-target.

**`shorten(uint32_t n)`** (lines 10-13)
```c
return (n >> 16) + (n & 0xffff);
```
Folds a 32-bit accumulator into 16 bits for **incremental one's-complement checksum** updates. Used everywhere a header field is rewritten so the TCP/IP checksum can be patched instead of recomputed from scratch. The idiom `h->check = ~shorten(shorten(check))` folds twice (to absorb a carry out of the first fold) and complements.

**TCP option normalization** (the `while` loop at the top of both filters)
- Known options (`MSS`, `SACK`, `SACK_PERM`, `TIMESTAMP`, `WINDOW`, `NOP`) are skipped (`opt += opt[1]`).
- **Unknown** options are overwritten with `NOP` bytes and the checksum is invalidated (`h->check = 0`) so the stack recomputes it. This keeps the option space predictable across recovery — TCPR only knows how to replay the options it understands.
- In `tcpr_filter_peer`, the same loop *records* the peer's `MSS` → `hard.peer.mss`, window scale → `hard.peer.ws` (stored `+1` so `0` means "absent"), and `SACK_PERM` → `hard.peer.sack_permitted`, and **rewrites SACK blocks by `+delta`** so selective-ack ranges stay valid in the app's space.

**`tcpr_filter(t, h, size)`** (lines 15-108) — application → peer. Covered in [[#1.2 Detecting a restart & computing `delta`]]. Full field map:
- line 41-44: `rst` → mark `failed`, drop.
- line 46-50: rewrite source port to `hard.port` (stable port).
- line 52-53: record `win`; compute `t->seq` = next byte the app will send (accounts for SYN +1 and payload).
- line 55-60: FIN handling (sets `t->fin` in peer space; failure if not `done_writing`).
- line 62-78: SYN handling → recover vs. first-connection (the core branch).
- line 80-85: `syn_sent` bookkeeping; replay `TCPR_RESET` if `failed`.
- line 87-99: record `ack`; advance/clamp to `hard.ack` (suppress pure acks that would leak past the checkpoint).
- line 101-107: rewrite `seq` by `-delta`, fix checksum, deliver.

**`tcpr_filter_peer(t, h, size)`** (lines 110-202) — peer → application.
- line 159-163: rewrite dest port back to the app's live `port`.
- line 167-172: on SYN, latch ports and `hard.ack = peer_ISN + 1`.
- line 174-177: record peer FIN seq.
- line 179-196: on ACK, record `peer.ack`/`have_ack`, test the `done` condition, detect **peer-side recovery** (`syn_sent && !syn` → compute `delta`, return `TCPR_RECOVER`), and rewrite `ack_seq` by `+delta`.
- returns `TCPR_DROP` if `failed`, else `TCPR_DELIVER`.

**`tcpr_update(t, u)`** (lines 204-225) — merge control state.
- If the caller's `u->port == 0` → it's a **GET**: copy live state into `u`, `TCPR_DELIVER` (reply).
- Otherwise **PUT**: copy `u->hard` + `port`/`done`/`failed` into `t`, then decide: no peer ack yet → `DROP`; failed → `RESET`; `hard.ack` advanced → `ACKNOWLEDGE` (emit an ack on the app's behalf); unchanged → `DROP`.

**`tcpr_acknowledge` / `tcpr_recover` / `tcpr_reset`** (lines 227-292) — packet synthesizers that only fill a `tcphdr` (the module wraps IP + checksums). `acknowledge` emits a bare ACK at the checkpoint and recomputes `done`; `recover` builds the fake SYN/ACK replaying saved options (see [[#1.3 Synthesizing the handshake — `tcpr_recover`]]); `reset` emits a RST at `t->ack`.

### A.2 `module/module.c` — kernel glue (xtables target)

- **`struct connection`** (lines 20-26): the `tcpr_ip4` state + `net_ns` + external `address` + a per-connection `spinlock_t`. Held in a global `connections` list guarded by `connections_lock` (rwlock).
- **`fix_checksums`** (lines 36-49): patch both IP and TCP checksums when an address is rewritten (NAT).
- **`lookup_internal` / `lookup_external`** (lines 51-85): the two "faces" of a connection (app-real vs peer-visible tuple), both scoped by `net_ns`.
- **`connection_create` / `connection_done`** (lines 87-134): allocate (double-checked under write lock) / unlink + free.
- **`inject_ip`** (lines 136-172): build an skb and transmit via `ip_route_me_harder` + `ip_local_out`; refuses to fragment. ⚠️ see [[#6. Known Bugs / Rough Edges]] — it touches `skb` before `alloc_skb`.
- **`inject_tcp`** (lines 174-220): wrap a synthesized `tcphdr` in IP, set src/dst by verdict (RESET/RECOVER look like they come *from the peer*; ACK looks like it comes *from the app*), compute checksums, inject.
- **`inject_update`** (lines 222-244): bounce a `tcpr_ip4` back to the control client over UDP.
- **`tcpr_tg_update` / `tcpr_tg_application` / `tcpr_tg_peer`** (lines 246-413): the three dispatch paths — see [[#3. Kernel Dispatch Path]].
- **`tcpr_tg`** + **`tcpr_tg_reg`** + init/exit (lines 415-467): the xtables target registration, hooked on `LOCAL_IN | LOCAL_OUT`, `--addr` passed as `targinfo`.

### A.3 `module/libxt_TCPR.c` — the iptables userspace plugin
Implements `-j TCPR [--addr IP]`: `parse` converts the address with `xtables_numeric_to_ipaddr`; `print`/`save` round-trip it for `iptables -L`/`iptables-save`. The target data is a single `uint32_t` address (0 = peer-side rule).

### A.4 `src/` userspace tools (all are `tcpr_ip4` stream filters)

| File | What it does | Key line |
|------|--------------|----------|
| `util.c` | `resolve_address`, `connect_to_tcpr` (reads `TCPR_HOST`/`TCPR_PORT`, UDP), `get_tcpr_state` (send ident → recv full state) | 35-93 |
| `get.c` | Build an identifying `tcpr_ip4` from `SRCPORT [HOST PORT]`, fetch state, write to stdout | — |
| `put.c` | Read records from stdin, `send()` each to the module (PUT) | — |
| `print.c` | Human-readable dump of every field (`inet_ntop`, `ntohl`/`ntohs`) | 18-70 |
| `ack.c` | Advance `hard.ack` by N bytes (or all received), bounded by live `ack` | 20-24 |
| `done.c` | Set `done_reading`/`done_writing` (`r`/`w` arg) or force `done` | — |
| `kill.c` | Set `failed = 1` (forces a reset on next packet) | — |
| `bind.c` | Stamp `state.address` + `tcpr.port` from `HOST PORT` | — |

### A.5 `src/chat.c` — the reference application (`tcpr-chat`)

This is the canonical example of **how a real app drives checkpointing**. It's a netcat-like relay between stdin/stdout and a TCP socket, plus a UDP control socket to TCPR.

- **`setup_tcpr`** (244-290): opens the UDP control socket (`-t`); if absent, disables checkpointing.
- **`setup_state`** (292-306): sends the identifying tuple, receives current state (this is what makes `recover` reattach to an existing connection).
- **`handle_events`** (318-445): a `select()` loop. The TCPR-relevant parts:
  - **On receive** (346-369): after reading `n` bytes from the peer, if checkpointing, **advance `hard.ack` by `n` and push to TCPR** (lines 350-351) — i.e., only acknowledge data the app has actually taken. On EOF, set `done_reading` and push.
  - **On send completion / EOF** (392-421): set `done_writing` and push before `shutdown(SHUT_WR)`.
- **Recovery** happens implicitly: run the same binary with the same `-b/-c/-t`; `setup_state` pulls existing state, the kernel sees the new SYN as a recovery, and the chat continues.

> [!example] The checkpoint discipline in one place
> `chat.c:349-352` is the whole correctness contract: advance `hard.ack` **after** the data is in the app's buffer, then tell TCPR. Advance too early → data loss on crash; too late → the peer buffers more and latency grows.

### A.6 `src/bridge.c` — a *recoverable* two-client bridge

Shows a stateful server that survives its **own** restart by persisting connection metadata to a memory-mapped file:
- **`setup`** (74-101): `mmap` a state file at `/var/tmp/tcpr-bridge-<bind>.state`. If it already exists → `recovering = 1`.
- **`setup_connections`** (first run) `accept`s two clients; **`recover_connections`** (after a crash) re-`bind`s to the saved local addresses and re-`connect`s — TCPR then splices these onto the still-open peer connections.
- **`handle_events`** (256-322): forwards bytes each way, advancing each side's `hard.ack` as data is relayed (284-285) and setting `done_reading`/`done_writing` on EOF — same discipline as `chat.c`, duplicated per client.

### A.7 `src/benchmark.c`, `examples/`
`benchmark.c` is a throughput harness (bulk generate/discard via the same `-g`/`-d` flags seen in `chat.c`). The `examples/recover` and `examples/migrate` shell scripts wire up network namespaces + a bridge and invoke these tools — see [[#The demo (`examples/recover`)]].

---

## Glossary

- **`delta`** — offset between the app's and peer's sequence spaces; recomputed on recovery; `0` in normal operation.
- **`hard` state (`tcpr_hard`)** — the crash-survivable checkpoint: ports, peer options, `hard.ack`, done flags.
- **`hard.ack`** — the checkpointed "next byte expected from peer"; only advances once data is durably consumed; bounds what the peer may discard.
- **Verdicts** — `DROP`, `DELIVER`, `ACKNOWLEDGE`, `RECOVER`, `RESET` (see `filter.h`).
- **Internal vs external lookup** — same connection found by the app's real addr/port vs the peer-visible stable addr/port (NAT-like translation).
- **Control protocol** — `tcpr_ip4` over UDP; `get`/`put` read/merge state; tools compose as Unix filters.

---

## See Also
- Project home: `http://www.cs.cornell.edu/~burgess/tcpr/`
- `README` — build + demo walkthrough
- `examples/recover/` — in-place failure & recovery demo
- `examples/migrate/` — live migration to a replica demo
