# lab

Adversary emulation and load testing for D13. Everything here runs **against the
isolated lab bridge only** (`172.30.0.0/24`, the `lab` compose profile) and exists
for one reason: to give the detection pipeline something to detect, so the chain from
sensor to alert can be exercised end to end.

Every scenario sources `_guard.sh`, which refuses any target that is not on the lab
subnet. That is not a formality — these generate attack traffic, and attack traffic
is only defensible against throwaway containers on a network that does not reach
anything real.

## What each scenario is

| Script | Emulates | MITRE | What the IDS reads |
|---|---|---|---|
| `scan.sh` | Port/service scan | T1046 | one source, many short connections to one host |
| `brute_force.sh` | SSH brute force | T1110 | failed logins in a burst, then one that succeeds |
| `beacon.sh` | C2 beacon cadence | T1071 | small, regular callbacks to one destination |
| `exfil.sh` | DNS / HTTP exfil | T1048 | high-entropy DNS names, or one large outbound POST |

`beacon.sh` and `exfil.sh` are **traffic generators, not tools**. They reproduce the
network *shape* of a beacon and of an exfil transfer using dummy random bytes to a
lab-local sink — there is no implant, no C2 listener, and nothing real to move. A
full Sliver or Mythic exercise clones its own server on the VM; these scripts only
make the detector fire.

`brute_force.sh` points hydra at `victim-ssh`, which `infra/docker-compose.yml`
builds with the password `password123` for exactly this. The wordlist ends on that
known-good password, so the run produces the failed-then-succeeded pattern and
nothing is actually discovered — the answer was in the compose file.

## Running them

The always-on `attacker` container is nmap only, so most scenarios run as a
short-lived tool container attached to the lab network. Bring the lab up first:

```bash
docker compose --profile lab up -d
docker compose --profile sensors up -d     # so there is something watching

LAB=$PWD/lab/scenarios

# scan - from the attacker container, which already has nmap
docker compose exec attacker nmap -sS -sV -T4 --top-ports 1000 172.30.0.10

# brute force
docker compose run --rm -v "$LAB:/scenarios" --network netsentinel_lab \
  vanhauser/hydra sh /scenarios/brute_force.sh

# C2 beacon cadence
docker compose run --rm -v "$LAB:/scenarios" --network netsentinel_lab \
  curlimages/curl:8.10.1 sh /scenarios/beacon.sh

# exfil - DNS pattern (MODE=http for the large-POST pattern instead)
docker compose run --rm -v "$LAB:/scenarios" --network netsentinel_lab \
  -e MODE=dns nicolaka/netshoot sh /scenarios/exfil.sh
```

Each scenario is the D13 emulation for one row of the end-to-end test in
`tests/e2e/test_scenario.py`: the code proves the chain joins up given a scored flow,
and these produce the flow.

## Load test

`load/locustfile.py` drives the API's read path — the alert feed, alert detail, the
approval queue — under concurrency, which is where a dashboard full of polling tabs
finds the ceiling first. Write paths are left out on purpose: a load run should not
flood the approval queue with junk.

```bash
export NETSENTINEL_LOAD_PASSWORD=...        # the seeded analyst's password
pip install locust                          # a laptop-side dev tool, not a workspace dep
locust -f lab/load/locustfile.py --host http://127.0.0.1:8000
```

Locust is not in the workspace dependencies. It runs on the laptop against the API
reached through the SSH tunnel, and adding it to the VM's install would pull a web
framework onto a box that has no use for one.

## This computer's own traffic

`local/watch_this_pc.ps1` scores the laptop's own traffic without a Linux sensor or
Redpanda: Windows' packet monitor captures (one administrator prompt), the real sensor
scores the capture with `--drop-repeats` (pktmon logs each packet once per stack
component), and the real writer stores the alerts in a separate database,
`netsentinel_mypc`, with this computer as the estate.

```powershell
powershell -ExecutionPolicy Bypass -File lab\local\watch_this_pc.ps1 -Seconds 300
powershell -ExecutionPolicy Bypass -File lab\replay\start_demo.ps1 -Native -Database netsentinel_mypc
```

To keep watching instead of scoring one capture, add `-Live` (Ctrl+C stops it):

```powershell
powershell -ExecutionPolicy Bypass -File lab\local\watch_this_pc.ps1 -Live
```

pktmon writes only files, so `local/capture_windows.ps1` (the one elevated part) cuts the
traffic into windows of `-Window` seconds, 15 by default, and moves each finished one into
`lab/local/out/live/`. A single long-running sensor reads them with `--pcap-dir` as one
stream, deleting each as it goes, so a connection that spans two windows is still one
flow. A single long-running writer follows the scored flows with `--replay --follow`.
The launcher also starts the dashboard on `netsentinel_mypc`, and each alert reaches it
about one window after the traffic. A live run keeps that database, its history and its
accounts between runs; `-Fresh` rebuilds it. Stopping goes in order so nothing captured
is dropped: the capture publishes its last window, the sensor reads what is left, then
the writer finishes the file. Port 8010 must be free (stop the Docker stack first),
because the dashboard's API uses it.

What it does not do: pktmon misses the packets in the second or so it takes to restart
between windows, so a connection whose handshake fell in that gap is seen mid-stream and
can alert. A burst of alerts is stored at about ten a second, because each one is
explained with SHAP before it is written.

Expect most flows to alert. The detectors learned normal traffic from NF-UNSW-NB15,
whose training split has no benign HTTPS at all, so ordinary browsing is foreign to them.
The capture holds your real traffic; it stays in `lab/local/out/`, which git ignores.
