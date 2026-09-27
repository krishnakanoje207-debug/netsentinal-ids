# Setting up the cloud VM

Step by step, from an empty cloud account to the full pipeline running: Suricata, Zeek,
Wazuh, Redpanda, ClickHouse, the scorers and the dashboard. Once the VM is ready,
`infra/README.md` is the reference for each Compose profile; this page gets you there.
Budget about two hours, most of it downloads.

## 1. Choose the machine

| | Needed | Why |
|---|---|---|
| RAM | **16 GB** | the core profiles take 12.1 GB (`infra/README.md`, "Why profiles") |
| vCPU | 4 | Suricata, Zeek and the scorers run side by side |
| Disk | 64 GB SSD minimum, 128 GB better | images ~15 GB, Greenbone feeds ~10 GB, ClickHouse grows |
| CPU architecture | x86-64 | every third-party image also publishes arm64 (checked 2026-09-27), but the stack has only been run on x86-64 |
| OS | Ubuntu Server 24.04 LTS | what the Compose files were written against |

On **Azure for Students** (the plan's choice), `Standard_B4ms` (4 vCPU, 16 GB) or
`Standard_D4as_v5` fits. Check the current price in your region on Azure's pricing page
before creating it: at student-credit rates a 16 GB VM left running all month uses most
of the credit, so **stop (deallocate) it whenever you are not using it** - a deallocated
VM costs only its disk.

### An 8 GB machine

The subscription may not offer either size. On the one used for this project (Central
India, 2026-09-27) both were unavailable and the only size allowed was 4 vCPU / 8 GB.
It runs the stack, because the caps are ceilings and real use is far below them:

- **Swap raised to 12 GB** (step 3 makes 4 GB; replace it):
  ```bash
  sudo swapoff /swapfile && sudo fallocate -l 12G /swapfile && sudo chmod 600 /swapfile && sudo mkswap /swapfile && sudo swapon /swapfile
  ```
- **Everything but `intel` and `scan` runs together.** Measured with `docker stats` on
  the first day: the detection path (`storage`, `bus`, `ingest`, `sensors`, `pipeline`,
  `lab`, `app`) used 2.4 GB against 8.65 GB of caps; adding `hids`, `response`,
  `dashboards` and `case` brought the containers to 5.0 GB, with 2.5 GB still available.
- **`intel` and `scan` take turns with `case` and `hids`:** stop `case` for an `intel`
  window, and `intel` and `hids` for a `scan` window, then bring them back.

## 2. Create the VM (Azure portal)

1. Sign in at https://portal.azure.com with the student account, then **Create a
   resource > Virtual machine**.
2. **Basics:** a new resource group `netsentinel`; name `netsentinel-vm`; the region
   nearest you; image **Ubuntu Server 24.04 LTS - x64 Gen2**; size as above.
3. **Administrator account:** authentication type **SSH public key** and a username
   (Azure's default is `azureuser`; this page writes `<user>`). The simplest key source is
   **Generate new key pair**: at **Review + create** the portal offers
   **Download private key and create resource**, and that is the only chance to get the
   key. Save it as `$HOME\.ssh\netsentinel_vm.pem`. Or, with **Use existing public key**,
   make one on the laptop first:
   ```powershell
   ssh-keygen -t ed25519 -f $HOME\.ssh\netsentinel_vm
   Get-Content $HOME\.ssh\netsentinel_vm.pub     # paste this into the portal
   ```
4. **Inbound ports:** allow **SSH (22) only**. Nothing else is ever opened: every service
   binds to 127.0.0.1 and you reach it through the tunnel (step 7). The lab carries attack
   traffic, so this is not optional.
5. **Disks:** OS disk **Premium SSD**, size 128 GB.
6. **Management:** turn on **Auto-shutdown** (for example 23:00) so a forgotten VM stops
   spending credit.
7. **Review + create.** Note the public IP address.

Optionally restrict the SSH rule to your own address: in the VM's **Networking** page, set
the rule's source to **My IP address**.

## 3. First login and OS preparation

```powershell
ssh -i $HOME\.ssh\netsentinel_vm <user>@<public-ip>
```

`<user>` is the username set at creation. The VM page's **Connect > Connect (Native SSH)**
shows it with the IP. With the portal's generated key, use `-i $HOME\.ssh\netsentinel_vm.pem`;
Windows OpenSSH refuses a downloaded key with "UNPROTECTED PRIVATE KEY FILE" until its
permissions are narrowed:

```powershell
icacls $HOME\.ssh\netsentinel_vm.pem /inheritance:r /grant:r "$($env:USERNAME):R"
```

If SSH times out, the port 22 rule's source is usually a stale address (home and mobile
IPs change): fix it in **Networking > Network settings**.

On the VM:

```bash
sudo apt update && sudo apt -y upgrade

# Docker Engine and the Compose plugin, from Docker's own repository
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER            # log out and back in after this

# The Wazuh indexer (OpenSearch) refuses to start below this
echo 'vm.max_map_count=262144' | sudo tee /etc/sysctl.d/99-netsentinel.conf
sudo sysctl --system

# A swap file, so a memory spike slows things down instead of killing a container
sudo fallocate -l 4G /swapfile && sudo chmod 600 /swapfile
sudo mkswap /swapfile && sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab

# Accurate time: alerts, JWT expiry and the shadow-mode windows all depend on it
timedatectl status                       # "System clock synchronized: yes"

sudo apt -y install git tcpreplay
exit
```

Log in again and check `docker run --rm hello-world`.

## 4. Get the code

The repository is private, so the VM needs its own read-only key:

```bash
ssh-keygen -t ed25519 -f ~/.ssh/github_deploy -N ''
cat ~/.ssh/github_deploy.pub
```

On GitHub: repository **netsentinal-ids > Settings > Deploy keys > Add deploy key**; paste
it and leave **Allow write access** unticked. (Or, from the laptop, with the `.pub` copied
over: `gh repo deploy-key add <file> --title azure-vm-readonly`.) Then:

```bash
cat >> ~/.ssh/config <<'EOF'
Host github.com
  IdentityFile ~/.ssh/github_deploy
EOF
git clone git@github.com:krishnakanoje207-debug/netsentinal-ids.git ~/netsentinel
```

## 5. Copy the trained models

The ONNX graphs and LightGBM boosters are gitignored (20 MB, regenerated by training), so
they travel separately. From the project folder **on the laptop**:

```powershell
scp -i $HOME\.ssh\netsentinel_vm -r artefacts <user>@<public-ip>:~/netsentinel/
```

The model cards are already in the clone; the registry refuses any model whose file does
not match the SHA-256 in its card, so a truncated copy fails loudly rather than scoring.

## 6. Configure and start

On the VM:

```bash
cd ~/netsentinel/infra
cp .env.example .env
nano .env        # fill in every value; generate each secret with
                 # python3 -c "import secrets; print(secrets.token_urlsafe(24))"
```

Then follow `infra/README.md` in this order:

1. **First run** - storage, bus, lab, sensors (including `suricata-update` for ET Open),
   ingest, app, pipeline.
2. **pipeline: the detection path** - register the models and the sensor row once; until
   then the sensor scores nothing.
3. **Verifying each step** - schema present, lab bridge up, Suricata computing JA4, Zeek
   writing `ja4` fields, and an attack from the lab raising an alert.
4. The optional profiles as you need them: **hids** (Wazuh; certificates and user hashes
   first), **response** (CrowdSec and the nftables bouncer), **dashboards** (Grafana),
   **case** (DFIR-IRIS), **intel** (MISP and Keep) and **scan** (Greenbone). Mind the
   memory rotation in "Why profiles": `intel` and `scan` cannot run together with
   everything else.

Load the estate so scan findings and the response gate know your own hosts:

```bash
docker cp ../lab/lab_inventory.csv netsentinel-api-1:/tmp/inventory.csv
docker compose exec api netsentinel-import-assets --csv /tmp/inventory.csv
```

`lab/lab_inventory.csv` lists the lab's victims and its benign client; for a real estate,
write your own with the same columns.

**Docker Hub's pull limit.** Anonymous pulls from Docker Hub are limited per address, and
a first run pulls a lot; past the limit a pull fails with `429 Too Many Requests` for a
few hours. Google's mirror serves the same images; pull from it and give the image the
name compose expects:

```bash
docker pull mirror.gcr.io/wazuh/wazuh-indexer:4.14.8
docker tag mirror.gcr.io/wazuh/wazuh-indexer:4.14.8 wazuh/wazuh-indexer:4.14.8
# official images sit under library/: mirror.gcr.io/library/redis:7-alpine
```

## 7. Use it from the laptop: the SSH tunnel

One command forwards every console to the laptop's localhost:

```powershell
ssh -i $HOME\.ssh\netsentinel_vm -N `
  -L 5180:127.0.0.1:5180 `
  -L 8010:127.0.0.1:8010 `
  -L 3000:127.0.0.1:3000 `
  -L 5601:127.0.0.1:5601 `
  -L 8443:127.0.0.1:8443 `
  <user>@<public-ip>
```

| On the laptop | What |
|---|---|
| https://127.0.0.1:5180 | the NetSentinel dashboard |
| http://127.0.0.1:8010/api/v1/docs | the API |
| http://127.0.0.1:3000 | Grafana |
| https://127.0.0.1:5601 | the Wazuh dashboard |
| https://127.0.0.1:8443 | DFIR-IRIS |

The dashboard's last-hour strip now shows flow counts, because ClickHouse is running.

**The Copilot stays on the laptop's GPU.** Forward PostgreSQL as well
(`-L 5432:127.0.0.1:5432`) and point it there:

```powershell
$env:NETSENTINEL_DATABASE_URL = "postgresql+psycopg://netsentinel:<POSTGRES_PASSWORD>@127.0.0.1:5432/netsentinel"
uv run netsentinel-copilot --latest 10
```

## 8. Run an attack and watch it arrive

On the VM, from the repository root:

```bash
sudo sh lab/replay/tcpreplay.sh <capture.pcap>     # a capture onto the lab bridge
# or one of the scripted attacks in lab/scenarios/ (they refuse targets outside 172.30.0.0/24)
```

On the laptop, the station clock is sweeping, and the alerts turn over onto the board as
the writer stores them.

## 9. Day to day

- **Stop it** when finished: Azure portal > the VM > **Stop**. `docker compose` services
  have `restart: unless-stopped`, so they come back by themselves on the next **Start**.
  The public IP may change after a stop unless you made it static.
- **Update the code:** `cd ~/netsentinel && git pull`, then
  `docker compose --profile <name> up -d --build` for the profiles whose code changed.
- **Updated models:** copy `artefacts/` again (step 5), register the new card, then
  restart the `pipeline` profile. A new model starts in shadow and is promoted from the
  dashboard's Models page.
- **Disk:** `docker system df`; ClickHouse keeps flows for the TTL in its DDL.

## What it costs to leave something out

| Skip | Effect |
|---|---|
| `hids` | no host alerts from Wazuh; frees 3 GB |
| `intel` | no MISP enrichment; alerts are unaffected |
| `scan` | the Estate page shows no findings |
| `response` | approved blocks are recorded but nothing enforces them |
| `dashboards` | no Grafana; the NetSentinel dashboard is unaffected |
