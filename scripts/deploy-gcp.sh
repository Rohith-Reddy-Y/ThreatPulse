#!/usr/bin/env bash
# ============================================================================
# ThreatPulse — one-shot deploy to Google Cloud's ALWAYS-FREE tier
#
# Run this in Google Cloud Shell (console.cloud.google.com → >_ icon), from the
# ThreatPulse folder:      bash scripts/deploy-gcp.sh
#
# What it creates (all inside the free tier):
#   • 1 × e2-micro VM in us-central1 (free tier region), Debian 12
#   • 30 GB standard persistent disk (free tier max), ephemeral external IP
#   • firewall rule for ports 80/443
#   • HTTPS via Caddy + Let's Encrypt on a free <ip>.sslip.io hostname
#   • a $1 budget alert so you're emailed if anything ever starts costing money
#
# Re-running is safe: existing resources are reused, the app is redeployed.
# ============================================================================
set -euo pipefail

# Override to reuse an existing VM, e.g.:
#   PROJECT=my-proj VM_NAME=my-vm ZONE=us-central1-c bash scripts/deploy-gcp.sh
VM_NAME="${VM_NAME:-threatpulse}"
REGION="us-central1"          # free tier: us-west1, us-central1 or us-east1 only
ZONE="${ZONE:-${REGION}-a}"
FW_RULE="threatpulse-allow-web"
APP_DIR="$(cd "$(dirname "$0")/.." && pwd)"

say()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m[!] %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31m[x] %s\033[0m\n' "$*"; exit 1; }

[ -f "$APP_DIR/server.js" ] || die "Run this from inside the ThreatPulse folder."
command -v gcloud >/dev/null || die "gcloud not found — run this in Google Cloud Shell."

# ── 1. Your email (TLS certificate contact + admin password resets) ─────────
ADMIN_EMAIL="${ADMIN_EMAIL:-}"
while [[ ! "$ADMIN_EMAIL" =~ ^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$ ]]; do
  read -rp "Your email address (for the HTTPS certificate & admin account): " ADMIN_EMAIL
done

# ── 2. Project + billing ────────────────────────────────────────────────────
say "Selecting a Google Cloud project"
PROJECT="${PROJECT:-$(gcloud config get-value project 2>/dev/null || true)}"
if [ -z "$PROJECT" ] || [ "$PROJECT" = "(unset)" ]; then
  PROJECT="threatpulse-$(tr -dc 'a-z0-9' </dev/urandom | head -c 6)"
  say "Creating project $PROJECT"
  gcloud projects create "$PROJECT" --name="ThreatPulse"
fi
gcloud config set project "$PROJECT" >/dev/null
echo "Project: $PROJECT"

BILLING_ACCOUNT="$(gcloud billing projects describe "$PROJECT" --format='value(billingAccountName)' 2>/dev/null | sed 's#billingAccounts/##')"
if [ -z "$BILLING_ACCOUNT" ]; then
  BILLING_ACCOUNT="$(gcloud billing accounts list --filter='open=true' --format='value(name)' --limit=1 | sed 's#billingAccounts/##')"
  [ -n "$BILLING_ACCOUNT" ] || die "No billing account found. Create one at https://console.cloud.google.com/billing (card is for verification; the free tier isn't charged), then re-run."
  say "Linking billing account $BILLING_ACCOUNT"
  gcloud billing projects link "$PROJECT" --billing-account="$BILLING_ACCOUNT" >/dev/null
fi

say "Enabling the Compute Engine API (takes ~1 min the first time)"
gcloud services enable compute.googleapis.com

# ── 3. $1 budget alert (emails billing admins at 50% and 100%) ──────────────
say "Setting a \$1 budget alert"
if gcloud services enable billingbudgets.googleapis.com >/dev/null 2>&1; then
  if ! gcloud billing budgets list --billing-account="$BILLING_ACCOUNT" --format='value(displayName)' 2>/dev/null | grep -qx 'threatpulse-1usd'; then
    gcloud billing budgets create --billing-account="$BILLING_ACCOUNT" \
      --display-name="threatpulse-1usd" --budget-amount=1USD \
      --filter-projects="projects/$PROJECT" \
      --threshold-rule=percent=0.5 --threshold-rule=percent=1.0 >/dev/null \
      && echo "Budget alert created." || warn "Couldn't create the budget alert — add one manually under Billing → Budgets & alerts."
  else
    echo "Budget alert already exists."
  fi
else
  warn "Couldn't enable the Budgets API — add a \$1 alert manually under Billing → Budgets & alerts."
fi

# ── 4. Firewall + VM ────────────────────────────────────────────────────────
say "Opening ports 80/443"
gcloud compute firewall-rules describe "$FW_RULE" >/dev/null 2>&1 || \
  gcloud compute firewall-rules create "$FW_RULE" --network=default \
    --allow=tcp:80,tcp:443 --target-tags=threatpulse --source-ranges=0.0.0.0/0 >/dev/null

say "Creating the free e2-micro VM"
if ! gcloud compute instances describe "$VM_NAME" --zone="$ZONE" >/dev/null 2>&1; then
  gcloud compute instances create "$VM_NAME" --zone="$ZONE" \
    --machine-type=e2-micro \
    --image-family=debian-12 --image-project=debian-cloud \
    --boot-disk-size=30GB --boot-disk-type=pd-standard \
    --tags=threatpulse >/dev/null
fi
# Make sure the firewall rule applies (also for a pre-existing VM).
gcloud compute instances add-tags "$VM_NAME" --zone="$ZONE" --tags=threatpulse >/dev/null

MT="$(gcloud compute instances describe "$VM_NAME" --zone="$ZONE" --format='value(machineType.basename())')"
[ "$MT" = "e2-micro" ] || warn "VM $VM_NAME is $MT — only e2-micro is in the free tier."
gcloud compute disks list --filter="zone~$ZONE AND users~/$VM_NAME\$" --format='value(name,sizeGb,type.basename())' | while read -r d sz t; do
  { [ "$t" = "pd-standard" ] && [ "${sz:-0}" -le 30 ]; } || warn "Disk $d is ${sz}GB $t — free tier covers only up to 30 GB pd-standard (expect ~\$0.10/GB-month otherwise)."
done

IP="$(gcloud compute instances describe "$VM_NAME" --zone="$ZONE" --format='value(networkInterfaces[0].accessConfigs[0].natIP)')"
[ -n "$IP" ] || die "VM has no external IP."
DOMAIN="${IP//./-}.sslip.io"
echo "VM IP: $IP   →   https://$DOMAIN"

say "Waiting for SSH"
for i in $(seq 1 30); do
  gcloud compute ssh "$VM_NAME" --zone="$ZONE" --quiet --command="true" >/dev/null 2>&1 && break
  sleep 10
  [ "$i" = 30 ] && die "VM didn't become reachable over SSH."
done

# ── 5. Ship the code ────────────────────────────────────────────────────────
say "Uploading ThreatPulse"
TARBALL="$(mktemp -d)/threatpulse.tar.gz"
tar -C "$APP_DIR" --exclude=.git --exclude=node_modules --exclude='*.db*' --exclude=.env -czf "$TARBALL" .
gcloud compute scp "$TARBALL" "$VM_NAME":~/threatpulse.tar.gz --zone="$ZONE" --quiet

# ── 6. Server-side setup ────────────────────────────────────────────────────
say "Installing Docker and starting ThreatPulse on the VM (5–10 min on first run)"
gcloud compute ssh "$VM_NAME" --zone="$ZONE" --quiet --command="sudo DOMAIN='$DOMAIN' ADMIN_EMAIL='$ADMIN_EMAIL' bash -s" <<'REMOTE'
set -euo pipefail

# 2 GB swap — e2-micro only has 1 GB RAM; the Docker build needs headroom.
if ! swapon --show | grep -q /swapfile; then
  fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile >/dev/null && swapon /swapfile
  grep -q '/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi

command -v docker >/dev/null || (curl -fsSL https://get.docker.com | sh >/dev/null)

mkdir -p /opt/threatpulse
tar -xzf "$(ls -t /home/*/threatpulse.tar.gz | head -1)" -C /opt/threatpulse
cd /opt/threatpulse

# Create .env once — keep secrets stable across redeploys.
if [ ! -f .env ]; then
  cat > .env <<ENV
NODE_ENV=production
PORT=3000
JWT_SECRET=$(openssl rand -hex 48)
DOMAIN=${DOMAIN}
BASE_URL=https://${DOMAIN}
ALLOWED_ORIGIN=https://${DOMAIN}
ADMIN_EMAIL=${ADMIN_EMAIL}
FETCH_CRON=*/15 * * * *
DASHBOARD_REFRESH=60
# Optional keys — add later, then: cd /opt/threatpulse && sudo docker compose up -d
NVD_API_KEY=
ABUSE_CH_API_KEY=
GROQ_API_KEY=
TAVILY_API_KEY=
# SMTP_HOST=smtp.gmail.com
# SMTP_PORT=587
# SMTP_USER=
# SMTP_PASS=
ENV
  chmod 600 .env
else
  # IP may have changed (ephemeral IP) — keep hostname settings in sync.
  sed -i "s#^DOMAIN=.*#DOMAIN=${DOMAIN}#; s#^BASE_URL=.*#BASE_URL=https://${DOMAIN}#; s#^ALLOWED_ORIGIN=.*#ALLOWED_ORIGIN=https://${DOMAIN}#" .env
fi

docker compose up -d --build

echo "Waiting for the app to become healthy..."
for i in $(seq 1 40); do
  s=$(docker inspect --format '{{.State.Health.Status}}' threatpulse 2>/dev/null || echo starting)
  [ "$s" = healthy ] && break
  sleep 6
done
echo "Container health: $(docker inspect --format '{{.State.Health.Status}}' threatpulse)"
echo
echo "------ FIRST-RUN ADMIN LOGIN (only shown on the very first start) ------"
docker logs threatpulse 2>&1 | grep -E 'Username: admin|Password: ' || echo "(admin already exists — use your existing password)"
echo "------------------------------------------------------------------------"
rm -f /home/*/threatpulse.tar.gz
REMOTE

say "Done!"
cat <<EOF

  🌐  Dashboard:  https://$DOMAIN
  🔒  Admin:      https://$DOMAIN/admin   (user: admin — password printed above,
                                          you'll be asked to change it)

  HTTPS may take ~1 minute to issue on first visit.

  Useful commands (from Cloud Shell):
    gcloud compute ssh $VM_NAME --zone=$ZONE
    sudo docker logs -f threatpulse          # app logs (inside the VM)
    sudo nano /opt/threatpulse/.env          # add API keys, then:
    cd /opt/threatpulse && sudo docker compose up -d

  Cost: e2-micro + 30 GB standard disk + external IP in $REGION are inside the
  always-free tier. A \$1 budget alert will email you if that ever changes.
EOF
