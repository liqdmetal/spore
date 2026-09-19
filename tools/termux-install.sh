#!/usr/bin/env bash
# Spore on Android via Termux — the practical mobile path today (a signed APK
# with a native UI is a separate project; this gets you a working client on
# Android in one command, with the same CLI as desktop).
#
#   pkg install -y git golang openssh && bash termux-install.sh
#
set -euo pipefail

echo "==> Spore for Termux (Android)"
cd "$HOME" || exit 1
if [ ! -d spore ]; then
  git clone https://github.com/liqdmetal/spore.git
fi
cd spore
git pull --ff-only || true

echo "==> building (this takes a few minutes on a phone)"
CGO_ENABLED=0 go build -ldflags "-s -w" -o "$HOME/spore" ./cmd/spore

if [ ! -f "$HOME/.spore/identity.key" ]; then
  echo "==> first run: generating your identity"
  "$HOME/spore" init -dir "$HOME/.spore" -chain dero
fi

cat <<'EOF'

==> done. your Spore client is at ~/spore (CLI).

quick start:
  ~/spore status                       # your DERO address
  ~/spore msg send -to <addr> -store <mailbox> ...   # E2 message (see docs/USER_GUIDE.md)

to keep your private key off the phone's plain disk, use the encrypted
state flags (-state-key FILE) described in docs/ONBOARDING.md.

tip: a hosted mailbox (https://sporem3.io) means the phone does not need to
run a node — point -rpc and -store at the hosted endpoints.
EOF
