#!/bin/sh
# Install crispkey and systemd service

set -e

# Build
echo "Building crispkey..."
mix deps.get
mix escript.build

# Install binary
echo "Installing to /usr/local/bin..."
sudo install -m 755 crispkey /usr/local/bin/crispkey

# Install systemd service (user-level)
echo "Installing systemd user service..."
mkdir -p ~/.config/systemd/user
cp contrib/crispkey.service ~/.config/systemd/user/

# Reload systemd
systemctl --user daemon-reload

echo ""
echo "Installation complete!"
echo ""
echo "To start the daemon:"
echo "  systemctl --user start crispkey"
echo ""
echo "To enable at login:"
echo "  systemctl --user enable crispkey"
echo ""
echo "To view logs:"
echo "  journalctl --user -u crispkey -f"
