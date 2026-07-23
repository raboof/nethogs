#!/bin/bash

# Create directories
sudo mkdir -p /var/log/nethogs
sudo mkdir -p /opt/nethogs-monitor

# Move files
sudo cp ../src/nethogs /opt/nethogs-monitor/
sudo cp nethogs-monitor.sh /opt/nethogs-monitor/
sudo cp nethogs-monitor-dashboard-template.html /opt/nethogs-monitor/
sudo cp nethogs-monitor.service /etc/systemd/system/
sudo cp nethogs-monitor-report.sh /opt/nethogs-monitor/

# Set execution permissions
sudo chmod +x /opt/nethogs-monitor/nethogs-monitor.sh
sudo chmod +x /opt/nethogs-monitor/nethogs-monitor-report.sh

# Link in local bins
sudo ln -sf /opt/nethogs-monitor/nethogs-monitor-report.sh /usr/local/bin/nethogs-monitor-report.sh

# Reload daemons
sudo systemctl daemon-reload
