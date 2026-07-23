# Nethogs monitor

Use nethogs as a background service to monitor network usage.

## Installation

```sh
sh nethogs-monitor-install.sh
```

## Usage

Enable service:
```sh
systemctl enable nethogs-monitor
```

Start service:
```sh
systemctl start nethogs-monitor
```

View report:
```sh
nethogs-monitor-report.sh
```


