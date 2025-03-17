# WiFi Manager

A user-friendly command-line interface for managing WiFi connections. This tool provides a simplified wrapper around the `wpa_cli` utility, making it easier to scan, connect, and manage WiFi networks.

## Features

- **Network Scanning**: Quickly scan for available WiFi networks with signal strength indicators
- **Simple Connections**: Connect to networks using a simple syntax or convenient short codes
- **Network Management**: List, enable, disable, and remove saved networks
- **Connection Monitoring**: Check connection status and watch for changes
- **Support for Secured Networks**: Easily connect to both open and password-protected networks

## Installation

```bash
go build -o wifi
sudo mv wifi /usr/local/bin/
```

## Usage

### Basic Commands

```
wifi <command>
     status    - Show current WiFi connection status
     watch     - Monitor WiFi connection status changes
     scan      - Scan for available WiFi networks
     add       - Add a new WiFi network (SSID [password])
     remove    - Remove a saved WiFi network (network_id)
     list      - List saved WiFi networks
     disable   - Disable a saved WiFi network (network_id)
     enable    - Enable a saved WiFi network (network_id)
     toggle    - Toggle enabled/disabled state (network_id)
     disconnect- Disconnect and reconnect a network (network_id)

Options:
     --open    - Filter to show only open networks during scan
```

### Examples

#### Scanning for Networks

```bash
wifi scan
```

Output will display available networks with their signal strength and security status:
```
abc ▓ 🔑 MyHomeNetwork
def ▒ 🔓 CoffeeShopWiFi
ghi ░ 🔑 WeakSignalNetwork
```

The first column is a unique short code you can use to connect to the network.

#### Connecting to Networks

Connect to an open network:
```bash
wifi add "Coffee Shop WiFi"
```

Connect using the short code:
```bash
wifi add abc
```

Connect to a secured network:
```bash
wifi add "My Home Network" "mypassword123"
```

#### Managing Saved Networks

List saved networks:
```bash
wifi list
```

Enable, disable, or toggle a network:
```bash
wifi enable 2
wifi disable 3
wifi toggle 4
```

Remove a saved network:
```bash
wifi remove 5
```

## Network Icons

When scanning for networks, the tool displays useful information:

- **Security**: 🔓 (open) or 🔑 (secured)
- **Signal Strength**:
  - ▓ (strong signal)
  - ▒ (medium signal)
  - ░ (weak signal)

## Requirements

- Linux system with `wpa_supplicant` installed
- Go 1.13 or higher (to build from source)
- Root privileges (for some operations)

## Contributing

Contributions are welcome! Feel free to open issues or pull requests.

## License

MIT License
