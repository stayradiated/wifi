# WiFi Manager

A user-friendly command-line interface for managing WiFi connections. This tool provides a simplified wrapper around the `wpa_cli` utility, making it easier to scan, connect, and manage WiFi networks.

## Features

- **Network Scanning**: Quickly scan for available WiFi networks with signal strength indicators
- **Simple Connections**: Connect to networks using a simple syntax or convenient short codes
- **Network Management**: List, enable, disable, and remove saved networks
- **Connection Monitoring**: Check connection status and watch for changes
- **Support for Secured Networks**: Easily connect to both open and password-protected networks
- **Unicode Support**: Proper display of SSIDs with special characters and emojis
- **Pretty Status Output**: Clean, formatted display of connection status information

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

Connect to a network with emoji or special characters:
```bash
wifi add "Café🏃🌟"
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

#### Checking Connection Status

Check the current connection status:
```bash
wifi status
```

This will display detailed information in a formatted layout:
```
📶 Selected interface 'wlan0'
────────────────────────────────────────────────────────
✅ Connected
🌐 Network: MyHomeNetwork
🔢 Network ID: 0
📍 BSSID: 00:11:22:33:44:55
🔐 Security: WPA2-PSK
🔒 Encryption: pairwise: CCMP, group: CCMP
📡 Frequency: 5180 MHz (5 GHz)
🌍 IP Address: 192.168.1.123
💻 Device: MAC: aa:bb:cc:dd:ee:ff, WiFi 6

────────────────────────────────────────────────────────
Additional Details:
  eap_type: 0
  mode: station
  ...
```

Monitor connection status changes in real-time:
```bash
wifi watch
```

## Network Icons

When scanning for networks, the tool displays useful information:

- **Security**: 🔓 (open) or 🔑 (secured)
- **Signal Strength**:
  - ▓ (strong signal)
  - ▒ (medium signal)
  - ░ (weak signal)

## Unicode and Emoji Support

WiFi Manager properly handles SSIDs with:
- Non-ASCII characters (e.g., Café, 网络)
- Emoji characters (e.g., "Home🏠Network", "Fast⚡WiFi")
- Other special characters

The tool automatically detects and properly displays these characters in scan results and status output.

## Requirements

- Linux system with `wpa_supplicant` installed
- Go 1.13 or higher (to build from source)
- Root privileges (for some operations)

## Contributing

Contributions are welcome! Feel free to open issues or pull requests.

## License

MIT License
