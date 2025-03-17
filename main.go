package main

import (
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Network represents a WiFi network
type Network struct {
	shortCode   string
	bssid       string
	frequency   string
	signalLevel int
	flags       map[string]bool
	isSecured   bool
	ssid        string
}

// SavedNetwork represents a WiFi network saved in the configuration
type SavedNetwork struct {
	networkId int
	ssid      string
	bssid     string
	flags     map[string]bool
}

// Execute wpa_cli command with the provided arguments
func wpaCli(args ...string) (string, error) {
	fmt.Println("» wpa_cli", strings.Join(args, " "))

	cmd := exec.Command("wpa_cli", args...)

	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("wpa_cli error: %w", err)
	}

	return string(output), nil
}

// removeEmptyLines removes empty lines from a slice of strings
func removeEmptyLines(input []string) []string {
	output := []string{}

	for _, line := range input {
		if len(strings.TrimSpace(line)) > 0 {
			output = append(output, line)
		}
	}

	return output
}

// lastLine gets the last non-empty line from the input string
func lastLine(input string) string {
	lines := removeEmptyLines(strings.Split(input, "\n"))
	if len(lines) == 0 {
		return ""
	}
	return lines[len(lines)-1]
}

// assertOK checks if the last line of the input is "OK"
func assertOK(input string) error {
	line := lastLine(input)
	if line != "OK" {
		return fmt.Errorf("expected OK, got: %s", line)
	}
	return nil
}

// escapeString escapes special characters in a string
func escapeString(input string) string {
	replacements := []struct {
		old string
		new string
	}{
		{"\\", "\\\\"},
		{"'", "\\'"},
		{"(", "\\("},
		{")", "\\)"},
		{"&", "\\&"},
		{"$", "\\$"},
	}

	result := input
	for _, r := range replacements {
		result = strings.ReplaceAll(result, r.old, r.new)
	}
	return result
}

// parseNetworkFlags parses network flags from a string
func parseNetworkFlags(input string) map[string]bool {
	flagMap := map[string]bool{}

	list := strings.Split(strings.Trim(input, "[]"), "][")
	for _, flag := range list {
		if flag != "" {
			flagMap[flag] = true
		}
	}

	return flagMap
}

// isNetworkSecured checks if a network is secured
func isNetworkSecured(flags map[string]bool) bool {
	for key := range flags {
		if strings.HasPrefix(key, "WPA2-") || strings.HasPrefix(key, "WPA-") || strings.HasPrefix(key, "RSN-") {
			return true
		}
	}
	return false
}

// getShortCode generates a short code for a network SSID
func getShortCode(input string) (string, error) {
	hash := sha256.New()
	if _, err := hash.Write([]byte(input)); err != nil {
		return "", err
	}
	shortCode := fmt.Sprintf("%x", hash.Sum(nil))[0:3]
	return shortCode, nil
}

// unescapeSSID decodes SSID strings that contain escaped UTF-8 sequences
func unescapeSSID(input string) string {
	// If there are no escape sequences, return the input as is
	if !strings.Contains(input, "\\x") {
		return input
	}

	// Replace all escape sequences
	var result strings.Builder
	i := 0
	for i < len(input) {
		if i+3 < len(input) && input[i] == '\\' && input[i+1] == 'x' {
			// Try to parse the hex value
			hexStr := input[i+2 : i+4]
			if val, err := strconv.ParseUint(hexStr, 16, 8); err == nil {
				result.WriteByte(byte(val))
				i += 4
				continue
			}
		}

		// If not an escape sequence, add the character as is
		result.WriteByte(input[i])
		i++
	}

	return result.String()
}

// parseScanResults parses the output of scan_results command
func parseScanResults(input string) ([]Network, error) {
	networks := []Network{}
	lines := removeEmptyLines(strings.Split(input, "\n"))

	// Need at least 3 lines (including header) to have valid data
	if len(lines) < 3 {
		return networks, nil
	}

	for _, line := range lines[2:] {
		chunks := strings.Split(line, "\t")
		if len(chunks) < 5 {
			continue
		}

		flags := parseNetworkFlags(chunks[3])

		signalLevel, err := strconv.Atoi(chunks[2])
		if err != nil {
			return nil, fmt.Errorf("invalid signal level: %s", chunks[2])
		}

		// Get the SSID and unescape it if needed
		ssid := chunks[4]
		ssid = unescapeSSID(ssid)

		shortCode, err := getShortCode(ssid)
		if err != nil {
			return nil, fmt.Errorf("failed to generate short code: %w", err)
		}

		networks = append(networks, Network{
			shortCode:   shortCode,
			bssid:       chunks[0],
			frequency:   chunks[1],
			signalLevel: signalLevel,
			flags:       flags,
			isSecured:   isNetworkSecured(flags),
			ssid:        ssid,
		})
	}

	// Sort networks by signal level (strongest first)
	sort.Slice(networks, func(p, q int) bool {
		return networks[p].signalLevel > networks[q].signalLevel
	})

	return networks, nil
}

// parseListNetworkResults parses the output of list_network command
func parseListNetworkResults(input string) ([]SavedNetwork, error) {
	networks := []SavedNetwork{}
	lines := removeEmptyLines(strings.Split(input, "\n"))

	// Need at least 3 lines (including header) to have valid data
	if len(lines) < 3 {
		return networks, nil
	}

	for _, line := range lines[2:] {
		chunks := strings.Split(line, "\t")
		if len(chunks) < 4 {
			continue
		}

		flags := parseNetworkFlags(chunks[3])

		networkId, err := strconv.Atoi(chunks[0])
		if err != nil {
			return nil, fmt.Errorf("invalid network ID: %s", chunks[0])
		}

		// Get the SSID and unescape it if needed
		ssid := chunks[1]
		ssid = unescapeSSID(ssid)

		bssid := chunks[2]

		networks = append(networks, SavedNetwork{
			networkId: networkId,
			ssid:      ssid,
			bssid:     bssid,
			flags:     flags,
		})
	}
	return networks, nil
}

var isShortCodeRegExp = regexp.MustCompile("^[A-f0-9]{3}$")

// isShortCode checks if a string is a valid short code
func isShortCode(input string) bool {
	return isShortCodeRegExp.MatchString(input)
}

// resolveShortCode resolves a short code to an SSID
func resolveShortCode(shortCode string) (string, error) {
	output, err := wpaCli("scan_results")
	if err != nil {
		return "", err
	}

	networks, err := parseScanResults(output)
	if err != nil {
		return "", err
	}

	for _, network := range networks {
		if network.shortCode == shortCode {
			return network.ssid, nil
		}
	}
	return "", errors.New("could not resolve shortCode")
}

// prettyPrintStatus formats the raw wpa_cli status output in a more readable way
func prettyPrintStatus(statusOutput string) string {
	lines := removeEmptyLines(strings.Split(statusOutput, "\n"))

	// Extract interface from first line if present
	interfaceLine := ""
	remainingLines := lines
	if len(lines) > 0 && strings.HasPrefix(lines[0], "Selected interface") {
		interfaceLine = lines[0]
		remainingLines = lines[1:]
	}

	// Parse key-value pairs
	statusMap := make(map[string]string)
	for _, line := range remainingLines {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := parts[0]
			value := parts[1]
			statusMap[key] = value
		}
	}

	// Start building pretty output
	var pretty strings.Builder

	if interfaceLine != "" {
		pretty.WriteString(fmt.Sprintf("📶 %s\n", interfaceLine))
		pretty.WriteString(strings.Repeat("─", 60) + "\n")
	}

	// Connection Status
	wpaState := statusMap["wpa_state"]
	if wpaState == "COMPLETED" {
		pretty.WriteString("✅ Connected\n")
	} else if wpaState != "" {
		pretty.WriteString(fmt.Sprintf("❓ Status: %s\n", wpaState))
	}

	// Network Information
	if ssid := statusMap["ssid"]; ssid != "" {
		pretty.WriteString(fmt.Sprintf("🌐 Network: %s\n", unescapeSSID(ssid)))
	}

	if id, ok := statusMap["id"]; ok {
		pretty.WriteString(fmt.Sprintf("🔢 Network ID: %s\n", id))
	}

	if bssid := statusMap["bssid"]; bssid != "" {
		pretty.WriteString(fmt.Sprintf("📍 BSSID: %s\n", bssid))
	}

	// Security Information
	if keyMgmt := statusMap["key_mgmt"]; keyMgmt != "" {
		pretty.WriteString(fmt.Sprintf("🔐 Security: %s\n", keyMgmt))
	}

	// Encryption
	encDetails := []string{}
	if pairwise := statusMap["pairwise_cipher"]; pairwise != "" {
		encDetails = append(encDetails, fmt.Sprintf("pairwise: %s", pairwise))
	}
	if group := statusMap["group_cipher"]; group != "" {
		encDetails = append(encDetails, fmt.Sprintf("group: %s", group))
	}

	if len(encDetails) > 0 {
		pretty.WriteString(fmt.Sprintf("🔒 Encryption: %s\n", strings.Join(encDetails, ", ")))
	}

	// Frequency & Signal
	if freq := statusMap["freq"]; freq != "" {
		freqInt, err := strconv.Atoi(freq)
		if err == nil {
			band := "2.4 GHz"
			if freqInt > 3000 {
				band = "5 GHz"
			}
			pretty.WriteString(fmt.Sprintf("📡 Frequency: %s MHz (%s)\n", freq, band))
		} else {
			pretty.WriteString(fmt.Sprintf("📡 Frequency: %s MHz\n", freq))
		}
	}

	// IP Information
	if ip := statusMap["ip_address"]; ip != "" {
		pretty.WriteString(fmt.Sprintf("🌍 IP Address: %s\n", ip))
	}

	// Device Details
	deviceDetails := []string{}
	if addr := statusMap["address"]; addr != "" {
		deviceDetails = append(deviceDetails, fmt.Sprintf("MAC: %s", addr))
	}
	if gen := statusMap["wifi_generation"]; gen != "" {
		deviceDetails = append(deviceDetails, fmt.Sprintf("WiFi %s", gen))
	}
	if len(deviceDetails) > 0 {
		pretty.WriteString(fmt.Sprintf("💻 Device: %s\n", strings.Join(deviceDetails, ", ")))
	}

	// Other potentially useful information
	if uuid := statusMap["uuid"]; uuid != "" {
		pretty.WriteString(fmt.Sprintf("🆔 UUID: %s\n", uuid))
	}

	// Show any additional fields
	pretty.WriteString("\n" + strings.Repeat("─", 60) + "\n")
	pretty.WriteString("Additional Details:\n")

	// Sort the keys for consistent display
	var keys []string
	for k := range statusMap {
		// Skip keys we've already displayed
		if k == "ssid" || k == "bssid" || k == "wpa_state" || k == "id" ||
			k == "key_mgmt" || k == "pairwise_cipher" || k == "group_cipher" ||
			k == "freq" || k == "ip_address" || k == "address" ||
			k == "wifi_generation" || k == "uuid" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		v := statusMap[k]
		if strings.HasPrefix(v, "\\x") {
			v = unescapeSSID(v)
		}
		pretty.WriteString(fmt.Sprintf("  %s: %s\n", k, v))
	}

	return pretty.String()
}

func main() {
	var filterByOpen bool
	flag.BoolVar(&filterByOpen, "open", false, "only list open networks")
	flag.Parse()

	command := ""
	args := flag.Args()
	if len(args) >= 1 {
		command = args[0]
	}

	switch command {
	case "status":
		output, err := wpaCli("status")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Print(prettyPrintStatus(output))

	case "watch":
		previousStatus := ""
		for {
			status, err := wpaCli("status")
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				time.Sleep(5 * time.Second)
				continue
			}

			if status != previousStatus {
				fmt.Print(prettyPrintStatus(status))
			}
			previousStatus = status
			time.Sleep(1 * time.Second)
		}

	case "list":
		output, err := wpaCli("list_network")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		networkList, err := parseListNetworkResults(output)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing network list: %v\n", err)
			os.Exit(1)
		}

		for _, network := range networkList {
			status := " "
			if network.flags["DISABLED"] {
				status = "×"
			}
			if network.flags["TEMP-DISABLED"] {
				status = "¤"
			}
			fmt.Printf(" %s %3d %s\n", status, network.networkId, network.ssid)
		}

	case "disable", "enable", "remove":
		if len(args) < 2 {
			fmt.Fprintf(os.Stderr, "Error: missing network ID\n")
			os.Exit(1)
		}

		networkId := args[1]
		output, err := wpaCli(command+"_network", networkId)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Print(output)

	case "disconnect":
		if len(args) < 2 {
			fmt.Fprintf(os.Stderr, "Error: missing network ID\n")
			os.Exit(1)
		}

		networkId := args[1]
		output, err := wpaCli("disable_network", networkId)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Print(output)

		time.Sleep(1 * time.Second)

		output, err = wpaCli("enable_network", networkId)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Print(output)

	case "toggle":
		if len(args) < 2 {
			fmt.Fprintf(os.Stderr, "Error: missing network ID\n")
			os.Exit(1)
		}

		networkId := args[1]
		output, err := wpaCli("list_network")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		networkList, err := parseListNetworkResults(output)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing network list: %v\n", err)
			os.Exit(1)
		}

		for _, network := range networkList {
			if strconv.Itoa(network.networkId) == networkId {
				var output string
				var err error

				if network.flags["DISABLED"] {
					output, err = wpaCli("enable_network", networkId)
				} else {
					output, err = wpaCli("disable_network", networkId)
				}

				if err != nil {
					fmt.Fprintf(os.Stderr, "Error: %v\n", err)
					os.Exit(1)
				}
				fmt.Print(output)
				break
			}
		}

	case "add":
		if len(args) < 2 {
			fmt.Fprintf(os.Stderr, "Error: missing SSID\n")
			os.Exit(1)
		}

		output, err := wpaCli("add_network")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		networkId := lastLine(output)
		ssid := args[1]

		if isShortCode(ssid) {
			resolvedShortCode, err := resolveShortCode(ssid)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			ssid = resolvedShortCode
		}

		escapedSsid := escapeString(ssid)
		output, err = wpaCli("set_network", networkId, "ssid", fmt.Sprintf("\\\"%s\\\"", escapedSsid))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		if err := assertOK(output); err != nil {
			fmt.Fprintf(os.Stderr, "Error setting SSID: %v\n", err)
			os.Exit(1)
		}

		if len(args) == 2 {
			output, err = wpaCli("set_network", networkId, "key_mgmt", "NONE")
		} else {
			psk := escapeString(args[2])
			output, err = wpaCli("set_network", networkId, "psk", fmt.Sprintf("\\\"%s\\\"", psk))
		}

		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		if err := assertOK(output); err != nil {
			fmt.Fprintf(os.Stderr, "Error setting key: %v\n", err)
			os.Exit(1)
		}

		output, err = wpaCli("enable_network", networkId)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		if err := assertOK(output); err != nil {
			fmt.Fprintf(os.Stderr, "Error enabling network: %v\n", err)
			os.Exit(1)
		}

		output, err = wpaCli("save")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		if err := assertOK(output); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving configuration: %v\n", err)
			os.Exit(1)
		}

	case "scan":
		output, err := wpaCli("scan")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		if err := assertOK(output); err != nil {
			fmt.Fprintf(os.Stderr, "gError initiating scan: %v\n", err)
			os.Exit(1)
		}

		// Wait a moment for the scan to complete
		time.Sleep(2 * time.Second)

		output, err = wpaCli("scan_results")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		networks, err := parseScanResults(output)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing scan results: %v\n", err)
			os.Exit(1)
		}

		for _, network := range networks {
			if filterByOpen && network.isSecured {
				continue
			}

			networkIcon := "🔓"
			if network.isSecured {
				networkIcon = "🔑"
			}

			networkSignalIcon := "▓"
			if network.signalLevel < -40 {
				networkSignalIcon = "▒"
			}
			if network.signalLevel < -80 {
				networkSignalIcon = "░"
			}

			fmt.Println(network.shortCode, networkSignalIcon, networkIcon, network.ssid)
		}

	default:
		if len(command) > 0 {
			fmt.Printf("Invalid command: %s\n", command)
		}

		fmt.Println("wifi <command>")
		fmt.Println("     status    - Show current WiFi connection status")
		fmt.Println("     watch     - Monitor WiFi connection status changes")
		fmt.Println("     scan      - Scan for available WiFi networks")
		fmt.Println("     add       - Add a new WiFi network (SSID [password])")
		fmt.Println("     remove    - Remove a saved WiFi network (network_id)")
		fmt.Println("     list      - List saved WiFi networks")
		fmt.Println("     disable   - Disable a saved WiFi network (network_id)")
		fmt.Println("     enable    - Enable a saved WiFi network (network_id)")
		fmt.Println("     toggle    - Toggle enabled/disabled state (network_id)")
		fmt.Println("     disconnect- Disconnect and reconnect a network (network_id)")
		fmt.Println("")
		fmt.Println("Options:")
		fmt.Println("     --open    - Filter to show only open networks during scan")
	}
}
