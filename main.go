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
	wpaCliArgs := append([]string{"wpa_cli"}, args...)
	fmt.Println("» wpa_cli", strings.Join(args, " "))

	cmd := exec.Command("as-host", wpaCliArgs...)

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

		ssid := chunks[1]
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

		shortCode, err := getShortCode(chunks[4])
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
			ssid:        chunks[4],
		})
	}

	// Sort networks by signal level (strongest first)
	sort.Slice(networks, func(p, q int) bool {
		return networks[p].signalLevel > networks[q].signalLevel
	})

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
		fmt.Print(output)

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
				fmt.Print(status)
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
			fmt.Fprintf(os.Stderr, "Error initiating scan: %v\n", err)
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
