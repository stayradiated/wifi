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

func wpaCli(args ...string) string {
	wpaCliArgs := append([]string{"wpa_cli"}, args...)
	fmt.Println("» wpa_cli", strings.Join(args, " "))

	cmd := exec.Command("as-host", wpaCliArgs...)

	output, err := cmd.Output()
	if err != nil {
		panic(err)
	}

	return string(output)
}

func removeEmptyLines(input []string) []string {
	output := []string{}

	for i := range input {
		if len(strings.Trim(input[i], " ")) > 0 {
			output = append(output, input[i])
		}
	}

	return output
}

func lastLine(input string) string {
	lines := removeEmptyLines(strings.Split(input, "\n"))
	return lines[len(lines)-1]
}

func assertOK(input string) {
	line := lastLine(input)
	if line != "OK" {
		panic(line)
	}
}

func escapeString(input string) string {
	input = strings.ReplaceAll(input, "\\", "\\\\")
	input = strings.ReplaceAll(input, "'", "\\'")
	input = strings.ReplaceAll(input, "(", "\\(")
	input = strings.ReplaceAll(input, ")", "\\)")
	input = strings.ReplaceAll(input, "&", "\\&")
	return input
}

type SavedNetwork struct {
	networkId int
	ssid      string
	bssid     string
	flags     map[string]bool
}

func parseListNetworkResults(input string) []SavedNetwork {
	networks := []SavedNetwork{}
	lines := removeEmptyLines(strings.Split(input, "\n")[2:])
	for i := range lines {
		line := lines[i]
		chunks := strings.Split(line, "\t")
		flags := parseNetworkFlags(chunks[3])

		networkId, err := strconv.Atoi(chunks[0])
		if err != nil {
			panic(err)
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
	return networks
}

type Network struct {
	shortCode   string
	bssid       string
	frequency   string
	signalLevel int
	flags       map[string]bool
	isSecured   bool
	ssid        string
}

func isNetworkSecured(flags map[string]bool) bool {
	for key := range flags {
		if strings.HasPrefix(key, "WPA2-") || strings.HasPrefix(key, "WPA-") || strings.HasPrefix(key, "RSN-") {
			return true
		}
	}
	return false
}

func getShortCode(input string) (shortCode string, err error) {
	hash := sha256.New()
	if _, err = hash.Write([]byte(input)); err != nil {
		return "", err
	}
	shortCode = fmt.Sprintf("%x", hash.Sum(nil))[0:3]
	return shortCode, nil
}

func parseNetworkFlags(input string) map[string]bool {
	flagMap := map[string]bool{}
	list := strings.Split(strings.Trim(input, "[]"), "][")
	for i := range list {
		flag := list[i]
		flagMap[flag] = true
	}
	return flagMap
}

func parseScanResults(input string) []Network {
	networks := []Network{}
	lines := removeEmptyLines(strings.Split(input, "\n")[2:])
	for i := range lines {
		line := lines[i]
		chunks := strings.Split(line, "\t")
		flags := parseNetworkFlags(chunks[3])

		signalLevel, err := strconv.Atoi(chunks[2])
		if err != nil {
			panic(err)
		}

		shortCode, err := getShortCode(chunks[4])
		if err != nil {
			panic(err)
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
	sort.Slice(networks, func(p, q int) bool {
		return networks[p].signalLevel > networks[q].signalLevel
	})
	return networks
}

var isShortCodeRegExp = regexp.MustCompile("^[A-f0-9]{3}$")

func isShortCode(input string) bool {
	return isShortCodeRegExp.MatchString(input)
}
func resolveShortCode(shortCode string) (string, error) {
	networks := parseScanResults(wpaCli("scan_results"))
	for _, network := range networks {
		if network.shortCode == shortCode {
			return network.ssid, nil
		}
	}
	return "", errors.New("Could not resolve shortCode")
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
		fmt.Print(wpaCli("status"))

	case "watch":
		previousStatus := ""
		for {
			status := wpaCli("status")
			if status != previousStatus {
				fmt.Print(status)
			}
			previousStatus = status
			time.Sleep(1 * time.Second)
		}

	case "list":
		networkList := parseListNetworkResults(wpaCli("list_network"))
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

	case "disable":
		networkId := os.Args[2]
		fmt.Print(wpaCli("disable_network", networkId))

	case "enable":
		networkId := os.Args[2]
		fmt.Print(wpaCli("enable_network", networkId))

  case "disconnect":
    networkId := os.Args[2]
		fmt.Print(wpaCli("disable_network", networkId))
    time.Sleep(1 * time.Second)
		fmt.Print(wpaCli("enable_network", networkId))

	case "remove":
		networkId := os.Args[2]
		fmt.Print(wpaCli("remove_network", networkId))

	case "toggle":
		networkId := os.Args[2]
		networkList := parseListNetworkResults(wpaCli("list_network"))
		for _, network := range networkList {
			if strconv.Itoa(network.networkId) == networkId {
				if network.flags["DISABLED"] {
					fmt.Print(wpaCli("enable_network", networkId))
				} else {
					fmt.Print(wpaCli("disable_network", networkId))
				}
			}
		}

	case "add":
		networkId := lastLine(wpaCli("add_network"))

		ssid := os.Args[2]

		if isShortCode(ssid) {
			resolveddShortCode, err := resolveShortCode(ssid)
			if err != nil {
				panic(err)
			}
			ssid = resolveddShortCode
		}

		escapedSsid := escapeString(ssid)

		assertOK(
			wpaCli("set_network", networkId, "ssid", fmt.Sprintf("\\\"%s\\\"", escapedSsid)))

		if len(os.Args) == 3 {
			assertOK(wpaCli("set_network", networkId, "key_mgmt", "NONE"))
		} else {
			psk := escapeString(os.Args[3])
			assertOK(wpaCli("set_network", networkId, "psk", fmt.Sprintf("\\\"%s\\\"", psk)))
		}

		assertOK(wpaCli("enable_network", networkId))
		assertOK(wpaCli("save"))

	case "scan":
		assertOK(wpaCli("scan"))
		networks := parseScanResults(wpaCli("scan_results"))

		for i := range networks {
			network := networks[i]

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
		fmt.Println("     status")
		fmt.Println("     watch")
		fmt.Println("     scan")
		fmt.Println("     add")
		fmt.Println("     remove")
		fmt.Println("     list")
		fmt.Println("     disable")
		fmt.Println("     enable")
		fmt.Println("     toggle")
	}
}
