package main

import (
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
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

type Network struct {
	bssid       string
	frequency   string
	signalLevel int
	flags       map[string]bool
	isSecured   bool
	ssid        string
}

func isNetworkSecured(flags map[string]bool) bool {
	return flags["WPA2-EAP-CCMP"] || flags["WPA2-PSK-CCMP"] || flags["WPA-PSK-CCMP+TKIP"]
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

		networks = append(networks, Network{
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

func main() {
	switch os.Args[1] {
	case "status":
		fmt.Print(wpaCli("status"))

	case "edit":

	case "restart":

	case "list":
		fmt.Print(wpaCli("list_networks"))

	case "disable":
		networkId := os.Args[2]
		fmt.Print(wpaCli("disable_network", networkId))

	case "enable":
		networkId := os.Args[2]
		fmt.Print(wpaCli("enable_network", networkId))

	case "remove":
		networkId := os.Args[2]
		fmt.Print(wpaCli("remove_network", networkId))

	case "join":
		networkId := lastLine(wpaCli("add_network"))

		ssid := os.Args[2]

		assertOK(
			wpaCli("set_network", networkId, "ssid", fmt.Sprintf("\\\"%s\\\"", ssid)))

		if len(os.Args) == 3 {
			assertOK(wpaCli("set_network", networkId, "key_mgmt", "NONE"))
		} else {
      psk := os.Args[3]
			assertOK(wpaCli("set_network", networkId, "psk", fmt.Sprintf("\\\"%s\\\"", psk)))
		}

		assertOK(wpaCli("enable_network", networkId))
		assertOK(wpaCli("save"))

	case "scan":
		assertOK(wpaCli("scan"))
		networks := parseScanResults(wpaCli("scan_results"))

		for i := range networks {
			network := networks[i]
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

			networkSsid := fmt.Sprintf("\u001B[45m%s\u001B[49m", network.ssid)

			fmt.Println(networkSignalIcon, networkIcon, networkSsid)
		}
	}
}