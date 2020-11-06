// Copyright 2020 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Binary check_docker_net_config returns an error if Docker is not configured
// for IPv6.
package main

import (
	"encoding/json"
	"fmt"
	"os"
)

const configPath = "/etc/docker/daemon.json"

func main() {
	// Open and parse the config.
	configFile, err := os.Open(configPath)
	if err != nil {
		fmt.Printf("Warning: unable to read Docker config file %q. Docker IPv6 may not be enabled: %v\n", configPath, err)
		return
	}
	var config map[string]interface{}
	if err := json.NewDecoder(configFile).Decode(&config); err != nil {
		fmt.Printf("Error: invalid Docker configuration file %q: %v\n", configPath, err)
		os.Exit(1)
	}

	// We don't do any complex validation - just check basic values and
	// assume Docker will complain if the CIDR value is bad.
	for _, field := range []string{"experimental", "ipv6", "fixed-cidr-v6"} {
		val, ok := config[field]
		if !ok {
			fmt.Printf("Error: Docker configuration %q must set field %q\n", configPath, field)
			os.Exit(1)
		}

		if val, ok := val.(bool); ok && !val {
			fmt.Printf("Error: Docker configuration %q must enable field %q\n", configPath, field)
			os.Exit(1)
		}
	}
}
