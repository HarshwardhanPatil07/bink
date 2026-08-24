// SPDX-FileCopyrightText: 2026 The bink Authors
// SPDX-License-Identifier: Apache-2.0

package node

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/bootc-dev/bink/internal/config"
	"github.com/bootc-dev/bink/internal/podman"
)

func newListCmd() *cobra.Command {
	var showAll bool

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List cluster nodes",
		Long:  "List all cluster nodes and their status",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runList(cmd.Context(), showAll)
		},
	}

	cmd.Flags().BoolVarP(&showAll, "all", "a", false, "Show all nodes (including stopped)")

	return cmd
}

func runList(ctx context.Context, showAll bool) error {
	clusterName := viper.GetString("cluster.name")

	podmanClient, err := podman.NewClient()
	if err != nil {
		return fmt.Errorf("creating podman client: %w", err)
	}

	filter := config.LabelFilter(config.LabelClusterName, clusterName)
	containers, err := podmanClient.ContainerList(ctx, filter)
	if err != nil {
		return fmt.Errorf("listing containers: %w", err)
	}

	type nodeInfo struct {
		name, role, state, created string
	}
	var nodes []nodeInfo

	for _, containerName := range containers {
		if containerName == "" {
			continue
		}

		component, _ := podmanClient.ContainerInspect(ctx, containerName, config.LabelInspectFormat(config.LabelComponent))
		if strings.TrimSpace(component) != "" {
			continue
		}

		nodeName, err := podmanClient.ContainerInspect(ctx, containerName, config.LabelInspectFormat(config.LabelNodeName))
		if err != nil {
			continue
		}
		nodeName = strings.TrimSpace(nodeName)
		if nodeName == "" {
			continue
		}

		state, _ := podmanClient.ContainerInspect(ctx, containerName, "{{.State.Status}}")
		state = strings.TrimSpace(state)

		if !showAll && state != "running" {
			continue
		}

		nodeRole, _ := podmanClient.ContainerInspect(ctx, containerName, config.LabelInspectFormat(config.LabelNodeRole))
		nodeRole = strings.TrimSpace(nodeRole)

		created, err := podmanClient.ContainerInspect(ctx, containerName, "{{.Created}}")
		if err == nil {
			created = strings.TrimSpace(created)
			if len(created) > 19 {
				created = created[:19]
			}
		} else {
			created = "unknown"
		}

		nodes = append(nodes, nodeInfo{name: nodeName, role: nodeRole, state: state, created: created})
	}

	if len(nodes) == 0 {
		fmt.Println("No cluster nodes found")
		return nil
	}

	fmt.Printf("Found %d cluster node(s):\n\n", len(nodes))

	for _, n := range nodes {
		statusSymbol := "?"
		switch n.state {
		case "running":
			statusSymbol = "✓"
		case "exited":
			statusSymbol = "✗"
		case "paused":
			statusSymbol = "⏸"
		}

		if n.role != "" {
			fmt.Printf("  %s %s (role: %s, status: %s, created: %s)\n", statusSymbol, n.name, n.role, n.state, n.created)
		} else {
			fmt.Printf("  %s %s (status: %s, created: %s)\n", statusSymbol, n.name, n.state, n.created)
		}
	}

	fmt.Println()
	return nil
}
