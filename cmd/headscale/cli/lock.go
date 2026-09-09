package cli

import (
	"context"
	"fmt"
	"net/http"
	"strconv"

	clientv1 "github.com/juanfont/headscale/gen/client/v1"
	"github.com/pterm/pterm"
	"github.com/samber/lo"
	"github.com/spf13/cobra"
	"tailscale.com/types/key"
)

func init() {
	rootCmd.AddCommand(lockCmd)
	lockCmd.AddCommand(lockStatusCmd)

	lockNodesCmd.Flags().Bool("signed", false, "Show only signed nodes")
	lockNodesCmd.Flags().Bool("unsigned", false, "Show only unsigned nodes")
	lockNodesCmd.Flags().Bool("unauthorized", false, "Show only unauthorized nodes")
	lockCmd.AddCommand(lockNodesCmd)
}

var lockCmd = &cobra.Command{
	Use:     "lock",
	Short:   "View Tailnet Lock (TKA) status and node verification details",
	Aliases: []string{"tailnet-lock"},
}

var lockStatusCmd = &cobra.Command{
	Use:     "status",
	Short:   "Display the tailnet lock status, trusted keys, and node statistics",
	Aliases: []string{cmdShow},
	RunE: clientRunE(func(ctx context.Context, client *clientv1.ClientWithResponses, cmd *cobra.Command, args []string) error {
		resp, err := client.GetTailnetLockStatusWithResponse(ctx)
		if err != nil {
			return fmt.Errorf("getting tailnet lock status: %w", err)
		}

		if resp.StatusCode() != http.StatusOK {
			return apiError(resp.StatusCode(), resp.ApplicationproblemJSONDefault)
		}

		status := resp.JSON200

		format, _ := cmd.Flags().GetString("output")
		if format != "" {
			return printOutput(cmd, status, "")
		}

		if !status.ConfigEnabled {
			pterm.Println("Tailnet lock is disabled in the server configuration.")
			pterm.Println("To enable it, set 'tailnet_lock.enabled: true' in config.yaml and restart headscale.")
			return nil
		}

		statusStr := pterm.LightRed("Disabled")
		if status.Enabled {
			statusStr = pterm.LightGreen("Enabled")
		}

		headStr := "None"
		if status.Head != nil && *status.Head != "" {
			headStr = *status.Head
		}

		pterm.DefaultSection.Println("Tailnet Lock Status")
		pterm.Printf("  Status:                     %s\n", statusStr)
		pterm.Printf("  Head AUM Hash:              %s\n", headStr)
		if status.Enabled && status.DisablementSecretsCount > 0 {
			pterm.Printf("  Disablement Secrets:        %d configured\n", status.DisablementSecretsCount)
		}
		pterm.Printf("  Total Nodes:                %d\n", status.Summary.TotalNodes)
		pterm.Printf("  Signed Nodes:               %d\n", status.Summary.SignedNodes)
		pterm.Printf("  Authorized Nodes:           %d\n", status.Summary.AuthorizedNodes)
		pterm.Printf("  Unsigned Nodes:             %d\n", status.Summary.UnsignedNodes)

		if status.TrustedKeys != nil && len(*status.TrustedKeys) > 0 {
			pterm.Println()
			pterm.DefaultSection.Println("Trusted Signing Keys")

			header := []string{"#", "Key ID", "Public Key (TLK)", "Votes", "Kind"}
			rows := make([][]string, 0, len(*status.TrustedKeys))
			for i, k := range *status.TrustedKeys {
				rows = append(rows, []string{
					strconv.Itoa(i + 1),
					k.KeyId,
					k.PublicKey,
					strconv.FormatInt(k.Votes, 10),
					k.Kind,
				})
			}

			return renderTable(header, rows)
		}

		return nil
	}),
}

var lockNodesCmd = &cobra.Command{
	Use:     "nodes",
	Short:   "Display tailnet lock status and signature details for nodes",
	Aliases: []string{cmdList, "ls"},
	RunE: clientRunE(func(ctx context.Context, client *clientv1.ClientWithResponses, cmd *cobra.Command, args []string) error {
		onlySigned, _ := cmd.Flags().GetBool("signed")
		onlyUnsigned, _ := cmd.Flags().GetBool("unsigned")
		onlyUnauthorized, _ := cmd.Flags().GetBool("unauthorized")

		resp, err := client.GetTailnetLockNodesWithResponse(ctx)
		if err != nil {
			return fmt.Errorf("getting tailnet lock nodes: %w", err)
		}

		if resp.StatusCode() != http.StatusOK {
			return apiError(resp.StatusCode(), resp.ApplicationproblemJSONDefault)
		}

		var nodes []clientv1.TKANodeLockStatus
		if resp.JSON200.Nodes != nil {
			nodes = *resp.JSON200.Nodes
		}

		if onlySigned {
			nodes = lo.Filter(nodes, func(n clientv1.TKANodeLockStatus, _ int) bool {
				return n.Signed
			})
		}
		if onlyUnsigned {
			nodes = lo.Filter(nodes, func(n clientv1.TKANodeLockStatus, _ int) bool {
				return !n.Signed
			})
		}
		if onlyUnauthorized {
			nodes = lo.Filter(nodes, func(n clientv1.TKANodeLockStatus, _ int) bool {
				return !n.Authorized
			})
		}

		return printListOutput(cmd, nodes, func() error {
			header := []string{
				"ID",
				"Hostname",
				"Owner",
				"NodeKey",
				"Signed",
				"Authorized",
				"Signer Key ID",
			}

			rows := make([][]string, 0, len(nodes))
			for _, n := range nodes {
				var nodeKey key.NodePublic
				err := nodeKey.UnmarshalText([]byte(n.NodeKey))
				nodeKeyStr := n.NodeKey
				if err == nil {
					nodeKeyStr = nodeKey.ShortString()
				}

				signedStr := pterm.LightRed("no")
				if n.Signed {
					signedStr = pterm.LightGreen("yes")
				}

				authStr := pterm.LightRed("no")
				if n.Authorized {
					authStr = pterm.LightGreen("yes")
				}

				signerStr := "-"
				if n.SigningKeyId != nil && *n.SigningKeyId != "" {
					signerStr = *n.SigningKeyId
				}

				rows = append(rows, []string{
					n.Id,
					n.GivenName,
					n.Owner,
					nodeKeyStr,
					signedStr,
					authStr,
					signerStr,
				})
			}

			return renderTable(header, rows)
		})
	}),
}
