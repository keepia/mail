package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/keepia/mail/internal/store"
)

func newSendAsCmd(o options) *cobra.Command {
	cmd := &cobra.Command{Use: "send-as", Short: "Grant, list, revoke and restore send-as rights"}
	cmd.AddCommand(newSendAsAddCmd(o), newSendAsListCmd(o), newSendAsSetCmd(o))
	return cmd
}

// sendAsArgs parses the mailbox and the address or @domain it may send as.
func sendAsArgs(args []string) (mailbox, as store.Address, err error) {
	if mailbox, err = parseAddress(args[0], false); err != nil {
		return
	}
	as, err = parseAddress(args[1], true)
	return
}

func newSendAsAddCmd(o options) *cobra.Command {
	return &cobra.Command{
		Use:   "add <local@domain> <local@domain | @domain>",
		Short: "Let a mailbox send as an address, or as any address of a domain, of its group",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			mailbox, as, err := sendAsArgs(args)
			if err != nil {
				return err
			}
			return withStore(cmd, o, func(st *store.Store) error {
				if _, err := st.CreateSendAs(cmd.Context(), mailbox, as); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%s may send as %s\n", mailbox, as)
				return nil
			})
		},
	}
}

func newSendAsListCmd(o options) *cobra.Command {
	var mailbox, group string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List the send-as grants",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var f store.SendAsFilter
			if cmd.Flags().Changed("mailbox") {
				m, err := parseAddress(mailbox, false)
				if err != nil {
					return err
				}
				f.Mailbox = m
			}
			g, err := optionalName(cmd, "group", group, parseGroup)
			if err != nil {
				return err
			}
			f.Group = g
			return withStore(cmd, o, func(st *store.Store) error {
				list, err := st.ListSendAs(cmd.Context(), f)
				if err != nil {
					return err
				}
				rows := make([][]string, 0, len(list))
				for _, s := range list {
					rows = append(rows, []string{s.Mailbox.String(), s.As.String(), yesNo(s.Active)})
				}
				return printTable(cmd, []string{"MAILBOX", "SEND AS", "ACTIVE"}, rows)
			})
		},
	}
	cmd.Flags().StringVar(&mailbox, "mailbox", "", "only the grants of this mailbox")
	cmd.Flags().StringVar(&group, "group", "", "only the grants of this group")
	return cmd
}

func newSendAsSetCmd(o options) *cobra.Command {
	var active bool
	cmd := &cobra.Command{
		Use:   "set <local@domain> <local@domain | @domain>",
		Short: "Revoke (--active=false) or restore (--active=true) a send-as grant",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			mailbox, as, err := sendAsArgs(args)
			if err != nil {
				return err
			}
			if err := needChange(cmd, "active"); err != nil {
				return err
			}
			return withStore(cmd, o, func(st *store.Store) error {
				if err := st.SetSendAsActive(cmd.Context(), mailbox, as, active); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "send-as %s %s updated\n", mailbox, as)
				return nil
			})
		},
	}
	cmd.Flags().BoolVar(&active, "active", true, "false revokes the grant, true restores it")
	return cmd
}
