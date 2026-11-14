package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/keepia/mail/internal/store"
)

func newMailboxCmd(o options) *cobra.Command {
	cmd := &cobra.Command{Use: "mailbox", Short: "Add, list and change mailboxes"}
	cmd.AddCommand(newMailboxAddCmd(o), newMailboxListCmd(o), newMailboxSetCmd(o))
	return cmd
}

func newMailboxAddCmd(o options) *cobra.Command {
	var quota, gate string
	var imap, pop3, smtp bool
	cmd := &cobra.Command{
		Use:   "add <local@domain>",
		Short: "Add a mailbox, on the store that placement chooses or on --store",
		Long: "Add a mailbox. Its store is the eligible store (active, on a server that is not removed)\n" +
			"with the lowest sum of quotas (an unlimited mailbox counts as 10 GiB), then the fewest\n" +
			"mailboxes, then the gate name; --store names one instead. The password comes from\n" +
			"--password-stdin, a prompt without echo on a terminal, or --password-hash-stdin (import).",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			addr, err := parseAddress(args[0], false)
			if err != nil {
				return err
			}
			if !cmd.Flags().Changed("quota") {
				return usagef("mailbox add needs --quota (unlimited, or a size such as 5GiB)")
			}
			q, err := parseQuota(quota)
			if err != nil {
				return err
			}
			g, err := optionalName(cmd, "store", gate, parseHost)
			if err != nil {
				return err
			}
			pw, err := readPasswordInput(cmd, o, true)
			if err != nil {
				return err
			}
			return withStore(cmd, o, func(st *store.Store) error {
				m, err := st.AddMailbox(cmd.Context(), store.AddMailboxRequest{
					Address: addr, Password: pw.password, PasswordHash: pw.hash,
					QuotaBytes: q, IMAP: imap, POP3: pop3, SMTP: smtp, Store: g,
				})
				if err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "mailbox %s added on store %s\n", addr, m.Store)
				return nil
			})
		},
	}
	f := cmd.Flags()
	f.StringVar(&quota, "quota", "", "the quota: unlimited (or 0), bytes, or a number with KiB, MiB, GiB or TiB (required)")
	f.StringVar(&gate, "store", "", "the gate name of the store to use instead of placement")
	f.BoolVar(&imap, "imap", true, "IMAP login allowed")
	f.BoolVar(&pop3, "pop3", true, "POP3 login allowed")
	f.BoolVar(&smtp, "smtp", true, "SMTP submission allowed")
	addPasswordFlags(cmd)
	return cmd
}

func newMailboxListCmd(o options) *cobra.Command {
	var domain, group, gate string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List the mailboxes (the password hash's scheme only, never the hash)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			d, err := optionalName(cmd, "domain", domain, parseDomain)
			if err != nil {
				return err
			}
			g, err := optionalName(cmd, "group", group, parseGroup)
			if err != nil {
				return err
			}
			s, err := optionalName(cmd, "store", gate, parseHost)
			if err != nil {
				return err
			}
			return withStore(cmd, o, func(st *store.Store) error {
				list, err := st.ListMailboxes(cmd.Context(), store.MailboxFilter{Domain: d, Group: g, Store: s})
				if err != nil {
					return err
				}
				rows := make([][]string, 0, len(list))
				for _, m := range list {
					rows = append(rows, []string{
						m.Address.String(), m.Group, m.Store, formatQuota(m.QuotaBytes),
						yesNo(m.IMAP), yesNo(m.POP3), yesNo(m.SMTP), m.State, m.Scheme,
					})
				}
				return printTable(cmd, []string{"ADDRESS", "GROUP", "STORE", "QUOTA", "IMAP", "POP3", "SMTP", "STATE", "SCHEME"}, rows)
			})
		},
	}
	cmd.Flags().StringVar(&domain, "domain", "", "only the mailboxes of this domain")
	cmd.Flags().StringVar(&group, "group", "", "only the mailboxes of this group")
	cmd.Flags().StringVar(&gate, "store", "", "only the mailboxes on this store (gate name)")
	return cmd
}

func newMailboxSetCmd(o options) *cobra.Command {
	var quota, state string
	var imap, pop3, smtp bool
	cmd := &cobra.Command{
		Use:   "set <local@domain>",
		Short: "Change a mailbox's quota, protocols, state or password (its store never changes)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			addr, err := parseAddress(args[0], false)
			if err != nil {
				return err
			}
			f := cmd.Flags()
			var c store.MailboxChange
			if f.Changed("quota") {
				q, err := parseQuota(quota)
				if err != nil {
					return err
				}
				c.QuotaBytes = &q
			}
			for name, p := range map[string]**bool{"imap": &c.IMAP, "pop3": &c.POP3, "smtp": &c.SMTP} {
				if f.Changed(name) {
					v, _ := f.GetBool(name)
					*p = &v
				}
			}
			if f.Changed("state") {
				s, err := parseState(state)
				if err != nil {
					return err
				}
				c.State = &s
			}
			pw, err := readPasswordInput(cmd, o, false)
			if err != nil {
				return err
			}
			if pw.hash != "" {
				c.PasswordHash = &pw.hash
			}
			if c == (store.MailboxChange{}) && pw.password == "" {
				return usagef("%s needs at least one of --quota, --imap, --pop3, --smtp, --state, --%s, --%s",
					cmd.CommandPath(), flagPasswordStdin, flagPasswordHashStdin)
			}
			return withStore(cmd, o, func(st *store.Store) error {
				if pw.password != "" {
					err = st.SetMailboxPassword(cmd.Context(), addr, pw.password, c)
				} else {
					err = st.UpdateMailbox(cmd.Context(), addr, c)
				}
				if err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "mailbox %s updated\n", addr)
				return nil
			})
		},
	}
	f := cmd.Flags()
	f.StringVar(&quota, "quota", "", "the new quota: unlimited (or 0), bytes, or a number with KiB, MiB, GiB or TiB")
	f.BoolVar(&imap, "imap", true, "IMAP login allowed")
	f.BoolVar(&pop3, "pop3", true, "POP3 login allowed")
	f.BoolVar(&smtp, "smtp", true, "SMTP submission allowed")
	f.StringVar(&state, "state", "", "active, or disabled: no login, and mail is refused as for an unknown address")
	addPasswordFlags(cmd)
	return cmd
}
