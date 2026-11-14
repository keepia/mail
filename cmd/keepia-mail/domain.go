package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/keepia/mail/internal/store"
)

func newDomainCmd(o options) *cobra.Command {
	cmd := &cobra.Command{Use: "domain", Short: "Add, list and switch mail domains"}
	cmd.AddCommand(newDomainAddCmd(o), newDomainListCmd(o), newDomainSetCmd(o))
	return cmd
}

func newDomainAddCmd(o options) *cobra.Command {
	var group string
	cmd := &cobra.Command{
		Use:   "add <domain>",
		Short: "Add a mail domain to a customer group",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name, err := parseDomain(args[0])
			if err != nil {
				return err
			}
			if !cmd.Flags().Changed("group") {
				return usagef("domain add needs --group")
			}
			g, err := parseGroup(group)
			if err != nil {
				return err
			}
			return withStore(cmd, o, func(st *store.Store) error {
				if _, err := st.CreateDomain(cmd.Context(), name, g); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "domain %s added to group %s\n", name, g)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&group, "group", "", "the customer group (required; it never changes)")
	return cmd
}

func newDomainListCmd(o options) *cobra.Command {
	var group string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List the mail domains",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			g, err := optionalName(cmd, "group", group, parseGroup)
			if err != nil {
				return err
			}
			return withStore(cmd, o, func(st *store.Store) error {
				domains, err := st.ListDomains(cmd.Context(), g)
				if err != nil {
					return err
				}
				rows := make([][]string, 0, len(domains))
				for _, d := range domains {
					rows = append(rows, []string{d.Name, d.Group, yesNo(d.Active)})
				}
				return printTable(cmd, []string{"DOMAIN", "GROUP", "ACTIVE"}, rows)
			})
		},
	}
	cmd.Flags().StringVar(&group, "group", "", "only the domains of this group")
	return cmd
}

func newDomainSetCmd(o options) *cobra.Command {
	var active bool
	cmd := &cobra.Command{
		Use:   "set <domain>",
		Short: "Switch a mail domain on or off (its group never changes)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name, err := parseDomain(args[0])
			if err != nil {
				return err
			}
			if err := needChange(cmd, "active"); err != nil {
				return err
			}
			return withStore(cmd, o, func(st *store.Store) error {
				if err := st.SetDomainActive(cmd.Context(), name, active); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "domain %s updated\n", name)
				return nil
			})
		},
	}
	cmd.Flags().BoolVar(&active, "active", true, "whether the domain takes mail and logins (--active=false switches it off)")
	return cmd
}

// optionalName parses the value of a filter flag with parse, or returns
// "" when the flag was not given.
func optionalName(cmd *cobra.Command, flag, value string, parse func(string) (string, error)) (string, error) {
	if !cmd.Flags().Changed(flag) {
		return "", nil
	}
	return parse(value)
}

func newAliasDomainCmd(o options) *cobra.Command {
	cmd := &cobra.Command{Use: "alias-domain", Short: "Add, list and change alias domains"}
	cmd.AddCommand(newAliasDomainAddCmd(o), newAliasDomainListCmd(o), newAliasDomainSetCmd(o))
	return cmd
}

func newAliasDomainAddCmd(o options) *cobra.Command {
	var domain string
	cmd := &cobra.Command{
		Use:   "add <name>",
		Short: "Add an alias domain: l@<name> is l@<domain>",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name, err := parseDomain(args[0])
			if err != nil {
				return err
			}
			if !cmd.Flags().Changed("domain") {
				return usagef("alias-domain add needs --domain")
			}
			d, err := parseDomain(domain)
			if err != nil {
				return err
			}
			return withStore(cmd, o, func(st *store.Store) error {
				if _, err := st.CreateAliasDomain(cmd.Context(), name, d); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "alias domain %s added for %s\n", name, d)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&domain, "domain", "", "the domain it stands for (required)")
	return cmd
}

func newAliasDomainListCmd(o options) *cobra.Command {
	var domain, group string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List the alias domains",
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
			return withStore(cmd, o, func(st *store.Store) error {
				list, err := st.ListAliasDomains(cmd.Context(), store.AliasDomainFilter{Domain: d, Group: g})
				if err != nil {
					return err
				}
				rows := make([][]string, 0, len(list))
				for _, a := range list {
					rows = append(rows, []string{a.Name, a.Domain, a.Group, yesNo(a.Active)})
				}
				return printTable(cmd, []string{"ALIAS DOMAIN", "DOMAIN", "GROUP", "ACTIVE"}, rows)
			})
		},
	}
	cmd.Flags().StringVar(&domain, "domain", "", "only the alias domains of this domain")
	cmd.Flags().StringVar(&group, "group", "", "only the alias domains of this group")
	return cmd
}

func newAliasDomainSetCmd(o options) *cobra.Command {
	var domain string
	var active bool
	cmd := &cobra.Command{
		Use:   "set <name>",
		Short: "Point an alias domain to another domain of its group, or switch it on or off",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name, err := parseDomain(args[0])
			if err != nil {
				return err
			}
			if err := needChange(cmd, "domain", "active"); err != nil {
				return err
			}
			var c store.AliasDomainChange
			if cmd.Flags().Changed("domain") {
				d, err := parseDomain(domain)
				if err != nil {
					return err
				}
				c.Domain = &d
			}
			if cmd.Flags().Changed("active") {
				c.Active = &active
			}
			return withStore(cmd, o, func(st *store.Store) error {
				if err := st.UpdateAliasDomain(cmd.Context(), name, c); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "alias domain %s updated\n", name)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&domain, "domain", "", "the new domain it stands for, in the same group")
	cmd.Flags().BoolVar(&active, "active", true, "whether the alias domain takes mail (--active=false switches it off)")
	return cmd
}
