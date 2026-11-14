package main

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/keepia/mail/internal/store"
)

func newAliasCmd(o options) *cobra.Command {
	cmd := &cobra.Command{Use: "alias", Short: "Add, list and change aliases and catch-alls"}
	cmd.AddCommand(newAliasAddCmd(o), newAliasListCmd(o), newAliasSetCmd(o))
	return cmd
}

// parseTargets parses alias targets: mailbox addresses (CD8: no alias as a
// target, so no loops).
func parseTargets(values []string) ([]store.Address, error) {
	out := make([]store.Address, 0, len(values))
	for _, v := range values {
		a, err := parseAddress(v, false)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, nil
}

// checkTargetDomains refuses a target on an alias domain, with the
// mailbox address to give instead: a target is a mailbox, which lives on
// the domain itself.
func checkTargetDomains(ctx context.Context, st *store.Store, targets []store.Address) error {
	for _, t := range targets {
		d, ok, err := st.AliasDomainTarget(ctx, t.Domain)
		if err != nil {
			return err
		}
		if ok {
			return fmt.Errorf("target %s is on the alias domain %s: give the mailbox address %s@%s: %w",
				t, t.Domain, t.LocalPart, d, store.ErrRefused)
		}
	}
	return nil
}

func newAliasAddCmd(o options) *cobra.Command {
	var targets []string
	cmd := &cobra.Command{
		Use:   "add <local@domain | @domain>",
		Short: "Add an alias, or with @domain the domain's catch-all, delivering to mailboxes of its group",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			addr, err := parseAddress(args[0], true)
			if err != nil {
				return err
			}
			if len(targets) == 0 {
				return usagef("alias add needs at least one --target")
			}
			ts, err := parseTargets(targets)
			if err != nil {
				return err
			}
			return withStore(cmd, o, func(st *store.Store) error {
				if err := checkTargetDomains(cmd.Context(), st, ts); err != nil {
					return err
				}
				if _, err := st.CreateAlias(cmd.Context(), addr, ts); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "alias %s added (%d targets)\n", addr, len(ts))
				return nil
			})
		},
	}
	cmd.Flags().StringArrayVar(&targets, "target", nil, "a mailbox address to deliver to (repeatable, at least one)")
	return cmd
}

func newAliasListCmd(o options) *cobra.Command {
	var domain, group string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List the aliases with their targets",
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
				list, err := st.ListAliases(cmd.Context(), store.AliasFilter{Domain: d, Group: g})
				if err != nil {
					return err
				}
				rows := make([][]string, 0, len(list))
				for _, a := range list {
					ts := make([]string, 0, len(a.Targets))
					for _, t := range a.Targets {
						ts = append(ts, t.String())
					}
					slices.Sort(ts)
					rows = append(rows, []string{a.Address.String(), strings.Join(ts, ","), yesNo(a.Active)})
				}
				return printTable(cmd, []string{"ALIAS", "TARGETS", "ACTIVE"}, rows)
			})
		},
	}
	cmd.Flags().StringVar(&domain, "domain", "", "only the aliases of this domain")
	cmd.Flags().StringVar(&group, "group", "", "only the aliases of this group")
	return cmd
}

func newAliasSetCmd(o options) *cobra.Command {
	var add, remove []string
	var active bool
	cmd := &cobra.Command{
		Use:   "set <local@domain | @domain>",
		Short: "Add or remove an alias's targets, or switch it on or off",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			addr, err := parseAddress(args[0], true)
			if err != nil {
				return err
			}
			if err := needChange(cmd, "add-target", "remove-target", "active"); err != nil {
				return err
			}
			var c store.AliasChange
			if c.Add, err = parseTargets(add); err != nil {
				return err
			}
			if c.Remove, err = parseTargets(remove); err != nil {
				return err
			}
			if cmd.Flags().Changed("active") {
				c.Active = &active
			}
			return withStore(cmd, o, func(st *store.Store) error {
				if err := checkTargetDomains(cmd.Context(), st, c.Add); err != nil {
					return err
				}
				if err := st.UpdateAlias(cmd.Context(), addr, c); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "alias %s updated\n", addr)
				return nil
			})
		},
	}
	cmd.Flags().StringArrayVar(&add, "add-target", nil, "a mailbox address to add as a target (repeatable)")
	cmd.Flags().StringArrayVar(&remove, "remove-target", nil, "a target to remove (repeatable; the last one cannot be removed)")
	cmd.Flags().BoolVar(&active, "active", true, "whether the alias takes mail (--active=false switches it off)")
	return cmd
}
