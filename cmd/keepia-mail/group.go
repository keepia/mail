package main

import (
	"fmt"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/keepia/mail/internal/store"
)

// The data-model commands (#95 part 2): group, domain, alias-domain,
// mailbox, alias and send-as, each with add, list and set. Every command
// checks its arguments, flags and stdin before it contacts the database
// (a usage error exits 64); each write is one transaction of the store API
// with its audit row.

// withStore opens the store and runs fn with it.
func withStore(cmd *cobra.Command, o options, fn func(st *store.Store) error) error {
	st, err := openDataStore(cmd, o)
	if err != nil {
		return err
	}
	defer st.Close()
	return fn(st)
}

// printTable prints an aligned table with a header line, as migrate
// status does; an empty table is its header alone. Columns are separated
// by two or more spaces.
func printTable(cmd *cobra.Command, header []string, rows [][]string) error {
	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, strings.Join(header, "\t"))
	for _, r := range rows {
		fmt.Fprintln(w, strings.Join(r, "\t"))
	}
	return w.Flush()
}

// yesNo is a boolean as the tables show it.
func yesNo(b bool) string { return strconv.FormatBool(b) }

// needChange is the usage error of a set without any change flag.
func needChange(cmd *cobra.Command, flags ...string) error {
	for _, f := range flags {
		if cmd.Flags().Changed(f) {
			return nil
		}
	}
	return usagef("%s needs at least one of --%s", cmd.CommandPath(), strings.Join(flags, ", --"))
}

func newGroupCmd(o options) *cobra.Command {
	cmd := &cobra.Command{Use: "group", Short: "Add, list and rename customer groups"}
	cmd.AddCommand(
		&cobra.Command{
			Use:   "add <name>",
			Short: "Add a customer group",
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				name, err := parseGroup(args[0])
				if err != nil {
					return err
				}
				return withStore(cmd, o, func(st *store.Store) error {
					if _, err := st.CreateGroup(cmd.Context(), name); err != nil {
						return err
					}
					fmt.Fprintf(cmd.OutOrStdout(), "group %s added\n", name)
					return nil
				})
			},
		},
		&cobra.Command{
			Use:   "list",
			Short: "List the customer groups with their number of domains",
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				return withStore(cmd, o, func(st *store.Store) error {
					groups, err := st.ListGroups(cmd.Context())
					if err != nil {
						return err
					}
					rows := make([][]string, 0, len(groups))
					for _, g := range groups {
						rows = append(rows, []string{g.Name, strconv.FormatInt(g.DomainCount, 10)})
					}
					return printTable(cmd, []string{"GROUP", "DOMAINS"}, rows)
				})
			},
		},
		newGroupSetCmd(o),
	)
	return cmd
}

func newGroupSetCmd(o options) *cobra.Command {
	var newName string
	cmd := &cobra.Command{
		Use:   "set <name>",
		Short: "Rename a customer group",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name, err := parseGroup(args[0])
			if err != nil {
				return err
			}
			if err := needChange(cmd, "name"); err != nil {
				return err
			}
			to, err := parseGroup(newName)
			if err != nil {
				return err
			}
			return withStore(cmd, o, func(st *store.Store) error {
				if err := st.RenameGroup(cmd.Context(), name, to); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "group %s updated\n", to)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&newName, "name", "", "the group's new name")
	return cmd
}
