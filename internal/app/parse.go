package app

import (
	"strconv"
	"strings"

	"malox/internal/config"
)

type command int

const (
	commandRoot command = iota
	commandScan
	commandDiff
	commandRules
	commandRulesTest
	commandCache
	commandCacheUpdate
	commandCacheClean
	commandVersion
)

func (c command) String() string {
	switch c {
	case commandRoot:
		return "root"
	case commandScan:
		return "scan"
	case commandDiff:
		return "diff"
	case commandRules:
		return "rules"
	case commandRulesTest:
		return "rules test"
	case commandCache:
		return "cache"
	case commandCacheUpdate:
		return "cache update"
	case commandCacheClean:
		return "cache clean"
	case commandVersion:
		return "version"
	default:
		return "unknown"
	}
}

type invocation struct {
	command command
	help    bool
	version bool
	flags   config.FlagValues
}

func parseInvocation(args []string) (invocation, error) {
	inv := invocation{command: commandRoot}
	positionals := []string{}

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			positionals = append(positionals, args[i+1:]...)
			break
		}
		if !isFlag(arg) {
			positionals = append(positionals, arg)
			continue
		}

		name, value, hasValue, err := splitFlag(arg)
		if err != nil {
			return invocation{}, err
		}

		switch name {
		case "h", "help":
			v, err := parseBoolFlag(name, value, hasValue)
			if err != nil {
				return invocation{}, err
			}
			inv.help = v
		case "version":
			v, err := parseBoolFlag(name, value, hasValue)
			if err != nil {
				return invocation{}, err
			}
			inv.version = v
		case "config":
			v, next, err := parseStringFlag(name, value, hasValue, args, i)
			if err != nil {
				return invocation{}, err
			}
			inv.flags.ConfigPath = &v
			i = next
		case "state-dir":
			v, next, err := parseStringFlag(name, value, hasValue, args, i)
			if err != nil {
				return invocation{}, err
			}
			inv.flags.StateDir = &v
			i = next
		case "cache-dir":
			v, next, err := parseStringFlag(name, value, hasValue, args, i)
			if err != nil {
				return invocation{}, err
			}
			inv.flags.CacheDir = &v
			i = next
		case "offline":
			v, err := parseBoolFlag(name, value, hasValue)
			if err != nil {
				return invocation{}, err
			}
			inv.flags.Offline = &v
		case "no-color":
			v, err := parseBoolFlag(name, value, hasValue)
			if err != nil {
				return invocation{}, err
			}
			inv.flags.NoColor = &v
		case "quiet":
			v, err := parseBoolFlag(name, value, hasValue)
			if err != nil {
				return invocation{}, err
			}
			inv.flags.Quiet = &v
		case "verbose":
			v, err := parseBoolFlag(name, value, hasValue)
			if err != nil {
				return invocation{}, err
			}
			inv.flags.Verbose = &v
		case "root":
			v, next, err := parseStringFlag(name, value, hasValue, args, i)
			if err != nil {
				return invocation{}, err
			}
			inv.flags.Scan.Root = &v
			i = next
		case "json":
			v, err := parseBoolFlag(name, value, hasValue)
			if err != nil {
				return invocation{}, err
			}
			inv.flags.Scan.JSON = &v
			inv.flags.Diff.JSON = &v
			inv.flags.Cache.JSON = &v
			inv.flags.Rules.Test.JSON = &v
		case "source":
			v, next, err := parseStringFlag(name, value, hasValue, args, i)
			if err != nil {
				return invocation{}, err
			}
			inv.flags.Cache.Source = &v
			i = next
		case "output":
			v, next, err := parseStringFlag(name, value, hasValue, args, i)
			if err != nil {
				return invocation{}, err
			}
			inv.flags.Scan.Output = &v
			i = next
		case "strict-hash":
			v, err := parseBoolFlag(name, value, hasValue)
			if err != nil {
				return invocation{}, err
			}
			inv.flags.Scan.StrictHash = &v
		case "max-workers":
			v, next, err := parseIntFlag(name, value, hasValue, args, i)
			if err != nil {
				return invocation{}, err
			}
			inv.flags.Scan.MaxWorkers = &v
			i = next
		case "max-file-size":
			v, next, err := parseInt64Flag(name, value, hasValue, args, i)
			if err != nil {
				return invocation{}, err
			}
			inv.flags.Scan.MaxFileSize = &v
			i = next
		case "from":
			v, next, err := parseStringFlag(name, value, hasValue, args, i)
			if err != nil {
				return invocation{}, err
			}
			inv.flags.Diff.From = &v
			i = next
		case "to":
			v, next, err := parseStringFlag(name, value, hasValue, args, i)
			if err != nil {
				return invocation{}, err
			}
			inv.flags.Diff.To = &v
			i = next
		case "policy":
			v, next, err := parseStringFlag(name, value, hasValue, args, i)
			if err != nil {
				return invocation{}, err
			}
			inv.flags.Rules.PolicyFiles = append(inv.flags.Rules.PolicyFiles, v)
			i = next
		case "no-builtin-rules":
			v, err := parseBoolFlag(name, value, hasValue)
			if err != nil {
				return invocation{}, err
			}
			useBuiltins := !v
			inv.flags.Rules.UseBuiltins = &useBuiltins
		case "fixture":
			v, next, err := parseStringFlag(name, value, hasValue, args, i)
			if err != nil {
				return invocation{}, err
			}
			inv.flags.Rules.Test.Fixture = &v
			i = next
		case "expect-findings":
			v, next, err := parseIntFlag(name, value, hasValue, args, i)
			if err != nil {
				return invocation{}, err
			}
			inv.flags.Rules.Test.ExpectedFindings = &v
			i = next
		case "expired":
			v, err := parseBoolFlag(name, value, hasValue)
			if err != nil {
				return invocation{}, err
			}
			inv.flags.Cache.Clean.Expired = &v
		case "all":
			v, err := parseBoolFlag(name, value, hasValue)
			if err != nil {
				return invocation{}, err
			}
			inv.flags.Cache.Clean.All = &v
		case "force":
			v, err := parseBoolFlag(name, value, hasValue)
			if err != nil {
				return invocation{}, err
			}
			inv.flags.Cache.Clean.Force = &v
		default:
			return invocation{}, usageError("unknown flag --%s", name)
		}
	}

	command, err := resolveCommand(positionals)
	if err != nil {
		return invocation{}, err
	}
	inv.command = command
	switch inv.command {
	case commandScan:
		inv.flags.Diff.JSON = nil
		inv.flags.Cache.JSON = nil
		inv.flags.Rules.Test.JSON = nil
	case commandDiff:
		inv.flags.Scan.JSON = nil
		inv.flags.Cache.JSON = nil
		inv.flags.Rules.Test.JSON = nil
	case commandRulesTest:
		inv.flags.Scan.JSON = nil
		inv.flags.Diff.JSON = nil
		inv.flags.Cache.JSON = nil
		if len(positionals) == 3 {
			inv.flags.Rules.Test.RuleFile = &positionals[2]
		}
	case commandCacheUpdate, commandCacheClean:
		inv.flags.Scan.JSON = nil
		inv.flags.Diff.JSON = nil
		inv.flags.Rules.Test.JSON = nil
	}

	if err := validateFlagScope(inv); err != nil {
		return invocation{}, err
	}
	if err := validateCommandCompleteness(inv); err != nil {
		return invocation{}, err
	}

	return inv, nil
}

func isFlag(arg string) bool {
	return strings.HasPrefix(arg, "-") && arg != "-"
}

func splitFlag(arg string) (name string, value string, hasValue bool, err error) {
	if strings.HasPrefix(arg, "--") {
		trimmed := strings.TrimPrefix(arg, "--")
		if trimmed == "" {
			return "", "", false, usageError("empty flag")
		}
		name, value, hasValue = strings.Cut(trimmed, "=")
		return name, value, hasValue, nil
	}
	if arg == "-h" {
		return "h", "", false, nil
	}
	return "", "", false, usageError("unknown shorthand flag %q", arg)
}

func parseStringFlag(
	name string,
	value string,
	hasValue bool,
	args []string,
	index int,
) (string, int, error) {
	if hasValue {
		if value == "" {
			return "", index, usageError("--%s requires a value", name)
		}
		return value, index, nil
	}
	next := index + 1
	if next >= len(args) || isFlag(args[next]) {
		return "", index, usageError("--%s requires a value", name)
	}
	return args[next], next, nil
}

func parseBoolFlag(name, value string, hasValue bool) (bool, error) {
	if !hasValue {
		return true, nil
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, usageError("--%s expects true or false", name)
	}
	return parsed, nil
}

func parseIntFlag(
	name string,
	value string,
	hasValue bool,
	args []string,
	index int,
) (int, int, error) {
	raw, next, err := parseStringFlag(name, value, hasValue, args, index)
	if err != nil {
		return 0, index, err
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil {
		return 0, index, usageError("--%s expects an integer", name)
	}
	return parsed, next, nil
}

func parseInt64Flag(
	name string,
	value string,
	hasValue bool,
	args []string,
	index int,
) (int64, int, error) {
	raw, next, err := parseStringFlag(name, value, hasValue, args, index)
	if err != nil {
		return 0, index, err
	}
	parsed, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, index, usageError("--%s expects an integer", name)
	}
	return parsed, next, nil
}

func resolveCommand(positionals []string) (command, error) {
	if len(positionals) == 0 {
		return commandRoot, nil
	}

	switch positionals[0] {
	case "scan":
		if len(positionals) != 1 {
			return commandRoot, usageError("scan does not accept positional arguments")
		}
		return commandScan, nil
	case "diff":
		if len(positionals) != 1 {
			return commandRoot, usageError("diff does not accept positional arguments")
		}
		return commandDiff, nil
	case "rules":
		if len(positionals) == 1 {
			return commandRules, nil
		}
		if (len(positionals) == 2 || len(positionals) == 3) && positionals[1] == "test" {
			return commandRulesTest, nil
		}
		return commandRoot, usageError("unknown rules subcommand %q", strings.Join(positionals[1:], " "))
	case "cache":
		if len(positionals) == 1 {
			return commandCache, nil
		}
		if len(positionals) == 2 {
			switch positionals[1] {
			case "update":
				return commandCacheUpdate, nil
			case "clean":
				return commandCacheClean, nil
			}
		}
		return commandRoot, usageError("unknown cache subcommand %q", strings.Join(positionals[1:], " "))
	case "version":
		if len(positionals) != 1 {
			return commandRoot, usageError("version does not accept positional arguments")
		}
		return commandVersion, nil
	default:
		return commandRoot, usageError("unknown command %q", positionals[0])
	}
}

func validateFlagScope(inv invocation) error {
	if err := validateCacheFlagScope(inv); err != nil {
		return err
	}
	if inv.command == commandScan {
		if inv.flags.Diff.From != nil {
			return usageError("--from is only valid for diff")
		}
		if inv.flags.Diff.To != nil {
			return usageError("--to is only valid for diff")
		}
		if inv.flags.Rules.Test.Fixture != nil {
			return usageError("--fixture is only valid for rules test")
		}
		if inv.flags.Rules.Test.ExpectedFindings != nil {
			return usageError("--expect-findings is only valid for rules test")
		}
		return nil
	}
	if inv.command == commandDiff {
		if inv.flags.Scan.Root != nil {
			return usageError("--root is only valid for scan")
		}
		if inv.flags.Scan.Output != nil {
			return usageError("--output is only valid for scan")
		}
		if inv.flags.Scan.StrictHash != nil {
			return usageError("--strict-hash is only valid for scan")
		}
		if inv.flags.Scan.MaxWorkers != nil {
			return usageError("--max-workers is only valid for scan")
		}
		if inv.flags.Scan.MaxFileSize != nil {
			return usageError("--max-file-size is only valid for scan")
		}
		if inv.flags.Rules.Test.Fixture != nil {
			return usageError("--fixture is only valid for rules test")
		}
		if inv.flags.Rules.Test.ExpectedFindings != nil {
			return usageError("--expect-findings is only valid for rules test")
		}
		return nil
	}
	if inv.command == commandRulesTest {
		if inv.flags.Scan.Root != nil {
			return usageError("--root is only valid for scan")
		}
		if inv.flags.Scan.Output != nil {
			return usageError("--output is only valid for scan")
		}
		if inv.flags.Scan.StrictHash != nil {
			return usageError("--strict-hash is only valid for scan")
		}
		if inv.flags.Scan.MaxWorkers != nil {
			return usageError("--max-workers is only valid for scan")
		}
		if inv.flags.Scan.MaxFileSize != nil {
			return usageError("--max-file-size is only valid for scan")
		}
		if inv.flags.Diff.From != nil {
			return usageError("--from is only valid for diff")
		}
		if inv.flags.Diff.To != nil {
			return usageError("--to is only valid for diff")
		}
		return nil
	}
	if inv.flags.Scan.Root != nil {
		return usageError("--root is only valid for scan")
	}
	if inv.flags.Scan.JSON != nil {
		return usageError("--json is only valid for scan, diff, or rules test")
	}
	if inv.flags.Scan.Output != nil {
		return usageError("--output is only valid for scan")
	}
	if inv.flags.Scan.StrictHash != nil {
		return usageError("--strict-hash is only valid for scan")
	}
	if inv.flags.Scan.MaxWorkers != nil {
		return usageError("--max-workers is only valid for scan")
	}
	if inv.flags.Scan.MaxFileSize != nil {
		return usageError("--max-file-size is only valid for scan")
	}
	if inv.flags.Diff.From != nil {
		return usageError("--from is only valid for diff")
	}
	if inv.flags.Diff.To != nil {
		return usageError("--to is only valid for diff")
	}
	if inv.flags.Rules.Test.Fixture != nil {
		return usageError("--fixture is only valid for rules test")
	}
	if inv.flags.Rules.Test.ExpectedFindings != nil {
		return usageError("--expect-findings is only valid for rules test")
	}
	return nil
}

func validateCacheFlagScope(inv invocation) error {
	cacheCommand := inv.command == commandCacheUpdate || inv.command == commandCacheClean
	if inv.flags.Cache.JSON != nil && !cacheCommand {
		return usageError("--json is only valid for scan, diff, rules test, or cache commands")
	}
	if inv.flags.Cache.Source != nil && inv.command != commandCacheUpdate {
		return usageError("--source is only valid for cache update")
	}

	cleanCommand := inv.command == commandCacheClean
	if inv.flags.Cache.Clean.Expired != nil && !cleanCommand {
		return usageError("--expired is only valid for cache clean")
	}
	if inv.flags.Cache.Clean.All != nil && !cleanCommand {
		return usageError("--all is only valid for cache clean")
	}
	if inv.flags.Cache.Clean.Force != nil && !cleanCommand {
		return usageError("--force is only valid for cache clean")
	}
	return nil
}

func validateCommandCompleteness(inv invocation) error {
	if inv.help || inv.version {
		return nil
	}
	switch inv.command {
	case commandRoot:
		return nil
	case commandRules:
		return usageError("rules requires a subcommand: test")
	case commandRulesTest:
		if inv.flags.Rules.Test.RuleFile == nil {
			return usageError("rules test requires a rule file")
		}
		if inv.flags.Rules.Test.Fixture == nil {
			return usageError("rules test requires --fixture")
		}
		return nil
	case commandCache:
		return usageError("cache requires a subcommand: update or clean")
	default:
		return nil
	}
}
