// Package config loads and validates typed Malox application configuration.
package config

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"malox/internal/platform"
	"malox/internal/report"
)

const defaultMaxFileSize = 10 * 1024 * 1024
const stateDirEnv = "MALOX_PROJECT_STATE_DIR"

// Values contains all typed configuration needed by the app boundary.
type Values struct {
	ConfigPath string
	StateDir   string
	CacheDir   string
	Offline    bool
	NoColor    bool
	Quiet      bool
	Verbose    bool
	Scan       Scan
	Diff       Diff
	Cache      Cache
	Rules      Rules
	Threat     Threat
}

// Scan contains configuration for the scan command.
type Scan struct {
	Root        string
	Output      report.Format
	StrictHash  bool
	MaxWorkers  int
	MaxFileSize int64
}

// Diff contains configuration for the diff command.
type Diff struct {
	From   string
	To     string
	Output report.Format
}

// Cache contains configuration for cache management commands.
type Cache struct {
	Output report.Format
	Source string
	Clean  CacheClean
}

// Threat contains configured threat-intelligence source settings.
type Threat struct {
	Sources         []string
	RequiredSources []string
	OSVURL          string
	NPMRegistryURL  string
}

// CacheClean contains configuration for malox cache clean.
type CacheClean struct {
	Expired bool
	All     bool
	Force   bool
}

// Rules contains local policy configuration.
type Rules struct {
	PolicyFiles []string
	UseBuiltins bool
	Test        RulesTest
}

// RulesTest contains configuration for malox rules test.
type RulesTest struct {
	RuleFile         string
	Fixture          string
	Output           report.Format
	ExpectedFindings *int
}

// FlagValues contains optional values parsed from CLI flags.
type FlagValues struct {
	ConfigPath *string
	StateDir   *string
	CacheDir   *string
	Offline    *bool
	NoColor    *bool
	Quiet      *bool
	Verbose    *bool
	Scan       ScanFlags
	Diff       DiffFlags
	Cache      CacheFlags
	Rules      RulesFlags
}

// ScanFlags contains optional scan values parsed from CLI flags.
type ScanFlags struct {
	Root        *string
	JSON        *bool
	Output      *string
	StrictHash  *bool
	MaxWorkers  *int
	MaxFileSize *int64
}

// DiffFlags contains optional diff values parsed from CLI flags.
type DiffFlags struct {
	From *string
	To   *string
	JSON *bool
}

// CacheFlags contains optional cache values parsed from CLI flags.
type CacheFlags struct {
	JSON   *bool
	Source *string
	Clean  CacheCleanFlags
}

// CacheCleanFlags contains optional cache clean values parsed from CLI flags.
type CacheCleanFlags struct {
	Expired *bool
	All     *bool
	Force   *bool
}

// RulesFlags contains optional rules values parsed from CLI flags.
type RulesFlags struct {
	PolicyFiles []string
	UseBuiltins *bool
	Test        RulesTestFlags
}

// RulesTestFlags contains optional rules test values parsed from CLI flags.
type RulesTestFlags struct {
	RuleFile         *string
	Fixture          *string
	JSON             *bool
	ExpectedFindings *int
}

// LoadOptions describes how Load should resolve configuration.
type LoadOptions struct {
	Flags   FlagValues
	WorkDir string
}

// ValidationError reports all user-actionable configuration problems at once.
type ValidationError struct {
	Problems []string
}

// Error returns a compact validation error summary.
func (e *ValidationError) Error() string {
	return "configuration error: " + strings.Join(e.Problems, "; ")
}

// AsValidationError unwraps err into a ValidationError when possible.
func AsValidationError(err error) (*ValidationError, bool) {
	var validationErr *ValidationError
	if errors.As(err, &validationErr) {
		return validationErr, true
	}
	return nil, false
}

// Load reads optional file configuration, applies CLI flags, and validates the result.
func Load(ctx context.Context, opts LoadOptions) (Values, error) {
	if err := ctx.Err(); err != nil {
		return Values{}, fmt.Errorf("load config: %w", err)
	}

	workDir, err := resolveWorkDir(opts.WorkDir)
	if err != nil {
		return Values{}, err
	}

	values := Values{
		Scan: Scan{
			Root:        workDir,
			Output:      report.FormatTable,
			MaxWorkers:  max(1, runtime.GOMAXPROCS(0)),
			MaxFileSize: defaultMaxFileSize,
		},
		Diff: Diff{
			Output: report.FormatTable,
		},
		Cache: Cache{
			Output: report.FormatTable,
		},
		Rules: Rules{
			UseBuiltins: true,
			Test: RulesTest{
				Output: report.FormatTable,
			},
		},
		Threat: Threat{
			Sources: []string{"local-policy"},
		},
	}

	var problems []string
	var outputExplicit bool
	var jsonRequested bool
	if opts.Flags.ConfigPath != nil {
		values.ConfigPath = *opts.Flags.ConfigPath
	}
	if values.ConfigPath != "" {
		resolved, err := platform.ResolvePath(workDir, values.ConfigPath)
		if err != nil {
			return Values{}, fmt.Errorf("resolve config path: %w", err)
		}
		values.ConfigPath = resolved

		fileValues, err := readFile(values.ConfigPath)
		if err != nil {
			return Values{}, fmt.Errorf("load config file %q: %w", values.ConfigPath, err)
		}
		if fileValues.Scan != nil && fileValues.Scan.Output != nil {
			outputExplicit = true
		}
		problems = append(problems, applyFile(workDir, &values, fileValues)...)
	}

	problems = append(problems, applyEnv(workDir, &values)...)
	problems = append(problems, applyFlags(workDir, &values, opts.Flags, &outputExplicit, &jsonRequested)...)
	if jsonRequested && outputExplicit && values.Scan.Output != report.FormatJSON {
		problems = append(problems, "--json cannot be combined with --output "+values.Scan.Output.String())
	}
	if jsonRequested {
		values.Scan.Output = report.FormatJSON
	}

	if values.StateDir == "" {
		values.StateDir = platform.DefaultStateDir(values.Scan.Root)
	}
	if values.CacheDir == "" {
		cacheDir, err := platform.DefaultCacheDir()
		if err != nil {
			return Values{}, err
		}
		values.CacheDir = cacheDir
	}

	problems = append(problems, values.validationProblems()...)
	if len(problems) > 0 {
		return Values{}, &ValidationError{Problems: problems}
	}

	return values, nil
}

func resolveWorkDir(workDir string) (string, error) {
	if workDir != "" {
		return filepath.Clean(workDir), nil
	}
	wd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("find working directory: %w", err)
	}
	return wd, nil
}

func applyFlags(
	workDir string,
	values *Values,
	flags FlagValues,
	outputExplicit *bool,
	jsonRequested *bool,
) []string {
	var problems []string

	applyPath := func(name string, input *string, target *string) {
		if input == nil {
			return
		}
		if strings.TrimSpace(*input) == "" {
			*target = ""
			problems = append(problems, requiredPathProblem(name))
			return
		}
		resolved, err := platform.ResolvePath(workDir, *input)
		if err != nil {
			problems = append(problems, fmt.Sprintf("resolve %s: %v", name, err))
			return
		}
		*target = resolved
	}

	applyPath("--state-dir", flags.StateDir, &values.StateDir)
	applyPath("--cache-dir", flags.CacheDir, &values.CacheDir)
	applyPath("--root", flags.Scan.Root, &values.Scan.Root)

	if flags.Offline != nil {
		values.Offline = *flags.Offline
	}
	if flags.NoColor != nil {
		values.NoColor = *flags.NoColor
	}
	if flags.Quiet != nil {
		values.Quiet = *flags.Quiet
	}
	if flags.Verbose != nil {
		values.Verbose = *flags.Verbose
	}
	if flags.Scan.StrictHash != nil {
		values.Scan.StrictHash = *flags.Scan.StrictHash
	}
	if flags.Scan.MaxWorkers != nil {
		values.Scan.MaxWorkers = *flags.Scan.MaxWorkers
	}
	if flags.Scan.MaxFileSize != nil {
		values.Scan.MaxFileSize = *flags.Scan.MaxFileSize
	}
	if flags.Scan.Output != nil {
		*outputExplicit = true
		format, err := report.ParseFormat(*flags.Scan.Output)
		if err != nil {
			problems = append(problems, err.Error())
		} else {
			values.Scan.Output = format
		}
	}
	if flags.Scan.JSON != nil && *flags.Scan.JSON {
		*jsonRequested = true
	}
	if flags.Diff.From != nil {
		values.Diff.From = *flags.Diff.From
	}
	if flags.Diff.To != nil {
		values.Diff.To = *flags.Diff.To
	}
	if flags.Diff.JSON != nil && *flags.Diff.JSON {
		values.Diff.Output = report.FormatJSON
	}
	if flags.Cache.JSON != nil && *flags.Cache.JSON {
		values.Cache.Output = report.FormatJSON
	}
	if flags.Cache.Source != nil {
		values.Cache.Source = strings.TrimSpace(*flags.Cache.Source)
	}
	if flags.Cache.Clean.Expired != nil {
		values.Cache.Clean.Expired = *flags.Cache.Clean.Expired
	}
	if flags.Cache.Clean.All != nil {
		values.Cache.Clean.All = *flags.Cache.Clean.All
	}
	if flags.Cache.Clean.Force != nil {
		values.Cache.Clean.Force = *flags.Cache.Clean.Force
	}
	for _, path := range flags.Rules.PolicyFiles {
		applyPolicyPath(workDir, path, &values.Rules.PolicyFiles, &problems)
	}
	if flags.Rules.UseBuiltins != nil {
		values.Rules.UseBuiltins = *flags.Rules.UseBuiltins
	}
	applyPath("--rules-test-file", flags.Rules.Test.RuleFile, &values.Rules.Test.RuleFile)
	applyPath("--fixture", flags.Rules.Test.Fixture, &values.Rules.Test.Fixture)
	if flags.Rules.Test.JSON != nil && *flags.Rules.Test.JSON {
		values.Rules.Test.Output = report.FormatJSON
	}
	if flags.Rules.Test.ExpectedFindings != nil {
		values.Rules.Test.ExpectedFindings = flags.Rules.Test.ExpectedFindings
	}

	return problems
}

func applyEnv(workDir string, values *Values) []string {
	raw, ok := os.LookupEnv(stateDirEnv)
	if !ok {
		return nil
	}
	if strings.TrimSpace(raw) == "" {
		values.StateDir = ""
		return []string{stateDirEnv + " is required"}
	}
	resolved, err := platform.ResolvePath(workDir, raw)
	if err != nil {
		return []string{fmt.Sprintf("resolve %s: %v", stateDirEnv, err)}
	}
	values.StateDir = resolved
	return nil
}

func (v Values) validationProblems() []string {
	problems := []string{}
	if strings.TrimSpace(v.ConfigPath) == "" && v.ConfigPath != "" {
		problems = append(problems, "config path cannot be blank")
	}
	if strings.TrimSpace(v.StateDir) == "" {
		problems = append(problems, "state dir is required")
	}
	if strings.TrimSpace(v.CacheDir) == "" {
		problems = append(problems, "cache dir is required")
	}
	if v.Quiet && v.Verbose {
		problems = append(problems, "--quiet and --verbose cannot both be set")
	}
	problems = append(problems, v.Scan.validationProblems()...)
	problems = append(problems, v.Diff.validationProblems()...)
	problems = append(problems, v.Cache.validationProblems()...)
	problems = append(problems, v.Rules.validationProblems()...)
	problems = append(problems, v.Threat.validationProblems()...)
	return problems
}

func (s Scan) validationProblems() []string {
	problems := []string{}
	if strings.TrimSpace(s.Root) == "" {
		problems = append(problems, "scan root is required")
	} else if info, err := os.Stat(s.Root); err != nil {
		problems = append(problems, fmt.Sprintf("scan root %q is not accessible: %v", s.Root, err))
	} else if !info.IsDir() {
		problems = append(problems, fmt.Sprintf("scan root %q must be a directory", s.Root))
	}
	if !s.Output.Valid() {
		problems = append(problems, "scan output must be one of table, json, or plain")
	}
	if s.MaxWorkers < 1 {
		problems = append(problems, "max workers must be greater than 0")
	}
	if s.MaxFileSize < 1 {
		problems = append(problems, "max file size must be greater than 0")
	}
	return problems
}

func (d Diff) validationProblems() []string {
	problems := []string{}
	if (d.From == "") != (d.To == "") {
		problems = append(problems, "--from and --to must be provided together")
	}
	if !d.Output.Valid() {
		problems = append(problems, "diff output must be one of table, json, or plain")
	}
	return problems
}

func (c Cache) validationProblems() []string {
	problems := []string{}
	if !c.Output.Valid() {
		problems = append(problems, "cache output must be one of table, json, or plain")
	}
	if c.Clean.Expired && c.Clean.All {
		problems = append(problems, "--expired and --all cannot both be set")
	}
	return problems
}

func (r Rules) validationProblems() []string {
	problems := []string{}
	if !r.Test.Output.Valid() {
		problems = append(problems, "rules test output must be one of table, json, or plain")
	}
	return problems
}

type fileConfig struct {
	StateDir *string           `json:"state_dir"`
	CacheDir *string           `json:"cache_dir"`
	Offline  *bool             `json:"offline"`
	NoColor  *bool             `json:"no_color"`
	Quiet    *bool             `json:"quiet"`
	Verbose  *bool             `json:"verbose"`
	Scan     *fileScanConfig   `json:"scan"`
	Rules    *fileRulesConfig  `json:"rules"`
	Threat   *fileThreatConfig `json:"threat"`
}

type fileScanConfig struct {
	Root        *string `json:"root"`
	JSON        *bool   `json:"json"`
	Output      *string `json:"output"`
	StrictHash  *bool   `json:"strict_hash"`
	MaxWorkers  *int    `json:"max_workers"`
	MaxFileSize *int64  `json:"max_file_size"`
}

type fileRulesConfig struct {
	PolicyFiles []string `json:"policy_files"`
	UseBuiltins *bool    `json:"use_builtins"`
}

type fileThreatConfig struct {
	Sources         []string `json:"sources"`
	RequiredSources []string `json:"required_sources"`
	OSVURL          *string  `json:"osv_url"`
	NPMRegistryURL  *string  `json:"npm_registry_url"`
}

func readFile(path string) (fileConfig, error) {
	f, err := os.Open(path)
	if err != nil {
		return fileConfig{}, err
	}
	defer f.Close()

	var cfg fileConfig
	decoder := json.NewDecoder(f)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return fileConfig{}, err
	}
	return cfg, nil
}

func requiredPathProblem(name string) string {
	name = strings.TrimPrefix(name, "--")
	name = strings.TrimPrefix(name, "scan.")
	name = strings.ReplaceAll(name, "-", " ")
	name = strings.ReplaceAll(name, ".", " ")
	name = strings.ReplaceAll(name, "_", " ")
	return name + " is required"
}

func applyFile(workDir string, values *Values, cfg fileConfig) []string {
	var problems []string
	applyPath := func(name string, input *string, target *string) {
		if input == nil {
			return
		}
		if strings.TrimSpace(*input) == "" {
			*target = ""
			problems = append(problems, requiredPathProblem(name))
			return
		}
		resolved, err := platform.ResolvePath(workDir, *input)
		if err != nil {
			problems = append(problems, fmt.Sprintf("resolve %s: %v", name, err))
			return
		}
		*target = resolved
	}

	applyPath("state_dir", cfg.StateDir, &values.StateDir)
	applyPath("cache_dir", cfg.CacheDir, &values.CacheDir)

	if cfg.Offline != nil {
		values.Offline = *cfg.Offline
	}
	if cfg.NoColor != nil {
		values.NoColor = *cfg.NoColor
	}
	if cfg.Quiet != nil {
		values.Quiet = *cfg.Quiet
	}
	if cfg.Verbose != nil {
		values.Verbose = *cfg.Verbose
	}
	if cfg.Scan == nil {
		problems = applyFileRules(workDir, values, cfg.Rules, problems)
		return applyFileThreat(values, cfg.Threat, problems)
	}

	applyPath("scan.root", cfg.Scan.Root, &values.Scan.Root)
	if cfg.Scan.StrictHash != nil {
		values.Scan.StrictHash = *cfg.Scan.StrictHash
	}
	if cfg.Scan.MaxWorkers != nil {
		values.Scan.MaxWorkers = *cfg.Scan.MaxWorkers
	}
	if cfg.Scan.MaxFileSize != nil {
		values.Scan.MaxFileSize = *cfg.Scan.MaxFileSize
	}
	if cfg.Scan.Output != nil {
		format, err := report.ParseFormat(*cfg.Scan.Output)
		if err != nil {
			problems = append(problems, err.Error())
		} else {
			values.Scan.Output = format
		}
	}
	if cfg.Scan.JSON != nil && *cfg.Scan.JSON {
		if cfg.Scan.Output != nil && *cfg.Scan.Output != report.FormatJSON.String() {
			problems = append(problems, "scan.json cannot be combined with scan.output "+*cfg.Scan.Output)
		}
		values.Scan.Output = report.FormatJSON
	}

	problems = applyFileRules(workDir, values, cfg.Rules, problems)
	return applyFileThreat(values, cfg.Threat, problems)
}

func applyFileRules(workDir string, values *Values, cfg *fileRulesConfig, problems []string) []string {
	if cfg == nil {
		return problems
	}
	for _, path := range cfg.PolicyFiles {
		applyPolicyPath(workDir, path, &values.Rules.PolicyFiles, &problems)
	}
	if cfg.UseBuiltins != nil {
		values.Rules.UseBuiltins = *cfg.UseBuiltins
	}
	return problems
}

func applyPolicyPath(workDir, input string, target *[]string, problems *[]string) {
	if strings.TrimSpace(input) == "" {
		*problems = append(*problems, "policy file path is required")
		return
	}
	resolved, err := platform.ResolvePath(workDir, input)
	if err != nil {
		*problems = append(*problems, fmt.Sprintf("resolve policy file: %v", err))
		return
	}
	*target = append(*target, resolved)
}

func applyFileThreat(values *Values, cfg *fileThreatConfig, problems []string) []string {
	if cfg == nil {
		return problems
	}
	if cfg.Sources != nil {
		values.Threat.Sources = cleanSourceList(cfg.Sources)
	}
	if cfg.RequiredSources != nil {
		values.Threat.RequiredSources = cleanSourceList(cfg.RequiredSources)
	}
	if cfg.OSVURL != nil {
		values.Threat.OSVURL = strings.TrimSpace(*cfg.OSVURL)
	}
	if cfg.NPMRegistryURL != nil {
		values.Threat.NPMRegistryURL = strings.TrimSpace(*cfg.NPMRegistryURL)
	}
	return problems
}

func (t Threat) validationProblems() []string {
	problems := []string{}
	for _, source := range append(slices.Clone(t.Sources), t.RequiredSources...) {
		if strings.TrimSpace(source) == "" {
			problems = append(problems, "threat source name is required")
		}
	}
	return problems
}

func cleanSourceList(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		out = append(out, value)
	}
	return out
}
