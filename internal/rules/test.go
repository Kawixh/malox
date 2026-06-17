package rules

// NewTestResult returns the JSON model for one rules test invocation.
func NewTestResult(ruleFile, fixture string, findings []Finding, warnings []Warning, expected *int) TestResult {
	result := TestResult{
		SchemaVersion:    TestSchemaVersion,
		RuleFile:         ruleFile,
		Fixture:          fixture,
		Valid:            true,
		Passed:           true,
		MatchCount:       len(findings),
		ExpectedFindings: expected,
		Findings:         findings,
		Warnings:         warnings,
		Errors:           []string{},
	}
	if expected != nil && len(findings) != *expected {
		result.Passed = false
		result.Errors = append(result.Errors, "finding count did not match expectation")
	}
	return result
}
