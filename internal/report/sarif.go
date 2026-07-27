package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"

	"github.com/drillproof/audit/internal/model"
)

// SARIF 2.1.0, typed rather than hand-built maps, so CI systems that validate
// the schema accept it. Cloud resources have no file/line, so findings are
// attached as logicalLocations — the part of the spec designed for exactly this.

const (
	sarifVersion = "2.1.0"
	sarifSchema  = "https://json.schemastore.org/sarif-2.1.0.json"
	toolName     = "drillproof-audit"
	infoURI      = "https://github.com/drillproof/audit"
)

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool        sarifTool         `json:"tool"`
	Results     []sarifResult     `json:"results"`
	Invocations []sarifInvocation `json:"invocations,omitempty"`
	Properties  map[string]any    `json:"properties,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string          `json:"id"`
	Name                 string          `json:"name"`
	ShortDescription     sarifText       `json:"shortDescription"`
	FullDescription      sarifText       `json:"fullDescription"`
	Help                 sarifText       `json:"help"`
	DefaultConfiguration sarifRuleConfig `json:"defaultConfiguration"`
	Properties           map[string]any  `json:"properties,omitempty"`
}

type sarifRuleConfig struct {
	Level string `json:"level"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	Properties          map[string]any    `json:"properties,omitempty"`
}

type sarifLocation struct {
	LogicalLocations []sarifLogicalLocation `json:"logicalLocations"`
}

type sarifLogicalLocation struct {
	Name               string `json:"name"`
	FullyQualifiedName string `json:"fullyQualifiedName,omitempty"`
	Kind               string `json:"kind"`
}

type sarifInvocation struct {
	ExecutionSuccessful        bool                `json:"executionSuccessful"`
	ToolExecutionNotifications []sarifNotification `json:"toolExecutionNotifications,omitempty"`
}

type sarifNotification struct {
	Level   string    `json:"level"`
	Message sarifText `json:"message"`
}

// ruleFor describes each check once, at the rule level.
var ruleDescriptions = map[model.CheckID]struct {
	short, full, help, level string
}{
	model.CheckCoverage: {
		short: "Resource has no backup",
		full:  "The resource has no recovery point or snapshot, so it cannot be recovered at all.",
		help:  "Add the resource to an AWS Backup plan, or enable automated backups.",
		level: "error",
	},
	model.CheckFreshness: {
		short: "Most recent backup is stale",
		full:  "The newest successful backup is older than the configured threshold, which usually means a schedule is silently failing.",
		help:  "Check the backup schedule for failures and confirm the cadence is intentional.",
		level: "warning",
	},
	model.CheckImmutability: {
		short: "Backups are deletable",
		full:  "Backups are not on write-once-read-many storage, so ransomware or a compromised credential can delete them.",
		help:  "Enable AWS Backup Vault Lock in compliance mode, or S3 Object Lock on the backup bucket.",
		level: "error",
	},
	model.CheckRedundancy: {
		short: "Backups exist in only one region",
		full:  "All recovery points live in the same region as the protected resource, so a region-level event takes both.",
		help:  "Add a cross-region copy action to the backup plan.",
		level: "warning",
	},
	model.CheckRestoreTested: {
		short: "Backup was never test-restored",
		full:  `No restore has ever been performed from this resource's recovery points. "Backed up" is not "recoverable".`,
		help:  "Perform a restore into an isolated environment, or schedule recurring drills.",
		level: "warning",
	},
}

// RenderSARIF writes findings as SARIF 2.1.0 for CI code-scanning surfaces.
func RenderSARIF(w io.Writer, result *model.Result) error {
	// Rules are emitted in canonical order and indexed, as SARIF requires.
	var rules []sarifRule
	ruleIndex := map[model.CheckID]int{}
	for _, check := range model.AllChecks {
		d := ruleDescriptions[check]
		ruleIndex[check] = len(rules)
		rules = append(rules, sarifRule{
			ID:                   fmt.Sprintf("drillproof/%s", check),
			Name:                 string(check),
			ShortDescription:     sarifText{Text: d.short},
			FullDescription:      sarifText{Text: d.full},
			Help:                 sarifText{Text: d.help},
			DefaultConfiguration: sarifRuleConfig{Level: d.level},
			Properties: map[string]any{
				"tags": []string{"backup", "disaster-recovery", "aws"},
			},
		})
	}

	var results []sarifResult
	for _, f := range result.Findings {
		// Passing and unassessed checks are not findings.
		if f.Status == model.StatusOK || f.Status == model.StatusSkipped {
			continue
		}

		results = append(results, sarifResult{
			RuleID:    fmt.Sprintf("drillproof/%s", f.Check),
			RuleIndex: ruleIndex[f.Check],
			Level:     sarifLevel(f.Status),
			Message:   sarifText{Text: message(f)},
			Locations: []sarifLocation{{
				LogicalLocations: []sarifLogicalLocation{{
					Name:               f.Resource.Display,
					FullyQualifiedName: qualifiedName(f.Resource),
					Kind:               string(f.Resource.Type),
				}},
			}},
			// Stable across runs so CI does not re-report the same finding as new.
			PartialFingerprints: map[string]string{
				"drillproof/v1": fingerprint(f),
			},
			Properties: map[string]any{
				"region":      f.Resource.Region,
				"resourceArn": f.Resource.ARN,
				"remediation": f.Remediation,
				"production":  f.Resource.Production,
			},
		})
	}

	var notifications []sarifNotification
	for _, warning := range result.Warnings {
		notifications = append(notifications, sarifNotification{
			Level:   "note",
			Message: sarifText{Text: warning},
		})
	}

	log := sarifLog{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           toolName,
				Version:        result.Version,
				InformationURI: infoURI,
				Rules:          rules,
			}},
			Results: results,
			Invocations: []sarifInvocation{{
				ExecutionSuccessful:        true,
				ToolExecutionNotifications: notifications,
			}},
			Properties: map[string]any{
				"recoverabilityScore": result.Score.Value,
				"criticalGaps":        result.Score.CriticalGaps,
				"accountId":           result.AccountID,
				"regions":             result.Regions,
			},
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

func sarifLevel(s model.Status) string {
	switch s {
	case model.StatusFail:
		return "error"
	case model.StatusWarn:
		return "warning"
	default:
		return "note"
	}
}

func message(f model.Finding) string {
	if f.Remediation == "" {
		return f.Summary
	}
	return f.Summary + " " + f.Remediation
}

func qualifiedName(r model.Resource) string {
	if r.ARN != "" {
		return r.ARN
	}
	return fmt.Sprintf("%s/%s/%s", r.Region, r.Type, r.Name)
}

// fingerprint identifies a finding by what it is about, not by when it was
// found, so the same unresolved gap keeps the same fingerprint run to run.
func fingerprint(f model.Finding) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s|%s",
		f.Check, f.Resource.Region, f.Resource.Type, identityOf(f.Resource))))
	return hex.EncodeToString(h[:])[:32]
}

func identityOf(r model.Resource) string {
	if r.ARN != "" {
		return r.ARN
	}
	return r.Name
}
