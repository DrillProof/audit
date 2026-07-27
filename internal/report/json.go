package report

import (
	"encoding/json"
	"io"

	"github.com/drillproof/audit/internal/model"
	"github.com/drillproof/audit/internal/score"
)

// SchemaVersion is bumped when the JSON contract changes incompatibly.
//
// The payload is assembled explicitly below rather than by embedding
// model.Result: encoding/json has no real ",inline", and keeping the wire format
// separate from the internal model lets one change without the other.
const SchemaVersion = "1.0"

// RenderJSON writes the full result as indented JSON.
func RenderJSON(w io.Writer, result *model.Result) error {
	payload := map[string]any{
		"schema_version":  SchemaVersion,
		"tool":            "drillproof-audit",
		"version":         result.Version,
		"account_id":      result.AccountID,
		"account_arn":     result.AccountArn,
		"regions":         result.Regions,
		"generated_at":    result.GeneratedAt,
		"rows":            result.Rows,
		"findings":        result.Findings,
		"score":           result.Score,
		"score_explained": score.Explain(result.Score),
		"warnings":        result.Warnings,
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(payload)
}
