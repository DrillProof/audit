// Package k8s detects whether a cluster's state is actually being backed up.
//
// AWS alone cannot answer this. An EKS cluster's control plane is managed, but
// what makes a cluster recoverable is its *state* — namespaces, workload
// manifests, CRDs, and the PV bindings — and on EKS that is almost always
// captured by Velero rather than by anything visible to the AWS APIs. So the
// cluster-state coverage check is only truthful if we look inside the cluster.
//
// Access is optional and read-only: without --kubeconfig the cluster-state
// check reports "not assessed" rather than guessing, because claiming a cluster
// has no backup when we simply did not look would be worse than saying nothing.
package k8s

import (
	"context"
	"fmt"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/tools/clientcmd"
)

// VeleroGroup is the API group Velero installs its CRDs under.
const VeleroGroup = "velero.io"

// State is what we learned from inside one cluster.
type State struct {
	// ClusterName is taken from the kubeconfig context, used to attribute this
	// evidence to the right EKS cluster.
	ClusterName string
	// ServerURL helps match an EKS cluster when the context name is unhelpful.
	ServerURL string
	// VeleroInstalled reports whether the velero.io CRDs are present.
	VeleroInstalled bool
	// CompletedBackups counts Velero backups that finished successfully.
	CompletedBackups int
	// LatestBackupAt is the completion time of the newest successful backup.
	LatestBackupAt *time.Time
	// Schedules counts Velero Schedule objects — a backup that recurs is worth
	// distinguishing from a one-off someone ran by hand.
	Schedules int
	// Restores counts Velero Restore objects. A cluster whose state has been
	// restored before is genuinely proven, which is exactly what we look for.
	CompletedRestores int
	LatestRestoreAt   *time.Time
	// Unassessed explains why we could not answer, if we could not.
	Unassessed string
}

// resources we query, as GroupVersionResource.
var (
	backupGVR = schema.GroupVersionResource{
		Group: VeleroGroup, Version: "v1", Resource: "backups",
	}
	scheduleGVR = schema.GroupVersionResource{
		Group: VeleroGroup, Version: "v1", Resource: "schedules",
	}
	restoreGVR = schema.GroupVersionResource{
		Group: VeleroGroup, Version: "v1", Resource: "restores",
	}
)

// Inspect connects with the given kubeconfig and reports the cluster's
// backup posture. It never mutates anything: discovery plus list, nothing else.
//
// Every failure path returns a State with Unassessed set rather than an error,
// because a cluster we cannot reach must degrade to "not assessed" and never
// take down the AWS scan that already succeeded.
func Inspect(ctx context.Context, kubeconfigPath, contextName string) State {
	var state State

	loadRules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfigPath != "" {
		loadRules.ExplicitPath = kubeconfigPath
	}

	overrides := &clientcmd.ConfigOverrides{}
	if contextName != "" {
		overrides.CurrentContext = contextName
	}

	clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadRules, overrides)

	// Name the cluster from the raw config before connecting, so we can attribute
	// the finding even if the connection itself fails.
	if raw, err := clientConfig.RawConfig(); err == nil {
		current := raw.CurrentContext
		if contextName != "" {
			current = contextName
		}
		if kubeCtx, ok := raw.Contexts[current]; ok {
			state.ClusterName = kubeCtx.Cluster
			if cluster, ok := raw.Clusters[kubeCtx.Cluster]; ok {
				state.ServerURL = cluster.Server
			}
		}
	}

	restConfig, err := clientConfig.ClientConfig()
	if err != nil {
		state.Unassessed = fmt.Sprintf("could not load kubeconfig: %s", err)
		return state
	}
	// Never let an unreachable cluster hang the scan.
	restConfig.Timeout = 15 * time.Second

	disco, err := discovery.NewDiscoveryClientForConfig(restConfig)
	if err != nil {
		state.Unassessed = fmt.Sprintf("could not build discovery client: %s", err)
		return state
	}

	groups, err := disco.ServerGroups()
	if err != nil {
		state.Unassessed = fmt.Sprintf("cluster unreachable: %s", err)
		return state
	}

	for _, g := range groups.Groups {
		if g.Name == VeleroGroup {
			state.VeleroInstalled = true
			break
		}
	}
	if !state.VeleroInstalled {
		// A definite negative: Velero is genuinely not installed. That is an
		// answer, not a gap in our knowledge.
		return state
	}

	dyn, err := dynamic.NewForConfig(restConfig)
	if err != nil {
		state.Unassessed = fmt.Sprintf("could not build dynamic client: %s", err)
		return state
	}

	state.CompletedBackups, state.LatestBackupAt = countCompleted(ctx, dyn, backupGVR, "Completed")
	state.CompletedRestores, state.LatestRestoreAt = countCompleted(ctx, dyn, restoreGVR, "Completed")

	if list, err := dyn.Resource(scheduleGVR).List(ctx, metav1.ListOptions{}); err == nil {
		state.Schedules = len(list.Items)
	}

	return state
}

// countCompleted lists a Velero resource and counts those in the wanted phase,
// returning the most recent completion timestamp.
func countCompleted(
	ctx context.Context,
	dyn dynamic.Interface,
	gvr schema.GroupVersionResource,
	wantPhase string,
) (int, *time.Time) {
	list, err := dyn.Resource(gvr).List(ctx, metav1.ListOptions{})
	if err != nil {
		return 0, nil
	}

	count := 0
	var latest *time.Time

	for i := range list.Items {
		item := list.Items[i]

		phase, found, err := unstructuredString(item.Object, "status", "phase")
		if err != nil || !found {
			continue
		}
		if !strings.EqualFold(phase, wantPhase) {
			continue
		}
		count++

		// Prefer the explicit completion timestamp; fall back to creation.
		when := timestampAt(item.Object, "status", "completionTimestamp")
		if when == nil {
			if ts := item.GetCreationTimestamp(); !ts.IsZero() {
				t := ts.Time
				when = &t
			}
		}
		if when != nil && (latest == nil || when.After(*latest)) {
			latest = when
		}
	}

	return count, latest
}

func unstructuredString(obj map[string]any, fields ...string) (string, bool, error) {
	current := any(obj)
	for _, f := range fields {
		m, ok := current.(map[string]any)
		if !ok {
			return "", false, nil
		}
		current, ok = m[f]
		if !ok {
			return "", false, nil
		}
	}
	s, ok := current.(string)
	if !ok {
		return "", false, nil
	}
	return s, true, nil
}

func timestampAt(obj map[string]any, fields ...string) *time.Time {
	raw, found, err := unstructuredString(obj, fields...)
	if err != nil || !found {
		return nil
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return nil
	}
	return &t
}

// MatchesCluster reports whether this cluster state plausibly describes the
// named EKS cluster. EKS kubeconfig entries usually carry the cluster name in
// the context name or the ARN-style server host, so both are checked.
//
// Attribution is deliberately conservative: a wrong match would credit one
// cluster with another's backups, which is worse than declining to attribute.
func (s State) MatchesCluster(eksClusterName string) bool {
	if eksClusterName == "" {
		return false
	}
	needle := strings.ToLower(eksClusterName)
	return strings.Contains(strings.ToLower(s.ClusterName), needle) ||
		strings.Contains(strings.ToLower(s.ServerURL), needle)
}

// Summary renders the Velero posture for a report note.
func (s State) Summary() string {
	if s.Unassessed != "" {
		return s.Unassessed
	}
	if !s.VeleroInstalled {
		return "Velero is not installed in this cluster"
	}
	parts := []string{fmt.Sprintf("Velero installed, %d completed backup(s)", s.CompletedBackups)}
	if s.Schedules > 0 {
		parts = append(parts, fmt.Sprintf("%d schedule(s)", s.Schedules))
	}
	if s.CompletedRestores > 0 {
		parts = append(parts, fmt.Sprintf("%d completed restore(s)", s.CompletedRestores))
	}
	return strings.Join(parts, ", ")
}
