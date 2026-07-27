package k8s

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMatchesClusterIsConservative(t *testing.T) {
	state := State{
		ClusterName: "arn:aws:eks:ap-southeast-1:123456789012:cluster/prod-cluster",
		ServerURL:   "https://ABC123.gr7.ap-southeast-1.eks.amazonaws.com",
	}

	assert.True(t, state.MatchesCluster("prod-cluster"))
	assert.True(t, state.MatchesCluster("PROD-CLUSTER"), "matching should be case-insensitive")

	// Crediting the wrong cluster with another's backups is worse than
	// declining to attribute, so a non-match must stay false.
	assert.False(t, state.MatchesCluster("staging-cluster"))
	assert.False(t, state.MatchesCluster(""), "an empty name must never match")
}

func TestMatchesClusterViaServerURL(t *testing.T) {
	state := State{
		ClusterName: "kubernetes",
		ServerURL:   "https://my-eks-prod.example.com",
	}
	assert.True(t, state.MatchesCluster("my-eks-prod"),
		"the server URL is a fallback when the context name is unhelpful")
}

func TestSummaryReportsWhatWeActuallyKnow(t *testing.T) {
	t.Run("unassessed wins", func(t *testing.T) {
		s := State{Unassessed: "cluster unreachable: i/o timeout", VeleroInstalled: true}
		assert.Equal(t, "cluster unreachable: i/o timeout", s.Summary())
	})

	t.Run("velero absent is a definite answer", func(t *testing.T) {
		s := State{VeleroInstalled: false}
		assert.Equal(t, "Velero is not installed in this cluster", s.Summary())
	})

	t.Run("counts are reported", func(t *testing.T) {
		s := State{VeleroInstalled: true, CompletedBackups: 4, Schedules: 2, CompletedRestores: 1}
		summary := s.Summary()
		assert.Contains(t, summary, "4 completed backup(s)")
		assert.Contains(t, summary, "2 schedule(s)")
		assert.Contains(t, summary, "1 completed restore(s)")
	})

	t.Run("zero counts are not padded with noise", func(t *testing.T) {
		s := State{VeleroInstalled: true, CompletedBackups: 0}
		assert.NotContains(t, s.Summary(), "schedule(s)")
		assert.NotContains(t, s.Summary(), "restore(s)")
	})
}

func TestInspectDegradesOnMissingKubeconfig(t *testing.T) {
	state := Inspect(context.Background(), filepath.Join(t.TempDir(), "nope.yaml"), "")
	assert.NotEmpty(t, state.Unassessed,
		"a missing kubeconfig must produce an explanation, not a panic")
	assert.False(t, state.VeleroInstalled)
}

func TestInspectDegradesOnMalformedKubeconfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.yaml")
	require.NoError(t, os.WriteFile(path, []byte("this is not: [valid kubeconfig"), 0o600))

	state := Inspect(context.Background(), path, "")
	assert.NotEmpty(t, state.Unassessed)
	assert.False(t, state.VeleroInstalled)
}

// A kubeconfig pointing at an unreachable server must time out and report, not
// hang the scan. The address is in the reserved TEST-NET-1 range so nothing real
// is contacted.
func TestInspectNamesTheClusterEvenWhenUnreachable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	kubeconfig := `apiVersion: v1
kind: Config
current-context: prod
clusters:
  - name: prod-cluster
    cluster:
      server: https://192.0.2.1:6443
contexts:
  - name: prod
    context:
      cluster: prod-cluster
      user: auditor
users:
  - name: auditor
    user:
      token: not-a-real-token
`
	require.NoError(t, os.WriteFile(path, []byte(kubeconfig), 0o600))

	done := make(chan State, 1)
	go func() {
		done <- Inspect(context.Background(), path, "")
	}()

	select {
	case state := <-done:
		// Attribution must survive a failed connection, so the finding can be
		// pinned to the right cluster.
		assert.Equal(t, "prod-cluster", state.ClusterName)
		assert.Contains(t, state.ServerURL, "192.0.2.1")
		assert.NotEmpty(t, state.Unassessed, "an unreachable cluster is 'not assessed'")
		assert.False(t, state.VeleroInstalled)
	case <-time.After(90 * time.Second):
		t.Fatal("Inspect hung on an unreachable cluster — it must always time out")
	}
}

func TestVeleroGroupIsTheRealAPIGroup(t *testing.T) {
	// Velero's CRDs are registered under velero.io; getting this wrong would
	// silently report every cluster as having no backups.
	assert.Equal(t, "velero.io", VeleroGroup)
	assert.Equal(t, "velero.io", backupGVR.Group)
	assert.Equal(t, "backups", backupGVR.Resource)
	assert.Equal(t, "schedules", scheduleGVR.Resource)
	assert.Equal(t, "restores", restoreGVR.Resource)
}

func TestUnstructuredHelpers(t *testing.T) {
	obj := map[string]any{
		"status": map[string]any{
			"phase":               "Completed",
			"completionTimestamp": "2026-07-25T10:30:00Z",
		},
	}

	phase, found, err := unstructuredString(obj, "status", "phase")
	require.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, "Completed", phase)

	_, found, err = unstructuredString(obj, "status", "missing")
	require.NoError(t, err)
	assert.False(t, found)

	_, found, err = unstructuredString(obj, "nope", "phase")
	require.NoError(t, err)
	assert.False(t, found)

	ts := timestampAt(obj, "status", "completionTimestamp")
	require.NotNil(t, ts)
	assert.Equal(t, 2026, ts.Year())
	assert.Equal(t, time.July, ts.Month())

	assert.Nil(t, timestampAt(obj, "status", "phase"),
		"an unparseable timestamp must return nil rather than a zero time")
}
