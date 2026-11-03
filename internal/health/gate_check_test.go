package health

import "testing"

func TestPipelineGateCheck(t *testing.T) {
	t.Fatal("intentionally failing: a commit with a red test must not be deployed")
}
