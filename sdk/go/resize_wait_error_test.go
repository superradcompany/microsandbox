package microsandbox

import (
	"encoding/json"
	"errors"
	"github.com/superradcompany/microsandbox/sdk/go/internal/ffi"
	"testing"
)

func TestResizeWaitErrorRetainsStructuredFailure(t *testing.T) {
	for _, reason := range []string{"superseded", "interrupted", "history_unavailable", "invalid_response", "observation_unavailable"} {
		payload := json.RawMessage(`{"reason":"` + reason + `","sandbox":"box","operation_id":"old","status":[{"resource":"cpus","requested":"2","actual":"2","enforced":"2","state":"applied"}]}`)
		err := wrapFFI(&ffi.Error{Kind: ffi.KindResizeWait, Message: "observation failed", ResizeWait: payload})
		var failure *ResizeWaitError
		if !errors.As(err, &failure) || !IsKind(err, ErrResizeWait) {
			t.Fatalf("lost failure: %v", err)
		}
		if string(failure.Reason) != reason || *failure.OperationID != "old" || *failure.Sandbox != "box" || len(failure.Status) != 1 {
			t.Fatalf("lost details: %#v", failure)
		}
		if err.Error() != "observation failed" {
			t.Fatalf("changed diagnostic: %v", err)
		}
	}
}
