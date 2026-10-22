package microsandbox

// ResizeWaitFailure is separate from per-resource convergence and wait timeout.
type ResizeWaitFailure string

const (
	ResizeWaitSuperseded             ResizeWaitFailure = "superseded"
	ResizeWaitInterrupted            ResizeWaitFailure = "interrupted"
	ResizeWaitHistoryUnavailable     ResizeWaitFailure = "history_unavailable"
	ResizeWaitInvalidResponse        ResizeWaitFailure = "invalid_response"
	ResizeWaitObservationUnavailable ResizeWaitFailure = "observation_unavailable"
)

// ResizeWaitError retains verified observations without asserting rollback or completion.
// Use errors.As to inspect the reason; IsKind recognizes ErrResizeWait.
type ResizeWaitError struct {
	Reason      ResizeWaitFailure      `json:"reason"`
	Sandbox     *string                `json:"sandbox"`
	OperationID *string                `json:"operation_id"`
	Status      []ResourceResizeStatus `json:"status"`
	err         *Error
}

func (e *ResizeWaitError) Error() string { return e.err.Error() }
func (e *ResizeWaitError) Unwrap() error { return e.err }
