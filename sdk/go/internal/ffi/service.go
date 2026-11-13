package ffi

import "time"

// ServiceTarget is the sandbox and port a Service routes to.
type ServiceTarget struct {
	Sandbox string `json:"sandbox"`
	Port    uint16 `json:"port"`
}

// ServiceInfo is the Service JSON returned by the msb_service_* functions.
type ServiceInfo struct {
	Handle    uint64         `json:"handle"`
	Slug      string         `json:"slug"`
	URL       string         `json:"url"`
	Status    string         `json:"status"`
	Target    *ServiceTarget `json:"target"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
}

// ServiceCreateRequest matches the JSON request expected by msb_service_create.
type ServiceCreateRequest struct {
	Slug   string        `json:"slug"`
	Target ServiceTarget `json:"target"`
}

// ServiceUpdateRequest matches the JSON request expected by msb_service_update.
type ServiceUpdateRequest struct {
	Target *ServiceTarget `json:"target,omitempty"`
}

// ServiceListOptions matches the JSON request expected by msb_service_list.
type ServiceListOptions struct {
	Sandbox *string `json:"sandbox,omitempty"`
	Cursor  *string `json:"cursor,omitempty"`
	Limit   *uint32 `json:"limit,omitempty"`
}

// ServicePage is the JSON page returned by msb_service_list.
type ServicePage struct {
	Services   []*ServiceInfo `json:"services"`
	NextCursor *string        `json:"next_cursor"`
}

// ServiceErrorDetails carries a Service change failure's refusal details.
type ServiceErrorDetails struct {
	Slug         string  `json:"slug"`
	Reason       string  `json:"reason"`
	RetryAfterMs *uint64 `json:"retry_after_ms"`
	RawCode      string  `json:"raw_code,omitempty"`
	RawStatus    int     `json:"raw_status,omitempty"`
	RawMessage   string  `json:"raw_message,omitempty"`
}
