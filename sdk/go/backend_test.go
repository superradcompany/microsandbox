package microsandbox

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBackendInfoJSONIsSecretSafe(t *testing.T) {
	info := BackendInfo{
		Kind:   BackendCloud,
		APIURL: "https://api.microsandbox.dev",
		Source: "MSB_API_KEY",
	}
	rendered, err := json.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(rendered), "msb_ak_") {
		t.Fatalf("backend info leaked an API key: %s", rendered)
	}
	if !strings.Contains(string(rendered), `"kind":"cloud"`) {
		t.Fatalf("backend kind missing from JSON: %s", rendered)
	}
}

func TestBackendKindsAreStable(t *testing.T) {
	if BackendLocal != "local" || BackendCloud != "cloud" || BackendUnknown != "unknown" {
		t.Fatal("backend kind wire names changed")
	}
}
