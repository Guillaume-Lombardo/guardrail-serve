package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
)

// testdata/compat_golden.json was recorded from the pre-policy-engine
// implementation (main 6eeac11). /scan/* and the default LiteLLM policy must
// keep returning byte-for-byte equivalent decisions, masks, metadata and reasons.
func TestScanAndLiteLLMMatchPrePolicyEngineGolden(t *testing.T) {
	raw, err := os.ReadFile("testdata/compat_golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Route    string          `json:"route"`
		Body     json.RawMessage `json:"body"`
		Status   int             `json:"status"`
		Response any             `json:"response"`
	}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) == 0 {
		t.Fatal("empty golden corpus")
	}
	handler := newTestHandler(t)
	for index, tc := range cases {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, tc.Route, strings.NewReader(string(tc.Body))))
		var got any
		if err := json.Unmarshal(recorder.Body.Bytes(), &got); err != nil {
			t.Fatalf("case %d: decode: %v", index, err)
		}
		if recorder.Code != tc.Status || !reflect.DeepEqual(got, tc.Response) {
			t.Errorf("case %d %s: status=%d body=%s, want status=%d %v", index, tc.Route, recorder.Code, recorder.Body.String(), tc.Status, tc.Response)
		}
	}
}
