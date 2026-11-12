package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

// Request Format example from https://docs.litellm.ai/docs/adding_provider/generic_guardrail_api
// JSON comments removed; field values and structure retained.
const liteLLMDocumentedPayload = `{
 "texts": ["extracted text from the request"],
 "images": ["base64_encoded_image_data"],
 "tools": [{"type":"function","function":{"name":"get_weather","description":"Get the current weather","parameters":{"type":"object","properties":{"location":{"type":"string"}}}}}],
 "tool_calls": [{"id":"call_abc123","type":"function","function":{"name":"get_weather","arguments":"{\"location\": \"San Francisco\"}"}}],
 "structured_messages": [{"role":"system","content":"You are a helpful assistant"},{"role":"user","content":"Hello"}],
 "request_data": {
  "user_api_key_hash":"hash of the litellm virtual key used",
  "user_api_key_alias":"alias of the litellm virtual key used",
  "user_api_key_user_id":"user id associated with the litellm virtual key used",
  "user_api_key_user_email":"user email associated with the litellm virtual key used",
  "user_api_key_team_id":"team id associated with the litellm virtual key used",
  "user_api_key_team_alias":"team alias associated with the litellm virtual key used",
  "user_api_key_end_user_id":"end user id associated with the litellm virtual key used",
  "user_api_key_org_id":"org id associated with the litellm virtual key used"
 },
 "request_headers":{"User-Agent":"OpenAI/Python 2.17.0","Content-Type":"application/json","X-Request-Id":"[present]"},
 "litellm_version":"1.x.y",
 "input_type":"request",
 "litellm_call_id":"unique_call_id",
 "litellm_trace_id":"trace_id",
 "additional_provider_specific_params":{}
}`

func TestL1LiteLLMDocumentedPayload(t *testing.T) {
	handler := newTestHandler(t)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/beta/litellm_basic_guardrail_api", strings.NewReader(liteLLMDocumentedPayload)))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var result map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result["action"] != "NONE" {
		t.Fatalf("response=%v", result)
	}
	if !reflect.DeepEqual(result["texts"], []any{"extracted text from the request"}) {
		t.Fatalf("texts=%v", result["texts"])
	}
	if _, ok := result["decision"]; ok {
		t.Fatalf("unexpected scan contract: %v", result)
	}
}

func TestL1MetadataAndStrictness(t *testing.T) {
	for _, route := range []string{"/scan/secrets", "/scan/pii", "/scan/prompt-injection", "/beta/litellm_basic_guardrail_api"} {
		for _, extra := range []string{`"request_data":{"user_api_key_team_id":"team","nested":{"future":true}}`, `"future_field":{"anything":[1,2]}`} {
			t.Run(route+extra, func(t *testing.T) {
				recorder := httptest.NewRecorder()
				newTestHandler(t).ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, route, strings.NewReader(`{"texts":["hello"],`+extra+`}`)))
				want := http.StatusOK
				if strings.HasPrefix(route, "/scan/") && strings.Contains(extra, "future_field") {
					want = http.StatusUnprocessableEntity
				}
				if recorder.Code != want {
					t.Fatalf("status=%d want=%d body=%s", recorder.Code, want, recorder.Body.String())
				}
			})
		}
	}
}

func TestL1LiteLLMTextAlignment(t *testing.T) {
	for _, tc := range []struct {
		name, texts, action string
		want                []string
	}{
		{"unchanged", `["first","","last"]`, "NONE", []string{"first", "", "last"}},
		{"redacted", `["first","password=abc123","last"]`, "GUARDRAIL_INTERVENED", []string{"first", "password=[REDACTED]", "last"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			newTestHandler(t).ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/beta/litellm_basic_guardrail_api", strings.NewReader(`{"texts":`+tc.texts+`,"images":["password=abc123"],"tools":[{"type":"code_interpreter"}],"tool_calls":[{"custom":true}],"structured_messages":[{"custom":"password=abc123"}],"additional_provider_specific_params":{"threshold":0.8}}`)))
			var response struct {
				Action string   `json:"action"`
				Texts  []string `json:"texts"`
			}
			if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			if recorder.Code != 200 || response.Action != tc.action || !reflect.DeepEqual(response.Texts, tc.want) {
				t.Fatalf("status=%d response=%s", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestL1LiteLLMBlockedReasonAndAlignment(t *testing.T) {
	texts := []string{strings.Repeat("x", 20001), "last"}
	body, err := json.Marshal(map[string]any{"texts": texts})
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	newTestHandler(t).ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/beta/litellm_basic_guardrail_api", strings.NewReader(string(body))))
	var response struct {
		Action string   `json:"action"`
		Reason string   `json:"blocked_reason"`
		Texts  []string `json:"texts"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if recorder.Code != 200 || response.Action != "BLOCKED" || response.Reason == "" || !reflect.DeepEqual(response.Texts, texts) {
		t.Fatalf("status=%d action=%s reason=%q count=%d", recorder.Code, response.Action, response.Reason, len(response.Texts))
	}
}
