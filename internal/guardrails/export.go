package guardrails

import "github.com/g1lom/guardrail-serve/internal/domain"

func ResponseFromResult(name string, original []string, result domain.Result) domain.Response {
	return responseFromResult(name, original, result)
}
