package httpapi

import (
	"net/http"

	"github.com/danielgtaylor/huma/v2"
)

type errorResponse struct {
	status int
	Detail string `json:"detail"`
}

func (e *errorResponse) Error() string {
	return e.Detail
}

func (e *errorResponse) GetStatus() int {
	return e.status
}

func (e *errorResponse) ContentType(string) string {
	return "application/json"
}

var errInvalidJSON = newStatusDetailError(http.StatusBadRequest, "Invalid JSON request body.")

func init() {
	huma.NewErrorWithContext = func(ctx huma.Context, status int, msg string, errs ...error) huma.StatusError {
		detail := msg
		errorMessages := make([]string, 0, len(errs))
		for _, err := range errs {
			if err == nil {
				continue
			}
			errorMessages = append(errorMessages, err.Error())
		}

		if len(errorMessages) == 1 {
			detail = errorMessages[0]
		}

		recordError(ctx.Context(), detail)

		return &errorResponse{
			status: status,
			Detail: detail,
		}
	}
}

func newStatusDetailError(status int, detail string) *errorResponse {
	return &errorResponse{status: status, Detail: detail}
}

func writeMethodNotAllowed(writer http.ResponseWriter, request *http.Request) {
	if request != nil {
		recordError(request.Context(), "Method not allowed.")
	}

	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusMethodNotAllowed)
	_, _ = writer.Write([]byte("{\"detail\":\"Method not allowed.\"}\n"))
}
