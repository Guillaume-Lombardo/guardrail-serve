package bench

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// JevModelsURL is the documented read-only model listing.
const JevModelsURL = "https://api.typesafe.ai/v1/models"

// JevModel is one listed model.
type JevModel struct {
	Name        string `json:"name"`
	ReleaseDate string `json:"release_date"`
}

// ListJevModels calls GET /v1/models. Errors carry the status only, never the body.
func ListJevModels(ctx context.Context, client *http.Client, url string, key []byte) ([]JevModel, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+string(key))
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "guardrail-bench")
	response, err := client.Do(request)
	if err != nil {
		return nil, errors.New("models request failed at the transport level")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("models request: status %d", response.StatusCode)
	}
	var decoded struct {
		Models []JevModel `json:"models"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&decoded); err != nil {
		return nil, errors.New("models answer is not the documented object")
	}
	return decoded.Models, nil
}
