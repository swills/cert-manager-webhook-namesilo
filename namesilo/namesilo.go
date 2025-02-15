package namesilo

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/swills/cert-manager-webhook-namesilo/utils"
)

type Response struct {
	Reply struct {
		Code   CodeWrapper `json:"code"`
		Detail string      `json:"detail"`
	} `json:"reply"`
}

// DNSRecordListResponse represents the response from namesilo api, see
// https://www.namesilo.com/api-reference#dns/dns-list-records
type DNSRecordListResponse struct {
	Reply struct {
		Code           CodeWrapper `json:"code"`
		Detail         string      `json:"detail"`
		ResourceRecord []struct {
			ResourceID string `json:"record_id"`
			Type       string `json:"type"`
			Host       string `json:"host"`
			Value      string `json:"value"`
		} `json:"resource_record"`
	} `json:"reply"`
}

// CodeWrapper holds the api response code string
// FIXME: namesilo API response code sometimes is string instead of int
type CodeWrapper string

func (c *CodeWrapper) UnmarshalJSON(data []byte) error {
	*c = CodeWrapper(data)
	*c = CodeWrapper(strings.Trim(string(data), "\""))

	return nil
}

//nolint:ireturn
func Call[Resp any](apiKey string, operation string, params map[string]string) (Resp, error) {
	var err error

	var resp Resp

	backgroundCtx := context.Background()

	var req *http.Request

	req, err = http.NewRequestWithContext(backgroundCtx, http.MethodGet, "https://www.namesilo.com/api/"+operation, nil)
	if err != nil {
		return resp, fmt.Errorf("error creating http request: %w", err)
	}

	queryParams := req.URL.Query()

	// common params
	queryParams.Set("version", "1")
	queryParams.Set("type", "json")
	queryParams.Set("key", apiKey)

	// add record api params
	for k, v := range params {
		queryParams.Set(k, v)
	}

	req.URL.RawQuery = queryParams.Encode()

	var httpResp *http.Response

	httpResp, err = http.DefaultClient.Do(req)
	if err != nil {
		return resp, fmt.Errorf("error creating http client: %w", err)
	}

	defer func() {
		_ = httpResp.Body.Close()
	}()

	if httpResp.StatusCode != http.StatusOK {
		return resp, fmt.Errorf("error response from namesilo api: %s, %w", httpResp.Status, ErrNamesiloHTTPNotOK)
	}

	var responseBody []byte

	responseBody, err = io.ReadAll(httpResp.Body)
	if err != nil {
		return resp, fmt.Errorf("error reading response body: %w", err)
	}

	if err := json.Unmarshal(responseBody, &resp); err != nil {
		utils.Log("namesilo unmarshal fail: %s, data: %s", err.Error(), string(responseBody))

		return resp, fmt.Errorf("namesilo unmarshal json fail: %w", err)
	}

	return resp, nil
}

func GetDomainFromZone(fqdn string) string {
	return strings.TrimSuffix(fqdn, ".")
}
