package scanner

import (
	"io"
	"net/http"
)

// readBody reads the response body safely
func readBody(resp *http.Response) ([]byte, error) {
	return io.ReadAll(resp.Body)
}
