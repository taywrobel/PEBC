package handlers

import "net/http"

// PerformCheck conducts a background check being passed in from the
// frontend.  It expects a CSR as the request body being passed in, with fields
// matching the specified requirements and formats to perform the check.
//
// On successful check it returns a 200 status code and a signed certificate.
// On a failed check, it will return a 403 (forbidden) status code.
func PerformCheck(w http.ResponseWriter, req *http.Request) {
	w.WriteHeader(http.StatusNotImplemented)
}
