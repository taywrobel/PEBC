package handlers

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"

	"github.com/twrobel3/UBC-PoC/models"
)

// PerformCheck conducts a background check being passed in from the
// frontend.  It expects a CSR as the request body being passed in, with fields
// matching the specified requirements and formats to perform the check.
//
// On successful check it returns a 200 status code and a signed certificate.
// On a failed check, it will return a 403 (forbidden) status code.
func PerformCheck(w http.ResponseWriter, req *http.Request) {
	b, err := httputil.DumpRequest(req, true)
	if err != nil {
		fmt.Println("Could not dump request:", err.Error())
	} else {
		fmt.Println(string(b))
	}

	// Read the body (PEM encoded CSR)
	bodyBytes, err := ioutil.ReadAll(req.Body)
	if err != nil {
		log.Print("Error in reading body:", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Decode the PEM CSR from the request body (should be the only block)
	pemBlock, _ := pem.Decode(bodyBytes)
	if pemBlock == nil {
		log.Print("Unable to parse PEM block")
	}

	// Use the DER contents of the CSR, and generate a certificate request object
	cr, err := x509.ParseCertificateRequest(pemBlock.Bytes)
	if err != nil {
		log.Print("Error in extracting CSR:", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Check that the CSR has a valid signature
	err = cr.CheckSignature()
	if err != nil {
		log.Print("CSR has invalid signature:", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Extract the public data JSON (seller information) from the B64 encoded common name
	publicJSON, err := base64.StdEncoding.DecodeString(cr.Subject.CommonName)
	if err != nil {
		log.Print("Unable to decode public data from B64", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Unmarshal the public json into a buyer model
	var buyer models.Buyer
	dec := json.NewDecoder(bytes.NewReader(publicJSON))
	err = dec.Decode(&buyer)
	if err != nil {
		log.Print("Unable to decode the json:", err.Error())
	}

	// Make the determination
	if !checkApproval(buyer) {
		// Sale not approved, send back a 403
		w.WriteHeader(http.StatusForbidden)
		return
	}

	// Good to purchase, let's sign the CSR and send the cert back.
	w.WriteHeader(http.StatusOK)
}

func checkApproval(buyer models.Buyer) bool {
	b, _ := json.MarshalIndent(buyer, "", "  ")
	fmt.Println(string(b))
	return true
}
