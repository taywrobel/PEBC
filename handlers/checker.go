package handlers

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"net/http/httputil"
	"reflect"
	"time"

	normalRand "math/rand"

	. "github.com/coreos/etcd-ca/pkix"

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
		w.WriteHeader(http.StatusBadRequest)
		return
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
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Make the determination
	if !checkApproval(buyer) {
		// Sale not approved, send back a 403
		w.WriteHeader(http.StatusForbidden)
		return
	}

	// Good to transfer, let's sign the CSR and send the cert back.
	// First get the private key from disk
	caKeyBytes, err := ioutil.ReadFile("CA/rootCA.key")
	if err != nil {
		log.Print("Unable to read the ca key file:", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Parse it into a pem block
	caKeyBlock, _ := pem.Decode(caKeyBytes)
	if caKeyBlock == nil {
		log.Print("Unable to get a PEM block out of the CA keyfile")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Parse the asn.1 block to get the keypair
	caKey, err := x509.ParsePKCS1PrivateKey(caKeyBlock.Bytes)
	if err != nil {
		log.Print("Failure to parse ca key block:", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Next, get the CA certificate, which we'll sign the CSR with
	caCertBytes, err := ioutil.ReadFile("CA/rootCA.pem")
	if err != nil {
		log.Print("Unable to read the ca key file:", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Parse it into a pem block
	caCertBlock, _ := pem.Decode(caCertBytes)
	if caCertBlock == nil {
		log.Print("Unable to get a PEM block out of the CA cert")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Parse the pem block into a cert
	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		log.Print("Failure to parse ca cert block:", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Fill out template info with the info from the CSR
	hostTemplate.SerialNumber.Set(big.NewInt(normalRand.Int63()))

	hostTemplate.Subject = cr.Subject

	hostTemplate.NotAfter = time.Now().AddDate(25, 0, 0).UTC()

	hostTemplate.SubjectKeyId, err = GenerateSubjectKeyId(cr.PublicKey)
	if err != nil {
		log.Print("Some shit broke, fuck if I know.", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	hostTemplate.IPAddresses = cr.IPAddresses
	hostTemplate.DNSNames = cr.DNSNames

	// Parse a certificate out of the CSR ASN.1 data
	// csrCert, err := x509.ParseCertificate(cr.Raw)
	// if err != nil {
	// 	log.Print("Failure to convert CSR to template certificate:", err.Error())
	// 	w.WriteHeader(http.StatusInternalServerError)
	// 	return
	// }

	// Sign the request
	fmt.Println(reflect.TypeOf(caKey.PublicKey))
	fmt.Println(reflect.TypeOf(caKey))

	certDer, err := x509.CreateCertificate(rand.Reader, &hostTemplate, caCert, &caKey.PublicKey, caKey)
	if err != nil {
		log.Print("Failure to create signed certiicate:", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDer,
	}

	w.Header().Set("Content-Type", "application/json")

	err = pem.Encode(w, block)
	if err != nil {
		log.Print("Couldn't encode block to responsewriter:", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func checkApproval(buyer models.Buyer) bool {
	b, _ := json.MarshalIndent(buyer, "", "  ")
	fmt.Println(string(b))
	return true
}

var // Build CA based on RFC5280
hostTemplate = x509.Certificate{
	// **SHOULD** be filled in a unique number
	SerialNumber: big.NewInt(0),
	// **SHOULD** be filled in host info
	Subject: pkix.Name{},
	// NotBefore is set to be 10min earlier to fix gap on time difference in cluster
	NotBefore: time.Now().Add(-600).UTC(),
	// 10-year lease
	NotAfter: time.Time{},
	// Used for certificate signing only
	KeyUsage: 0,

	ExtKeyUsage: []x509.ExtKeyUsage{
		x509.ExtKeyUsageServerAuth,
		x509.ExtKeyUsageClientAuth,
	},
	UnknownExtKeyUsage: nil,

	// activate CA
	BasicConstraintsValid: false,

	// 160-bit SHA-1 hash of the value of the BIT STRING subjectPublicKey
	// (excluding the tag, length, and number of unused bits)
	// **SHOULD** be filled in later
	SubjectKeyId: nil,

	// Subject Alternative Name
	DNSNames: nil,

	PermittedDNSDomainsCritical: false,
	PermittedDNSDomains:         nil,
}
