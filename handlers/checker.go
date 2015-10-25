package handlers

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"time"

	normalRand "math/rand"

	"github.com/twrobel3/UBC-PoC/models"
)

type Checker struct {
	CA    *x509.Certificate
	Key   *rsa.PrivateKey
	check checkFunc
}

type checkFunc func(models.Buyer) bool

func NewChecker(caFiles string, fn checkFunc) (*Checker, error) {
	caKeyBytes, err := ioutil.ReadFile(caFiles + ".key")
	if err != nil {
		return nil, err
	}

	// Parse it into a pem block
	caKeyBlock, _ := pem.Decode(caKeyBytes)
	if caKeyBlock == nil {
		return nil, err
	}

	// Parse the asn.1 block to get the keypair
	caKey, err := x509.ParsePKCS1PrivateKey(caKeyBlock.Bytes)
	if err != nil {
		return nil, err
	}

	// Next, get the CA certificate, which we'll sign the CSR with
	caCertBytes, err := ioutil.ReadFile(caFiles + ".pem")
	if err != nil {
		return nil, err
	}

	// Parse it into a pem block
	caCertBlock, _ := pem.Decode(caCertBytes)
	if caCertBlock == nil {
		return nil, err
	}

	// Parse the pem block into a cert
	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return nil, err
	}

	return &Checker{
		CA:    caCert,
		Key:   caKey,
		check: fn,
	}, nil
}

// PerformCheck conducts a background check being passed in from the
// frontend.  It expects a CSR as the request body being passed in, with fields
// matching the specified requirements and formats to perform the check.
//
// On successful check it returns a 200 status code and a signed certificate.
// On a failed check, it will return a 403 (forbidden) status code.
func (ch *Checker) PerformCheck(w http.ResponseWriter, req *http.Request) {
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
	if !ch.check(buyer) {
		// Sale not approved, send back a 403
		w.WriteHeader(http.StatusForbidden)
		return
	}

	// Good to transfer, let's sign the CSR and send the cert back.
	// First get the private key from disk

	ski, err := GenerateSubjectKeyId(cr.PublicKey)
	if err != nil {
		log.Print("Some shit broke, fuck if I know.", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	var // Build CA based on RFC5280
	hostTemplate = x509.Certificate{
		SerialNumber: big.NewInt(normalRand.Int63()),
		Subject:      cr.Subject,
		// NotBefore is set to be 10min earlier to fix gap on time difference in cluster
		NotBefore: time.Now().Add(-600).UTC(),
		// 25-year lease
		NotAfter: time.Now().AddDate(25, 0, 0).UTC(),
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
		SubjectKeyId: ski,

		// Subject Alternative Name
		IPAddresses: cr.IPAddresses,
		DNSNames:    cr.DNSNames,

		PermittedDNSDomainsCritical: false,
		PermittedDNSDomains:         nil,
	}

	// Sign the request
	certDer, err := x509.CreateCertificate(rand.Reader, &hostTemplate, ch.CA, &ch.Key.PublicKey, ch.Key)
	if err != nil {
		log.Print("Failure to create signed certiicate:", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDer,
	}

	w.Header().Set("Content-Type", "application/x-pem-file")

	err = pem.Encode(w, block)
	if err != nil {
		log.Print("Couldn't encode block to responsewriter:", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func GenerateSubjectKeyId(pub crypto.PublicKey) ([]byte, error) {
	var pubBytes []byte
	var err error
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		pubBytes, err = asn1.Marshal(rsa.PublicKey{
			N: pub.N,
			E: pub.E,
		})
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("only RSA public key is supported")
	}

	hash := sha1.Sum(pubBytes)

	return hash[:], nil
}
