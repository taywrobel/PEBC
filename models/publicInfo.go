package models

// Buyer is a struct which represents the public ifnormation object that will be
// passed in with the CSR
type Buyer struct {
	FistName   string `json:"firstName"`
	MiddleName string `json:"middleName"`
	LastName   string `json:"lastName"`
	SSN        string `json:"ssn"`
	DLNumber   string `json:"dl"`
	DLState    string `json:"dlState"`
}
