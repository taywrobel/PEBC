package handlers

import (
	"net/http"

	"github.com/unrolled/render"
)

// Index renders the primary webform
func Index(w http.ResponseWriter, req *http.Request) {
	r := render.New(render.Options{
		Directory: "static",
	})
	r.HTML(w, http.StatusOK, "index", nil)
}
