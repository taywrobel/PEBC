package main

import (
	"github.com/codegangsta/negroni"
	"github.com/twrobel3/UBC-PoC/handlers"
)

func main() {
	n := negroni.Classic()
	n.UseHandler(handlers.Router())
	n.Run(":3000")
}
