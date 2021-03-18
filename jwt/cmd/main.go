package main

import (
	"fmt"
	"os"

	"github.com/elmalba/oauth2-server/jwt"
)

func main() {
	fmt.Println(jwt.GetToken("1", "malba@mmae.cl", os.Getenv("KEY")))
}
