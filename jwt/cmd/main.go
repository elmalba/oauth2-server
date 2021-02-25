package main

import (
	"fmt"

	"github.com/elmalba/oauth2-server/jwt"
)

func main() {
	fmt.Println(jwt.GetToken("1", "malba@mmae.cl", "938A945C734CC33925F7A9934514F"))
}
