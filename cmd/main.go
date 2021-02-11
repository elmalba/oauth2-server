package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/elmalba/oauth2-server"
)

func main() {
	srv := oauth2.CreateServer("https://xn--ensea-rta.cl", "/oauth2")

	client := oauth2.Client{}
	client.ClientID = "1234"
	client.Secret = "lala1234"
	client.CallBackURL = "https://xn--ensea-rta.cl/md-eit/admin/oauth2callback.php"
	srv.AddClient(&client)

	srv.MiddleWare = func(w http.ResponseWriter, r *http.Request) string {
		return "1"
	}

	srv.DecodeToken = func(userID string) []byte {

		fmt.Println("User : ", userID)
		return []byte(`{
			"user": "lasi",
			"given_name": "John",
			"family_name": "Stone",
			"email": "lalo@example.c",
			"picture": "1524601669",
			"iss": "https://accounts.google.com",
			"iat": 1610368834
		  }`)
	}

	log.Fatal(http.ListenAndServe(":8000", nil))
}
