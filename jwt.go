package oauth2

import (
	"fmt"

	"github.com/dgrijalva/jwt-go"
)

var JwtKey = []byte("3nS3nAM3")

type userID struct {
	ID string
	jwt.StandardClaims
}

func decode(authorization, key string) (userID, error) {
	user := userID{}
	token, err := jwt.ParseWithClaims(authorization, &user, func(token *jwt.Token) (interface{}, error) {
		return []byte(key), nil
	})
	if err != nil {
		return userID{}, fmt.Errorf("No valid token")
	}

	if !token.Valid {
		return userID{}, fmt.Errorf("No valid token")
	}
	return user, nil
}

func getToken(user, key string) string {

	u := userID{}
	u.ID = user
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, u)
	tokenString, _ := token.SignedString([]byte(key))
	return tokenString
}
