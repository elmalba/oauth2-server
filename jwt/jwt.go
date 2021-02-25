package jwt

import (
	"fmt"

	"github.com/dgrijalva/jwt-go"
)

type userID struct {
	ID    string
	Email string
	jwt.StandardClaims
}

func Decode(authorization, key string) (userID, error) {
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

func GetToken(user, email, key string) string {
	u := userID{}
	u.ID = user
	u.Email = email
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, u)
	tokenString, _ := token.SignedString([]byte(key))
	return tokenString
}
