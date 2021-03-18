package oauth2

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/go-session/session"
)

type Session struct {
	ID       int
	Email    string
	ClientID string
	Data     string
}

func (s *Session) Load(ctx *gin.Context) {

	r := ctx.Request
	w := ctx.Writer
	store, err := session.Start(context.Background(), w, r)
	if err != nil {
		fmt.Fprint(w, err)

	}

	foo, _ := store.Get("oauth")
	b, _ := json.Marshal(foo)
	json.Unmarshal(b, &s)
}

func (s *Session) Save(ctx *gin.Context) {

	r := ctx.Request
	w := ctx.Writer
	store, err := session.Start(context.Background(), w, r)
	if err != nil {
		fmt.Fprint(w, err)
		return
	}
	store.Set("oauth", *s)
	err = store.Save()
	if err != nil {
		fmt.Fprint(w, err)
		return
	}
	return

}
