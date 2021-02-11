package oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-session/session"
)

type Session struct {
	ID       int
	ClientID string
	Data     string
}

func (s *Session) Load(w http.ResponseWriter, r *http.Request) {
	store, err := session.Start(context.Background(), w, r)
	if err != nil {
		fmt.Fprint(w, err)

	}

	foo, _ := store.Get("oauth")
	b, _ := json.Marshal(foo)
	json.Unmarshal(b, &s)
}

func (s *Session) Save(w http.ResponseWriter, r *http.Request) {

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
