package oauth2

import "net/http"

type Client struct {
	ClientID    string
	SecretID    string
	CallBackURL string
}

type server struct {
	Clients                     map[string]*Client
	GenerateCode                func(string) string
	DecodeCode                  func(string) string
	MiddleWare                  func(*http.Request) string
	FindUser                    func(string) []byte
	GenerateToken               func(string, string) string
	DecodeToken                 func(string) []byte
	Discover                    func() []byte
	ValidateClientID            func(string) (*Client, bool)
	ValidateClientIDAndSecretID func(string, string) bool
	key                         string
}

func (o *server) AddClient(c *Client) {
	o.Clients[c.ClientID] = c
}

func (o *server) SetKey(key string) {
	o.key = key
}
