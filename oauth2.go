package oauth2

import "github.com/gin-gonic/gin"

type Client struct {
	ClientID    string
	Secret      string
	CallBackURL string
}

type server struct {
	Clients                     map[string]*Client
	GenerateCode                func(string) string
	DecodeCode                  func(string) string
	MiddleWare                  func(*gin.Context, *Session) string
	GetUser                     func(*gin.Context, string) []byte
	GenerateToken               func(string, string) string
	Discover                    func() []byte
	ValidateClientID            func(*gin.Context, string) (*Client, bool)
	ValidateClientIDAndSecretID func(*gin.Context, string, string) bool
	key                         string
}

func (o *server) AddClient(c *Client) {
	o.Clients[c.ClientID] = c
}

func (o *server) SetKey(key string) {
	o.key = key
}
