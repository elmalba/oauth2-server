package oauth2

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func CreateServer(hostName, basePath string) (*server, *gin.Engine) {
	ws := gin.Default()
	SRV := server{}
	SRV.Clients = make(map[string]*Client)
	uuidWithHyphen := uuid.New()
	uuid := strings.Replace(uuidWithHyphen.String(), "-", "", -1)
	SRV.SetKey(uuid)

	SRV.ValidateClientID = func(ctx *gin.Context, clientID string) (*Client, bool) {
		return SRV.Clients[clientID], SRV.Clients[clientID] != nil
	}

	SRV.ValidateClientIDAndSecretID = func(ctx *gin.Context, clientID, secretID string) bool {
		return clientID != "" && secretID != "" &&
			SRV.Clients[clientID].Secret == secretID
	}

	SRV.Discover = func() []byte {
		url := fmt.Sprintf(`%s%s`, hostName, basePath)
		return []byte(`{
			"issuer": "` + url + `/",
			"authorization_endpoint": "` + url + `/auth",
			"token_endpoint": "` + url + `/token",
			"userinfo_endpoint": "` + url + `/userinfo",
			"revocation_endpoint": "` + url + `/revoke",
			"jwks_uri": "` + url + `/certs",
			"response_types_supported": [
			 "code",
			 "token",
			 "id_token",
			 "code token",
			 "code id_token",
			 "token id_token",
			 "code token id_token",
			 "none"
			],
			"subject_types_supported": [
			 "public"
			],
			"id_token_signing_alg_values_supported": [
			 "RS256"
			],
			"scopes_supported": [
			 "openid",
			 "email",
			 "profile"
			],
			"token_endpoint_auth_methods_supported": [
			 "client_secret_post",
			 "client_secret_basic"
			],
			"claims_supported": [
			 "user",
			 "email",
			 "email_verified"			
			],
			"code_challenge_methods_supported": [
			 "plain",
			 "S256"
			],
			"grant_types_supported": [
			 "authorization_code",
			 "refresh_token",
			 "urn:ietf:params:oauth:grant-type:device_code",
			 "urn:ietf:params:oauth:grant-type:jwt-bearer"
			]
		   }`)

	}

	ws.GET(basePath+"/token", func(ctx *gin.Context) {
		user, passwd, ok := ctx.Request.BasicAuth()

		body2, _ := ioutil.ReadAll(ctx.Request.Body)

		params, _ := url.ParseQuery(string(body2))

		if !ok || !SRV.ValidateClientIDAndSecretID(ctx, user, passwd) {
			ctx.AbortWithStatus(401)
			return
		}

		ctx.String(200, (`{"access_token":"` + params.Get("code") + `","scope":"all","token_type":"Bearer"}`))

		return
	})
	auth := func(ctx *gin.Context) {

		s := Session{}
		s.Load(ctx)
		clientID := ctx.Request.URL.Query().Get("client_id")

		if clientID == "" {
			clientID = s.ClientID
		} else {
			s.ClientID = clientID
			s.Data = ctx.Request.URL.Query().Encode()
		}

		client, valid := SRV.ValidateClientID(ctx, clientID)

		if !valid {
			NewUrl := hostName
			ctx.Redirect(http.StatusSeeOther, NewUrl)
			return
		}

		user, email := SRV.MiddleWare(ctx, &s)
		if user == "" {
			return
		}
		s.Save(ctx)
		token := getToken(user, SRV.key+client.Secret)
		params, _ := url.ParseQuery(s.Data)
		params.Set("code", token)
		uri := client.CallBackURL + `?` + params.Encode()
		expiration := time.Now().Add(365 * 24 * time.Hour)
		cookie := http.Cookie{Name: "ensena", Value: token, Expires: expiration}
		ctx.SetCookie(cookie.Name, cookie.Value, cookie.MaxAge, cookie.Path, cookie.Domain, cookie.Secure, cookie.HttpOnly)
		ctx.Redirect(http.StatusTemporaryRedirect, uri)
	}
	ws.GET(basePath+"/auth", auth)
	ws.POST(basePath+"/auth", auth)

	ws.GET(basePath+"/userinfo", func(ctx *gin.Context) {

		token := ctx.Request.Header.Get("Authorization")

		if token == "" {
			return
		}

		token = strings.Split(token, "Bearer ")[1]

		userTK, err := decode(token, SRV.key+"ggDjxBawQxUnEVeyUzFtpeR8MZQ0rmrQ")

		fmt.Println(userTK, err)
		if err != nil {
			return
		}

		user := SRV.GetUser(ctx, userTK.ID)
		ctx.Writer.Write(user)
		return
	})

	return &SRV, ws
}
