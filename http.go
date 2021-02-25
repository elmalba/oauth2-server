package oauth2

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/elmalba/oauth2-server/jwt"
	"github.com/google/uuid"
)

func CreateServer(hostName, basePath string) *server {

	SRV := server{}
	SRV.Clients = make(map[string]*Client)
	uuidWithHyphen := uuid.New()
	uuid := strings.Replace(uuidWithHyphen.String(), "-", "", -1)
	SRV.SetKey(uuid)

	SRV.ValidateClientID = func(clientID string) (*Client, bool) {
		return SRV.Clients[clientID], SRV.Clients[clientID] != nil
	}

	SRV.ValidateClientIDAndSecretID = func(clientID, secretID string) bool {
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

	http.HandleFunc(basePath+"/token", func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()

		body2, _ := ioutil.ReadAll(r.Body)

		params, _ := url.ParseQuery(string(body2))

		if !ok || !SRV.ValidateClientIDAndSecretID(u, p) {
			w.WriteHeader(401)
			return
		}

		w.Write([]byte(`{"access_token":"` + params.Get("code") + `","scope":"all","token_type":"Bearer"}`))

		return
	})
	http.HandleFunc(basePath+"/auth", func(w http.ResponseWriter, r *http.Request) {

		s := Session{}
		s.Load(w, r)
		clientID := r.URL.Query().Get("client_id")

		if clientID == "" {
			clientID = s.ClientID
		} else {
			s.ClientID = clientID
			s.Data = r.URL.Query().Encode()
		}

		client, valid := SRV.ValidateClientID(clientID)

		if !valid {
			NewUrl := hostName + basePath + "/login"
			http.Redirect(w, r, NewUrl, http.StatusSeeOther)
			return
		}

		user := SRV.MiddleWare(w, r, &s)
		if user == "" {
			return
		}
		s.Save(w, r)
		token := jwt.GetToken(user, s.Email, SRV.key)
		params, _ := url.ParseQuery(s.Data)
		params.Set("code", token)
		uri := client.CallBackURL + `?` + params.Encode()
		http.Redirect(w, r, uri, http.StatusSeeOther)

	})

	http.HandleFunc(basePath+"/userinfo", func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if token == "" {
			return
		}
		token = strings.Split(token, "Bearer ")[1]
		userTK, err := jwt.Decode(token, SRV.key)
		fmt.Println(userTK, err)
		if err != nil {
			return
		}
		user := SRV.GetUser(userTK.ID)
		w.Write(user)
		return
	})
	return &SRV
}
