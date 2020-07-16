// Package ygg implements yggdrasil authentication system
package ygg

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"goygg/internal/config"
	"goygg/internal/ygg/model"
	"io"
	"io/ioutil"
	"math/rand"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type serverMeta struct {
	Meta               map[string]string `json:"meta"`
	SkinDomains        []string          `json:"skinDomains"`
	SignaturePublicKey string            `json:"signaturePublickey"`
}

func (h *Handler) makePassword(password string) string {
	hash := sha256.Sum256([]byte(h.Config.Salt + password))

	return hex.EncodeToString(hash[:])
}

func (h *Handler) handleServerMeta(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		srvErrHTTP(writer, http.StatusMethodNotAllowed)
		return
	}

	bs, err := x509.MarshalPKIXPublicKey(&h.PrivateKey.PublicKey)
	if err != nil {
		panic(err)
	}

	writer.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(writer).Encode(serverMeta{
		SkinDomains: h.Config.SkinDomains,
		Meta:        h.Config.Meta,
		SignaturePublicKey: string(pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: bs,
		})),
	})
}

type inputAuthenticate struct {
	Username    string `json:"username"`
	Password    string `json:"password"`
	ClientToken string `json:"clientToken,omitempty"`
	RequestUser bool   `json:"requestUser"`
	Agent       struct {
		Name    string `json:"name"`
		Version int    `json:"version"`
	} `json:"agent"`
}

type outputAuthenticate struct {
	AccessToken       string           `json:"accessToken"`
	ClientToken       string           `json:"clientToken"`
	AvailableProfiles []*serverProfile `json:"availableProfiles"`
	SelectProfile     *serverProfile   `json:"selectedProfile,omitempty"`
	User              *serverUser      `json:"user,omitempty"`
}

func (h *Handler) handleAuthenticate(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		srvErrHTTP(writer, http.StatusMethodNotAllowed)
		return
	}

	input := &inputAuthenticate{}

	err := json.NewDecoder(request.Body).Decode(input)
	if err != nil {
		srvErrError(writer, err)
		return
	}

	password := h.makePassword(input.Password)

	user, err := h.Repository.LoadUserByEmail(request.Context(), input.Username)
	if err != nil {
		srvErrInvalidPassword(writer)
		return
	}

	if user.Password != password {
		srvErrInvalidPassword(writer)
		return
	}

	err = h.Repository.RemoveTokens(request.Context(), user.ID)
	if err != nil {
		srvErrError(writer, err)
		return
	}

	token, err := h.Repository.CreateToken(request.Context(), user.ID, input.ClientToken)
	if err != nil {
		srvErrError(writer, err)
		return
	}

	var userout *serverUser
	if input.RequestUser {
		userout = &serverUser{
			ID: user.ID,
		}
	}

	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(&outputAuthenticate{
		AccessToken: token.Access,
		ClientToken: token.Client,
		AvailableProfiles: []*serverProfile{
			{
				ID:   user.ProfileID,
				Name: user.ProfileName,
			},
		},
		SelectProfile: &serverProfile{
			ID:   user.ProfileID,
			Name: user.ProfileName,
		},
		User: userout,
	})
}

type inputRefresh struct {
	AccessToken     string         `json:"accessToken"`
	ClientToken     string         `json:"clientToken"`
	RequestUser     bool           `json:"requestUser"`
	SelectedProfile *serverProfile `json:"selectedProfile"`
}

type outputRefresh struct {
	AccessToken   string         `json:"accessToken"`
	ClientToken   string         `json:"clientToken"`
	SelectProfile *serverProfile `json:"selectedProfile,omitempty"`
	User          *serverUser    `json:"user,omitempty"`
}

func (h *Handler) handleRefresh(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		srvErrHTTP(writer, http.StatusMethodNotAllowed)
		return
	}

	bs, err := ioutil.ReadAll(request.Body)
	if err != nil {
		srvErrError(writer, err)
		return
	}

	input := &inputRefresh{}

	err = json.Unmarshal(bs, input)
	if err != nil {
		srvErrError(writer, err)
		return
	}

	token, err := h.Repository.LoadTokenByAccess(request.Context(), input.AccessToken)
	if token == nil {
		token, err = h.Repository.LoadTokenByClient(request.Context(), input.ClientToken)
	}

	if err != nil {
		srvErrInvalidToken(writer)
		return
	}

	user, err := h.Repository.LoadUserByID(request.Context(), token.UserID)
	if err != nil {
		srvErrError(writer, err)
		return
	}

	token, err = h.Repository.UpdateToken(request.Context(), token.UserID)
	if err != nil {
		srvErrInvalidToken(writer)
		return
	}

	var userout *serverUser
	if input.RequestUser {
		userout = &serverUser{
			ID: user.ID,
		}
	}

	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(&outputRefresh{
		AccessToken: token.Access,
		ClientToken: token.Client,
		SelectProfile: &serverProfile{
			ID:   user.ProfileID,
			Name: user.ProfileName,
		},
		User: userout,
	})
}

type inputValidate struct {
	AccessToken string `json:"accessToken"`
	ClientToken string `json:"clientToken"`
}

func (h *Handler) handleValidate(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		srvErrHTTP(writer, http.StatusMethodNotAllowed)
		return
	}

	input := &inputValidate{}

	err := json.NewDecoder(request.Body).Decode(input)
	if err != nil {
		srvErrError(writer, err)
		return
	}

	token, err := h.Repository.LoadTokenByAccess(request.Context(), input.AccessToken)
	if err != nil {
		srvErrInvalidToken(writer)
		return
	}

	if token.Client != input.ClientToken {
		srvErrInvalidToken(writer)
		return
	}

	writer.WriteHeader(http.StatusNoContent)
}

type inputInvalidate struct {
	AccessToken string `json:"accessToken"`
}

func (h *Handler) handleInvalidate(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		srvErrHTTP(writer, http.StatusMethodNotAllowed)
		return
	}

	input := &inputInvalidate{}

	err := json.NewDecoder(request.Body).Decode(input)
	if err != nil {
		srvErrError(writer, err)
		return
	}

	token, err := h.Repository.LoadTokenByAccess(request.Context(), input.AccessToken)
	if err != nil {
		srvErrInvalidToken(writer)
		return
	}

	_, err = h.Repository.UpdateToken(request.Context(), token.UserID)
	if err != nil {
		srvErrInvalidToken(writer)
		return
	}

	writer.WriteHeader(http.StatusNoContent)
}

type inputSignout struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (h *Handler) handleSignout(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		srvErrHTTP(writer, http.StatusMethodNotAllowed)
		return
	}

	input := &inputSignout{}

	err := json.NewDecoder(request.Body).Decode(input)
	if err != nil {
		srvErrError(writer, err)
		return
	}

	user, err := h.Repository.LoadUserByEmail(request.Context(), input.Username)
	if err != nil {
		srvErrInvalidPassword(writer)
		return
	}

	password := h.makePassword(input.Password)

	if user.Password != password {
		srvErrInvalidPassword(writer)
		return
	}

	err = h.Repository.RemoveTokens(request.Context(), user.ID)
	if err != nil {
		srvErrError(writer, err)
		return
	}

	writer.WriteHeader(http.StatusNoContent)
}

type inputJoin struct {
	AccessToken     string `json:"accessToken"`
	SelectedProfile string `json:"selectedProfile"`
	ServerID        string `json:"serverId"`
}

func (h *Handler) handleJoin(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		srvErrHTTP(writer, http.StatusMethodNotAllowed)
		return
	}

	input := &inputJoin{}

	err := json.NewDecoder(request.Body).Decode(input)
	if err != nil {
		srvErrError(writer, err)
		return
	}

	_, err = h.Repository.LoadTokenByAccess(request.Context(), input.AccessToken)
	if err != nil {
		srvErrInvalidToken(writer)
		return
	}

	writer.WriteHeader(http.StatusNoContent)
}

func (h *Handler) handleHasJoined(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		srvErrHTTP(writer, http.StatusMethodNotAllowed)
		return
	}

	username := request.URL.Query().Get("username")

	user, err := h.Repository.LoadUserByName(request.Context(), username)
	if err != nil {
		writer.WriteHeader(http.StatusNoContent)
		return
	}

	var skin *serverTexture

	if user.ProfileTextureSkinURL != "" {
		skin = &serverTexture{
			URL: user.ProfileTextureSkinURL,
		}
		if user.ProfileTextureSkinModel != "" {
			skin.Metadata = &serverTextureMetadata{
				Model: user.ProfileTextureSkinModel,
			}
		}
	}

	var cape *serverTexture

	if user.ProfileTextureCapeURL != "" {
		cape = &serverTexture{
			URL: user.ProfileTextureCapeURL,
		}
	}

	raw, err := json.Marshal(&serverProfilePropertyTextures{
		ProfileID:   user.ProfileID,
		ProfileName: user.ProfileName,
		Textures: &serverProfilePropertyTexturesDetails{
			Skin: skin,
			Cape: cape,
		},
		Timestamp: time.Now().Unix() + time.Now().UnixNano()/int64(time.Millisecond),
	})
	if err != nil {
		writer.WriteHeader(http.StatusNoContent)
		return
	}

	b64 := base64.StdEncoding.EncodeToString(raw)
	sh1 := sha1.Sum(([]byte)(b64))

	sig, err := h.PrivateKey.Sign(rand.New(rand.NewSource(time.Now().UnixNano())), sh1[:], crypto.SHA1)
	if err != nil {
		writer.WriteHeader(http.StatusNoContent)
		return
	}

	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(&serverProfile{
		ID:   user.ProfileID,
		Name: user.ProfileName,
		Properties: []*serverProfileProperty{
			{
				Name:      "textures",
				Value:     b64,
				Signature: base64.StdEncoding.EncodeToString(sig),
			},
		},
	})
}

func (h *Handler) handleProfiles(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		srvErrHTTP(writer, http.StatusMethodNotAllowed)
		return
	}

	var names []string

	err := json.NewDecoder(request.Body).Decode(&names)
	if err != nil {
		srvErrError(writer, err)
		return
	}

	var profiles []*serverProfile

	for _, n := range names {
		user, err := h.Repository.LoadUserByName(request.Context(), n)
		if err != nil {
			srvErrError(writer, err)
			return
		}

		profiles = append(profiles, &serverProfile{
			ID:   user.ProfileID,
			Name: user.ProfileName,
		})
	}

	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(&profiles)
}

func (h *Handler) handleProfile(writer http.ResponseWriter, request *http.Request, uuid string) {
	if request.Method != http.MethodGet {
		srvErrHTTP(writer, http.StatusMethodNotAllowed)
		return
	}

	user, err := h.Repository.LoadUserByID(request.Context(), uuid)
	if err != nil {
		srvErrError(writer, err)
		return
	}

	var skin *serverTexture

	if user.ProfileTextureSkinURL != "" {
		skin = &serverTexture{
			URL: user.ProfileTextureSkinURL,
		}

		if user.ProfileTextureSkinModel != "" {
			skin.Metadata = &serverTextureMetadata{
				Model: user.ProfileTextureSkinModel,
			}
		}
	}

	var cape *serverTexture

	if user.ProfileTextureCapeURL != "" {
		cape = &serverTexture{
			URL: user.ProfileTextureCapeURL,
		}
	}

	raw, err := json.Marshal(&serverProfilePropertyTextures{
		ProfileID:   user.ProfileID,
		ProfileName: user.ProfileName,
		Textures: &serverProfilePropertyTexturesDetails{
			Skin: skin,
			Cape: cape,
		},
		Timestamp: time.Now().Unix() + time.Now().UnixNano()/int64(time.Millisecond),
	})
	if err != nil {
		writer.WriteHeader(http.StatusNoContent)
		return
	}

	b64 := base64.StdEncoding.EncodeToString(raw)

	writer.Header().Set("Content-Type", "application/json")

	if request.URL.Query().Get("unsigned") == "true" {
		_ = json.NewEncoder(writer).Encode(&serverProfile{
			ID:   user.ProfileID,
			Name: user.ProfileName,
			Properties: []*serverProfileProperty{
				{
					Name:  "textures",
					Value: b64,
				},
			},
		})
	} else {
		sh1 := sha1.Sum(([]byte)(b64))

		sig, err := rsa.SignPKCS1v15(rand.New(rand.NewSource(time.Now().UnixNano())), h.PrivateKey, crypto.SHA1, sh1[:])
		if err != nil {
			writer.WriteHeader(http.StatusNoContent)
			return
		}

		_ = json.NewEncoder(writer).Encode(&serverProfile{
			ID:   user.ProfileID,
			Name: user.ProfileName,
			Properties: []*serverProfileProperty{
				{
					Name:      "textures",
					Value:     b64,
					Signature: base64.StdEncoding.EncodeToString(sig),
				},
			},
		})
	}
}

func (h *Handler) handleTexture(writer http.ResponseWriter, request *http.Request, texid string) {
	if request.Method != http.MethodGet {
		srvErrHTTP(writer, http.StatusMethodNotAllowed)
		return
	}

	fpath := filepath.Join(h.Config.TexturesDir, texid)

	f, err := os.OpenFile(fpath, os.O_RDONLY, 0644)
	if err != nil {
		srvErrHTTP(writer, http.StatusNotFound)
		return
	}

	stat, err := f.Stat()
	if err != nil {
		srvErrHTTP(writer, http.StatusNotFound)
		return
	}

	writer.Header().Set("Content-Length", strconv.FormatInt(stat.Size(), 10))
	writer.Header().Set("Content-Type", "image/png")

	_, _ = io.Copy(writer, f)
}

func firstString(arr []string) string {
	if arr == nil {
		return ""
	}

	return arr[0]
}

func firstFile(arr []*multipart.FileHeader) *multipart.FileHeader {
	if arr == nil {
		return nil
	}

	return arr[0]
}

func (h *Handler) copyFile(skin *multipart.FileHeader) (string, error) {
	f, err := skin.Open()
	if err != nil {
		return "", err
	}

	defer func() {
		_ = f.Close()
	}()

	bs, err := ioutil.ReadAll(f)
	if err != nil {
		return "", err
	}

	sh := sha256.New()
	_, _ = sh.Write(bs)

	sh256 := sh.Sum(nil)
	hc := hex.EncodeToString(sh256)

	_, err = f.Seek(0, io.SeekStart)
	if err != nil {
		return "", err
	}

	target := filepath.Join(h.Config.TexturesDir, hc)

	tf, err := os.OpenFile(target, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return "", err
	}

	defer func() {
		_ = tf.Close()
	}()

	_, err = io.Copy(tf, f)
	if err != nil {
		return "", err
	}

	return hc, nil
}

func (h *Handler) updateUser(
	writer http.ResponseWriter,
	request *http.Request,
	user *model.User,
	skinmodel, password, nickname string,
	skin, cape *multipart.FileHeader,
) (err error) {
	if user.Password != password {
		srvErr(writer, "IllegalArgumentException", "Invalid paramaters", "Invalid password")
		return
	}

	if nickname != "" {
		user.ProfileName = nickname
	}

	if skinmodel != "" {
		if skinmodel != "default" && skinmodel != "slim" {
			srvErr(writer, "IllegalArgumentException", "Invalid paramaters", "skinmodel must be either default or slim")
			return
		}

		user.ProfileTextureSkinModel = skinmodel
	}

	var hc string

	if skin != nil {
		hc, err = h.copyFile(skin)
		if err != nil {
			srvErrError(writer, err)
			return
		}

		user.ProfileTextureSkinURL = h.Config.External + "/texture/" + hc
	} else {
		user.ProfileTextureSkinURL = ""
	}

	if cape != nil {
		hc, err = h.copyFile(cape)
		if err != nil {
			srvErrError(writer, err)
			return
		}

		user.ProfileTextureCapeURL = h.Config.External + "/texture/" + hc
	} else {
		user.ProfileTextureCapeURL = ""
	}

	err = h.Repository.UpdateUser(request.Context(), user)
	if err != nil {
		srvErrError(writer, err)
		return
	}

	writer.Header().Set("Location", h.Config.External+"/signup?success=true")
	writer.WriteHeader(http.StatusFound)

	return nil
}

func (h *Handler) handleRegister(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		srvErrHTTP(writer, http.StatusMethodNotAllowed)
		return
	}

	err := request.ParseMultipartForm(1024 * 1024 * 100)
	if err != nil {
		srvErrError(writer, err)
		return
	}

	values := request.MultipartForm.Value
	email := firstString(values["email"])
	nickname := firstString(values["nickname"])
	skinmodel := firstString(values["model"])
	rawpass := firstString(values["password"])

	if rawpass == "" {
		srvErr(writer, "IllegalArgumentException", "Invalid paramaters", "Password required")
		return
	}

	password := h.makePassword(rawpass)

	if len(nickname) > 16 {
		srvErrError(writer, fmt.Errorf("name should be within 16 characters"))
		return
	}

	files := request.MultipartForm.File
	skin := firstFile(files["skin"])
	cape := firstFile(files["cape"])

	if email == "" {
		srvErr(writer, "IllegalArgumentException", "Invalid paramaters", "Email required")
		return
	}

	user, err := h.Repository.LoadUserByEmail(request.Context(), email)
	if err == sql.ErrNoRows {
		if nickname == "" {
			srvErr(writer, "IllegalArgumentException", "Invalid paramaters", "Nickname required")
			return
		}

		user, err = h.Repository.CreateUser(request.Context(), nickname, email, password)
		if err != nil {
			srvErrError(writer, err)
			return
		}
	} else if err != nil {
		srvErrError(writer, err)
		return
	}

	err = h.updateUser(writer, request, user, skinmodel, password, nickname, skin, cape)
	if err != nil {
		srvErrError(writer, err)
	}
}

// Handler yggdrasil
type Handler struct {
	Config     *config.Config
	Repository model.Repository
	PrivateKey *rsa.PrivateKey
}

func (h *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodOptions {
		writer.Header().Set("Access-Control-Allow-Origin", request.URL.Scheme+"://"+request.URL.Host)
		writer.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
		writer.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		writer.Header().Set("Access-Control-Allow-Credentials", "true")
		writer.WriteHeader(http.StatusNoContent)

		return
	}

	switch {
	case request.URL.Path == "/":
		h.handleServerMeta(writer, request)
	case request.URL.Path == "/authserver/authenticate":
		h.handleAuthenticate(writer, request)
	case request.URL.Path == "/authserver/refresh":
		h.handleRefresh(writer, request)
	case request.URL.Path == "/authserver/validate":
		h.handleValidate(writer, request)
	case request.URL.Path == "/authserver/invalidate":
		h.handleInvalidate(writer, request)
	case request.URL.Path == "/authserver/signout":
		h.handleSignout(writer, request)
	case request.URL.Path == "/sessionserver/session/minecraft/join":
		h.handleJoin(writer, request)
	case request.URL.Path == "/sessionserver/session/minecraft/hasJoined":
		h.handleHasJoined(writer, request)
	case request.URL.Path == "/api/profiles/minecraft":
		h.handleProfiles(writer, request)
	case strings.HasPrefix(request.URL.Path, "/sessionserver/session/minecraft/profile/"):
		uuid := strings.TrimPrefix(request.URL.Path, "/sessionserver/session/minecraft/profile/")

		h.handleProfile(writer, request, uuid)
	case strings.HasPrefix(request.URL.Path, "/texture/"):
		texid := strings.TrimPrefix(request.URL.Path, "/texture/")

		h.handleTexture(writer, request, texid)
	case request.URL.Path == "/register":
		h.handleRegister(writer, request)
	default:
		srvErrHTTP(writer, http.StatusNotFound)
	}
}
