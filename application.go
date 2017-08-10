package main

import (
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fpe/fpe"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	_ "github.com/go-sql-driver/mysql"
	"github.com/goware/cors"
	"github.com/unrolled/secure"
)

// The RequestValues type describes the structure of the body of POST requests.
// The structure is json of this structure:
// {
//   "values": ["message", "values"],
//   "tweaks": ["abcdefgh", "12345678"]
// }
type RequestValues struct {
	Values []string `json:"values"`
	Tweaks []string `json:"tweaks"`
}

// The ResponseValues type describes the structure of the all responses.
// The structure is json of this structure:
// {
//   "values": ["message", "values"]
// }
type ResponseValues struct {
	Values []string `json:"values"`
}

var arks = make(map[string]fpe.Algorithm)

func getValuesFromURLParam(r *http.Request) ([]string, [][]byte, error) {
	values := r.URL.Query()["q"]
	if len(values) == 1 {
		values = strings.Split(values[0], ",")
	}

	tweakStrings := r.URL.Query()["tweaks"]
	if len(tweakStrings) == 1 {
		tweakStrings = strings.Split(tweakStrings[0], ",")
	}

	tweaks := make([][]byte, len(tweakStrings))
	for i := 0; i < len(tweakStrings); i++ {
		var err error
		tweaks[i], err = hex.DecodeString(tweakStrings[i])
		if err != nil {
			return nil, nil, err
		}
	}

	return values, tweaks, nil
}

func getValuesFromBody(r *http.Request) (RequestValues, error) {
	decoder := json.NewDecoder(r.Body)
	var requestValues RequestValues
	err := decoder.Decode(&requestValues)
	defer r.Body.Close()
	return requestValues, err
}

// GetEncryptHandler handles requests for GET /v1/ark/{arkname}/encrypt
// Takes a query parameter 'q' that is a comma separated list of values to encrypt
// and returns a response body of type ResponseValues.
func GetEncryptHandler(w http.ResponseWriter, r *http.Request) {
	ark := arks[chi.URLParam(r, "arkName")]
	values, tweaks, err := getValuesFromURLParam(r)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		return
	}
	payload := ResponseValues{Values: []string{}}
	for i := 0; i < len(values); i++ {
		value := values[i]
		tweak := []byte{}
		if i < len(tweaks) {
			tweak = tweaks[i]
		}
		message, err := ark.Encrypt(string(value), tweak)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(err.Error()))
			return
		}
		payload.Values = append(payload.Values, strings.ToUpper(message))
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(payload)
	return
}

// PostEncryptHandler handles requests for POST /v1/ark/{arkname}/encrypt
// Takes a json body of structure RequestValues and returns a body of structure
// ResponseValues.
func PostEncryptHandler(w http.ResponseWriter, r *http.Request) {
	ark := arks[chi.URLParam(r, "arkName")]
	requestValues, err := getValuesFromBody(r)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		return
	}
	payload := ResponseValues{Values: []string{}}
	for i := 0; i < len(requestValues.Values); i++ {
		value := requestValues.Values[i]
		tweak := []byte{}
		if i < len(requestValues.Tweaks) {
			tweak, err = hex.DecodeString(requestValues.Tweaks[i])
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(err.Error()))
				return
			}
		}
		message, err := ark.Encrypt(string(value), tweak)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(err.Error()))
			return
		}
		payload.Values = append(payload.Values, strings.ToUpper(message))
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(payload)
	return
}

// GetDecryptHandler handles requests for GET /v1/ark/{arkname}/decrypt
// Takes a query parameter 'q' that is a comma separated list of values to decrypt
// and returns a response body of type ResponseValues.
func GetDecryptHandler(w http.ResponseWriter, r *http.Request) {
	ark := arks[chi.URLParam(r, "arkName")]
	values, tweaks, err := getValuesFromURLParam(r)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		return
	}
	payload := ResponseValues{Values: []string{}}
	for i := 0; i < len(values); i++ {
		value := values[i]
		tweak := []byte{}
		if i < len(tweaks) {
			tweak = tweaks[i]
		}
		message, err := ark.Decrypt(string(value), tweak)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(err.Error()))
			return
		}
		payload.Values = append(payload.Values, strings.ToUpper(message))
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(payload)
	return
}

// PostDecryptHandler handles requests for POST /v1/ark/{arkname}/decrypt
// Takes a json body of structure RequestValues and returns a body of structure
// ResponseValues.
func PostDecryptHandler(w http.ResponseWriter, r *http.Request) {
	ark := arks[chi.URLParam(r, "arkName")]
	requestValues, err := getValuesFromBody(r)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		return
	}
	payload := ResponseValues{Values: []string{}}
	for i := 0; i < len(requestValues.Values); i++ {
		value := requestValues.Values[i]
		tweak := []byte{}
		if i < len(requestValues.Tweaks) {
			tweak, err = hex.DecodeString(requestValues.Tweaks[i])
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(err.Error()))
				return
			}
		}
		message, err := ark.Decrypt(string(value), tweak)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(err.Error()))
			return
		}
		payload.Values = append(payload.Values, strings.ToUpper(message))
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(payload)
	return
}

// ArkCtx checks to make sure the arkName URL parameter is valid ARK name and returns
// a 404 if it cannot be found.
func ArkCtx(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		arkName := chi.URLParam(r, "arkName")
		_, found := arks[arkName]
		if found {
			next.ServeHTTP(w, r)
		} else {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("ARK name not configured"))
		}
	})
}

// APIKeyValid checks to make sure the provided API key is valid and returns an error
// otherwise.
func APIKeyValid(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := strings.Trim(r.Header.Get("Authorization"), "Bearer ")
		if key == "" {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("You need a valid token."))
			return
		}

		db, err := sql.Open("mysql", "/anthem_fpe?parseTime=true")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(err.Error()))
			return
		}
		defer db.Close()

		var foundKey string // foundKey doesn't do anything atm, Scan requires an arg
		err = db.QueryRow("SELECT value FROM api_keys WHERE value=?", key).Scan(&foundKey)
		switch {
		case err == sql.ErrNoRows:
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("You need a valid token."))
			return
		case err != nil:
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(err.Error()))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func main() {
	ff1, _ := fpe.NewFF1("2B7E151628AED2A6ABF7158809CF4F3C", 36, 2, 20, 16)
	arks["ff1"] = &ff1
	ff3, _ := fpe.NewFF3("2B7E151628AED2A6ABF7158809CF4F3C", 36, 2, 20)
	arks["ff3"] = &ff3

	secureMiddleware := secure.New(secure.Options{
		FrameDeny:        true,
		BrowserXssFilter: true,
	})

	r := chi.NewRouter()

	cors := cors.New(cors.Options{
		// AllowedOrigins: []string{"https://foo.com"}, // Use this to allow specific origin hosts
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	})
	r.Use(cors.Handler)

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(secureMiddleware.Handler)

	r.Route("/v1/ark/{arkName}", func(r chi.Router) {
		r.Use(ArkCtx)
		r.Use(APIKeyValid)

		r.Get("/encrypt", GetEncryptHandler)
		r.Post("/encrypt", PostEncryptHandler)
		r.Get("/decrypt", GetDecryptHandler)
		r.Post("/decrypt", PostDecryptHandler)
	})

	f, _ := os.Create("/var/log/golang/fpe-server.log")
	defer f.Close()
	log.SetOutput(f)

	port := os.Getenv("PORT")
	if port == "" {
		port = "80"
	}
	log.Printf("Listening on port %s\n\n", port)
	http.ListenAndServe(":"+port, r)
}
