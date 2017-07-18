package main

import (
	"encoding/json"
	"fpe/fpe"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/goware/cors"
	"github.com/unrolled/secure"
)

type MessageValues struct {
	Values []string `json:"values"`
}

var arks map[string]fpe.Algorithm = make(map[string]fpe.Algorithm)

func getValuesFromURLParam(r *http.Request) []string {
	values := r.URL.Query()["q"]
	if len(values) == 1 {
		values = strings.Split(values[0], ",")
	}

	return values
}

func getValuesFromBody(r *http.Request) (MessageValues, error) {
	decoder := json.NewDecoder(r.Body)
	var messageValues MessageValues
	err := decoder.Decode(&messageValues)
	defer r.Body.Close()
	return messageValues, err
}

func GetEncryptHandler(w http.ResponseWriter, r *http.Request) {
	ark := arks[chi.URLParam(r, "arkName")]
	values := getValuesFromURLParam(r)
	payload := MessageValues{Values: []string{}}
	for i := 0; i < len(values); i++ {
		value := values[i]
		message, err := ark.Encrypt(string(value), []byte{})
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Unable to encrypt value: " + value))
			return
		}
		payload.Values = append(payload.Values, strings.ToUpper(message))
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(payload)
	return
}

func PostEncryptHandler(w http.ResponseWriter, r *http.Request) {
	ark := arks[chi.URLParam(r, "arkName")]
	messageValues, err := getValuesFromBody(r)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Unable to parse values"))
		return
	}
	payload := MessageValues{Values: []string{}}
	for i := 0; i < len(messageValues.Values); i++ {
		value := messageValues.Values[i]
		message, err := ark.Encrypt(string(value), []byte{})
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Unable to encrypt value: " + value))
			return
		}
		payload.Values = append(payload.Values, strings.ToUpper(message))
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(payload)
	return
}

func GetDecryptHandler(w http.ResponseWriter, r *http.Request) {
	ark := arks[chi.URLParam(r, "arkName")]
	values := getValuesFromURLParam(r)
	payload := MessageValues{Values: []string{}}
	for i := 0; i < len(values); i++ {
		value := values[i]
		message, err := ark.Decrypt(string(value), []byte{})
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Unable to decrypt value: " + value))
			return
		}
		payload.Values = append(payload.Values, strings.ToUpper(message))
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(payload)
	return
}

func PostDecryptHandler(w http.ResponseWriter, r *http.Request) {
	ark := arks[chi.URLParam(r, "arkName")]
	messageValues, err := getValuesFromBody(r)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Unable to parse values"))
		return
	}
	payload := MessageValues{Values: []string{}}
	for i := 0; i < len(messageValues.Values); i++ {
		value := messageValues.Values[i]
		message, err := ark.Decrypt(string(value), []byte{})
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Unable to decrypt value: " + value))
			return
		}
		payload.Values = append(payload.Values, strings.ToUpper(message))
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(payload)
	return
}

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
