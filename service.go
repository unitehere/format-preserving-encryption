package main

import (
	"encoding/json"
	"fpe/fpe"
	"net/http"
	"strings"
	"time"

	"github.com/husobee/vestigo"
)

type MessageValues struct {
	Values []string `json:"values"`
}

var arks map[string]fpe.FF1 = make(map[string]fpe.FF1)

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
	ff1 := arks[vestigo.Param(r, "arkName")]
	values := getValuesFromURLParam(r)
	payload := MessageValues{Values: []string{}}
	for i := 0; i < len(values); i++ {
		value := values[i]
		message, err := ff1.Encrypt(string(value), []byte{})
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Unable to encrypt value: " + value))
			return
		}
		payload.Values = append(payload.Values, message)
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(payload)
	return
}

func PostEncryptHandler(w http.ResponseWriter, r *http.Request) {
	ff1 := arks[vestigo.Param(r, "arkName")]
	messageValues, err := getValuesFromBody(r)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Unable to parse values"))
		return
	}
	payload := MessageValues{Values: []string{}}
	for i := 0; i < len(messageValues.Values); i++ {
		value := messageValues.Values[i]
		message, err := ff1.Encrypt(string(value), []byte{})
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Unable to encrypt value: " + value))
			return
		}
		payload.Values = append(payload.Values, message)
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(payload)
	return
}

func GetDecryptHandler(w http.ResponseWriter, r *http.Request) {
	ff1 := arks[vestigo.Param(r, "arkName")]
	values := getValuesFromURLParam(r)
	payload := MessageValues{Values: []string{}}
	for i := 0; i < len(values); i++ {
		value := values[i]
		message, err := ff1.Decrypt(string(value), []byte{})
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Unable to decrypt value: " + value))
			return
		}
		payload.Values = append(payload.Values, message)
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(payload)
	return
}

func PostDecryptHandler(w http.ResponseWriter, r *http.Request) {
	ff1 := arks[vestigo.Param(r, "arkName")]
	messageValues, err := getValuesFromBody(r)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Unable to parse values"))
		return
	}
	payload := MessageValues{Values: []string{}}
	for i := 0; i < len(messageValues.Values); i++ {
		value := messageValues.Values[i]
		message, err := ff1.Decrypt(string(value), []byte{})
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Unable to decrypt value: " + value))
			return
		}
		payload.Values = append(payload.Values, message)
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(payload)
	return
}

func checkArkName(f http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		arkName := vestigo.Param(r, "arkName")
		_, found := arks[arkName]
		if found {
			f(w, r)
		} else {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("ARK name not configured"))
		}
	}
}

func main() {
	ff1, _ := fpe.NewFF1("2B7E151628AED2A6ABF7158809CF4F3C", 36, 2, 20, 16)
	arks["test"] = ff1

	router := vestigo.NewRouter()
	router.SetGlobalCors(&vestigo.CorsAccessControl{
		AllowOrigin:      []string{"*"},
		AllowCredentials: true,
		ExposeHeaders:    []string{},
		MaxAge:           3600 * time.Second,
		AllowHeaders:     []string{},
	})
	router.Get("/v1/ark/:arkName/encrypt", GetEncryptHandler, checkArkName)
	router.Post("/v1/ark/:arkName/encrypt", PostEncryptHandler, checkArkName)
	router.Get("/v1/ark/:arkName/decrypt", GetDecryptHandler, checkArkName)
	router.Post("/v1/ark/:arkName/decrypt", PostDecryptHandler, checkArkName)

	http.ListenAndServe(":8080", router)
}
