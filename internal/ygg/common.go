package ygg

import (
	"encoding/json"
	"io"
	"net/http"
)

type serverError struct {
	Error        string `json:"error"`
	ErrorMessage string `json:"errorMessage"`
	Cause        string `json:"cause,omitempty"`
}

func srvErr(writer io.Writer, err, msg, cause string) {
	_ = json.NewEncoder(writer).Encode(&serverError{
		Error:        err,
		ErrorMessage: msg,
		Cause:        cause,
	})
}

func srvErrError(writer http.ResponseWriter, err error) {
	writer.WriteHeader(http.StatusInternalServerError)
	srvErr(writer, "IllegalArgumentException", err.Error(), "")
}

func srvErrHTTP(writer http.ResponseWriter, status int) {
	writer.WriteHeader(status)
	srvErr(writer, http.StatusText(status), http.StatusText(status), "")
}

func srvErrInvalidToken(writer http.ResponseWriter) {
	writer.WriteHeader(http.StatusForbidden)
	srvErr(writer, "ForbiddenOperationException", "Invalid token.", "")
}

func srvErrInvalidPassword(writer http.ResponseWriter) {
	writer.WriteHeader(http.StatusForbidden)
	srvErr(writer, "ForbiddenOperationException", "Invalid credentials. Invalid username or password.", "")
}
