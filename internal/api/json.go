package api

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"

	"github.com/marcioamatte/pki-dash/internal/auth"
	"github.com/marcioamatte/pki-dash/internal/ca"
	"github.com/marcioamatte/pki-dash/internal/service"
	"github.com/marcioamatte/pki-dash/internal/store"
	"github.com/marcioamatte/pki-dash/internal/vault"
)

const maxBody = 1 << 20 // 1 MiB

// apiError is an error with a deliberate status and a client-safe message.
type apiError struct {
	status int
	code   string
	msg    string
}

func (e *apiError) Error() string { return e.msg }

func badRequest(msg string) error { return &apiError{http.StatusBadRequest, "bad_request", msg} }

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": msg}})
}

// decode reads a strict JSON body: right content type, bounded size, no
// unknown fields, no trailing data.
func decode(w http.ResponseWriter, r *http.Request, v any) error {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mt != "application/json" {
		return &apiError{http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json"}
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			return &apiError{http.StatusRequestEntityTooLarge, "too_large", "request body too large"}
		}
		return badRequest("malformed JSON body")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return badRequest("unexpected data after JSON body")
	}
	return nil
}

// mapError turns an error into a response. Only validation-type errors echo
// their text; anything unexpected is logged here and reported generically.
func mapError(w http.ResponseWriter, r *http.Request, log *slog.Logger, err error) {
	var ae *apiError
	switch {
	case errors.As(err, &ae):
		writeErr(w, ae.status, ae.code, ae.msg)

	case errors.Is(err, auth.ErrInvalidCredentials):
		writeErr(w, http.StatusUnauthorized, "invalid_credentials", "invalid username or password")
	case errors.Is(err, auth.ErrInvalidSession):
		writeErr(w, http.StatusUnauthorized, "unauthenticated", "authentication required")
	case errors.Is(err, auth.ErrExternalUser):
		writeErr(w, http.StatusConflict, "external_user", "this user is managed by the identity provider")
	case errors.Is(err, auth.ErrForbidden):
		writeErr(w, http.StatusForbidden, "forbidden", "you are not allowed to do this")
	case errors.Is(err, vault.ErrBadPassphrase):
		writeErr(w, http.StatusUnauthorized, "invalid_passphrase", "wrong master passphrase")

	case errors.Is(err, service.ErrLocked):
		writeErr(w, http.StatusConflict, "vault_locked", "the vault is locked; unlock it with the master passphrase")
	case errors.Is(err, service.ErrNotInitialized):
		writeErr(w, http.StatusConflict, "vault_not_initialized", "the vault has not been initialised")
	case errors.Is(err, service.ErrAlreadyInitialized), errors.Is(err, auth.ErrSetupDone):
		writeErr(w, http.StatusConflict, "already_initialized", "already set up")
	case errors.Is(err, service.ErrKeyOffline):
		writeErr(w, http.StatusConflict, "key_offline", "this CA's private key is not held by the service")
	case errors.Is(err, store.ErrNotFound):
		writeErr(w, http.StatusNotFound, "not_found", "not found")
	case errors.Is(err, service.ErrAlreadyRevoked):
		writeErr(w, http.StatusConflict, "already_revoked", "the certificate is already revoked")
	case errors.Is(err, service.ErrCARevoked):
		writeErr(w, http.StatusConflict, "ca_revoked", "this CA is revoked")
	case errors.Is(err, service.ErrAlreadyImported):
		writeErr(w, http.StatusConflict, "already_imported", "this exact CRL is already published")
	case errors.Is(err, ca.ErrCRLNotNewer):
		writeErr(w, http.StatusConflict, "crl_not_newer", err.Error())
	case errors.Is(err, service.ErrNotIntermediate):
		writeErr(w, http.StatusUnprocessableEntity, "policy_violation", "only an intermediate CA can be revoked")
	case errors.Is(err, service.ErrNoCRL):
		writeErr(w, http.StatusNotFound, "no_crl", "this CA has not published a CRL")
	case errors.Is(err, store.ErrExists):
		writeErr(w, http.StatusConflict, "already_exists", "already exists")
	case errors.Is(err, store.ErrLastAdmin):
		writeErr(w, http.StatusConflict, "last_admin", "cannot remove the last active admin")

	case errors.Is(err, service.ErrIssueFromRoot), errors.Is(err, service.ErrBadParent), errors.Is(err, service.ErrNotARoot),
		errors.Is(err, ca.ErrExceedsParent), errors.Is(err, ca.ErrPathLenExhausted),
		errors.Is(err, ca.ErrPolicy), errors.Is(err, ca.ErrKeyMismatch):
		writeErr(w, http.StatusUnprocessableEntity, "policy_violation", err.Error())

	case errors.Is(err, auth.ErrWeakPassword), errors.Is(err, auth.ErrInvalidUsername), errors.Is(err, auth.ErrInvalidRole),
		errors.Is(err, vault.ErrWeakPassphrase), errors.Is(err, ca.ErrInvalidRequest), errors.Is(err, ca.ErrWeakKey),
		errors.Is(err, ca.ErrUnsupportedAlgo), errors.Is(err, store.ErrInvalid):
		writeErr(w, http.StatusBadRequest, "invalid_input", err.Error())

	default:
		log.Error("request failed", "method", r.Method, "path", r.URL.Path, "request_id", requestID(r), "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "internal error")
	}
}
