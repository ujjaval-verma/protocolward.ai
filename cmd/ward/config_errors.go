// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"strings"

	"protocolward.ai/ward/internal/config"
)

// mapConfigLoadError converts a config.Load error into a *serveError with a
// consistent error envelope used by every cmd/ward subcommand (ward serve,
// ward config export, ward doctor). Emits the startup-error stderr line and
// returns the typed error so the cobra layer can exit with the right code.
//
// Extracted from per-subcommand duplication (Ralph N1 ward-doctor slice).
// Adding a new config.* error type → one branch, one file, every subcommand
// benefits.
func mapConfigLoadError(cfgPath string, err error) *serveError {
	var missingErr *config.MissingFileError
	if errors.As(err, &missingErr) {
		msg := fmt.Sprintf("config file not found: %s", cfgPath)
		rem := "create the file or pass --config with the correct path; see ward.example.yaml for a template"
		printStartupError("config error", msg, rem)
		return &serveError{Code: 2, Message: msg, Remediation: rem}
	}
	var ukErr *config.UnknownKeyError
	if errors.As(err, &ukErr) {
		parts := make([]string, len(ukErr.Keys))
		for i, k := range ukErr.Keys {
			parts[i] = k.String()
		}
		msg := fmt.Sprintf("config error in %s: %s", cfgPath, strings.Join(parts, "; "))
		rem := "fix the spelling or remove the key in ward.yaml; see ward.example.yaml for a template"
		printStartupError("config error", msg, rem)
		return &serveError{Code: 2, Message: msg, Remediation: rem}
	}
	var mdErr *config.MultipleDocumentsError
	if errors.As(err, &mdErr) {
		msg := fmt.Sprintf("config error in %s: another document starts at line %d", cfgPath, mdErr.Line)
		rem := "ward.yaml holds exactly one YAML document; remove the extra `---` separator or merge the documents into one"
		printStartupError("config error", msg, rem)
		return &serveError{Code: 2, Message: msg, Remediation: rem}
	}
	var parseErr *config.ParseError
	if errors.As(err, &parseErr) {
		msg := fmt.Sprintf("config parse error in %s: %v", cfgPath, parseErr.Err)
		rem := "check ward.yaml for YAML syntax errors; see ward.example.yaml for a template"
		printStartupError("config error", msg, rem)
		return &serveError{Code: 2, Message: msg, Remediation: rem}
	}
	var valErr *config.ValidationError
	if errors.As(err, &valErr) {
		msg := fmt.Sprintf("config validation error: field %q: %s", valErr.Field, valErr.Message)
		rem := "correct the invalid value in ward.yaml; see ward.example.yaml for a template"
		printStartupError("config error", msg, rem)
		return &serveError{Code: 2, Message: msg, Remediation: rem}
	}
	printStartupError("config error", err.Error(), "check ward.yaml and see ward.example.yaml for a template")
	return &serveError{Code: 2, Message: err.Error(), Remediation: "check ward.yaml"}
}
