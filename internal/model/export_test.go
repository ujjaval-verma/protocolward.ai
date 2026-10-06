// SPDX-License-Identifier: Apache-2.0

package model

// export_test.go re-exports package-internal helpers + caps so the
// external _test packages can drive them without making the helpers
// part of the production API. Standard Go pattern.

var (
	Sanitize     = sanitize
	BoundString  = boundString
	StripControl = stripControl
)

const (
	MaxHostnameLen   = maxHostnameLen
	MaxUserAgentLen  = maxUserAgentLen
	MaxClientHints   = maxClientHints
	MaxClientHintLen = maxClientHintLen
)
