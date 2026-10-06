// SPDX-License-Identifier: Apache-2.0

//go:build js && wasm

// Command wardwasm is the browser build of Ward's decision path. It
// registers globalThis.ward with four synchronous functions (init,
// assess, decide, exportConfig) that wrap the natively-tested
// cmd/wardwasm/internal/demo package. It makes no network calls and has
// no filesystem (invariant 4). Build with `make wasm`.
package main

import (
	"context"
	"errors"
	"fmt"
	"syscall/js"

	"protocolward.ai/ward/cmd/wardwasm/internal/demo"
)

func main() {
	d := demo.New()
	ward := js.Global().Get("Object").New()
	ward.Set("init", js.FuncOf(guard(func(args []js.Value) any { return initJS(d, args) })))
	ward.Set("assess", js.FuncOf(guard(func(args []js.Value) any { return assessJS(d, args) })))
	ward.Set("decide", js.FuncOf(guard(func(args []js.Value) any { return decideJS(d, args) })))
	ward.Set("exportConfig", js.FuncOf(guard(func(_ []js.Value) any { return exportJS(d) })))
	js.Global().Set("ward", ward)
	select {} // keep the runtime alive so the callbacks stay valid
}

// guard turns a panic inside a callback into an {error} object. An
// unrecovered panic would kill the Go runtime and break every later call
// on the page. The panic value is deliberately not echoed: it is Go
// runtime text the page cannot act on.
func guard(fn func(args []js.Value) any) func(js.Value, []js.Value) any {
	return func(_ js.Value, args []js.Value) (out any) {
		defer func() {
			if r := recover(); r != nil {
				out = map[string]any{"error": "internal error: the demo could not process that input"}
			}
		}()
		return fn(args)
	}
}

func errorObject(err error) map[string]any {
	return map[string]any{"error": demo.ErrorMessage(err)}
}

// typeOf returns v's JS type. syscall/js panics on types it does not model
// (BigInt), so ok=false means "unsupported type", never a crash.
func typeOf(v js.Value) (t js.Type, ok bool) {
	defer func() {
		if recover() != nil {
			t, ok = js.TypeUndefined, false
		}
	}()
	return v.Type(), true
}

func isType(v js.Value, want js.Type) bool {
	t, ok := typeOf(v)
	return ok && t == want
}

// getProp reads obj[key] through Reflect.get. Unlike js.Value.Get,
// js.Value.Call catches a JS exception and turns it into a Go panic that
// callers recover, so a throwing getter or Proxy trap cannot escape as an
// uncaught JS exception (which would abandon the Go goroutine and leak
// wasm heap).
func getProp(obj js.Value, key any) js.Value {
	return js.Global().Get("Reflect").Call("get", obj, key)
}

var errUnreadable = errors.New("init: the config could not be read (a getter or proxy threw); pass plain objects and arrays")

func initJS(d *demo.Demo, args []js.Value) (out any) {
	fail := func(err error) any { return map[string]any{"ok": false, "error": err.Error()} }
	defer func() {
		if recover() != nil { // a JS exception surfaced by Call
			out = fail(errUnreadable)
		}
	}()
	if len(args) != 1 || !isType(args[0], js.TypeObject) || isArray(args[0]) {
		return fail(errors.New("init: expected one object argument {decoys, blocklist, allowlist}"))
	}
	var cfg demo.Config
	var err error
	if cfg.Decoys, err = stringList(args[0], "decoys"); err != nil {
		return fail(err)
	}
	if cfg.Blocklist, err = stringList(args[0], "blocklist"); err != nil {
		return fail(err)
	}
	if cfg.Allowlist, err = stringList(args[0], "allowlist"); err != nil {
		return fail(err)
	}
	if err := d.Init(cfg); err != nil {
		return fail(err)
	}
	return map[string]any{"ok": true}
}

// stringList reads obj[key] as a string array. A missing key or null means
// an empty list. The array length is checked before any element is copied;
// per-entry length is enforced by demo.Init (MaxInputLen). Property reads go
// through getProp; a JS exception becomes a panic recovered by initJS.
//
// NOTE: js.Value.Length panics on JS string primitives (it requires an
// object; the panic is mislabelled "Value.SetIndex" in go1.26), so the
// length is read as a property of a value already known to be an array.
func stringList(obj js.Value, key string) ([]string, error) {
	v := getProp(obj, key)
	if v.IsUndefined() || v.IsNull() {
		return nil, nil
	}
	if !isType(v, js.TypeObject) || !isArray(v) {
		return nil, fmt.Errorf("init: %s must be an array of strings", key)
	}
	lv := getProp(v, "length")
	if !isType(lv, js.TypeNumber) {
		return nil, fmt.Errorf("init: %s must be an array of strings", key)
	}
	n := lv.Int()
	if err := demo.CheckListLen(key, n); err != nil {
		return nil, err
	}
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		e := getProp(v, i)
		if !isType(e, js.TypeString) {
			return nil, fmt.Errorf("init: %s[%d] must be a string", key, i)
		}
		out = append(out, e.String())
	}
	return out, nil
}

func isArray(v js.Value) bool {
	return js.Global().Get("Array").Call("isArray", v).Bool()
}

// nameArg checks the single hostname argument of assess/decide is a string.
// Shape and length (≤ 253) are validated natively by demo's normalizeName.
func nameArg(fn string, args []js.Value) (string, error) {
	if len(args) != 1 || !isType(args[0], js.TypeString) {
		return "", fmt.Errorf("%s: expected one string argument", fn)
	}
	return args[0].String(), nil
}

func assessJS(d *demo.Demo, args []js.Value) any {
	name, err := nameArg("assess", args)
	if err != nil {
		return errorObject(err)
	}
	a, err := d.Assess(context.Background(), name)
	if err != nil {
		return errorObject(err)
	}
	return a.Map()
}

func decideJS(d *demo.Demo, args []js.Value) any {
	name, err := nameArg("decide", args)
	if err != nil {
		return errorObject(err)
	}
	dec, err := d.Decide(name)
	if err != nil {
		return errorObject(err)
	}
	return dec.Map()
}

// exportJS ignores its arguments so ward.exportConfig can be used directly
// as a DOM event handler.
func exportJS(d *demo.Demo) any {
	out, err := d.ExportConfig()
	if err != nil {
		return errorObject(err)
	}
	return out
}
