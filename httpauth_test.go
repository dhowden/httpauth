// Copyright 2015, David Howden
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package httpauth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCreds(t *testing.T) {
	creds := map[string]string{
		"alice": "shhhh",
		"bob":   "",
	}
	tests := []struct {
		username, password string
		valid              bool
	}{
		// Empty, invalid
		{
			"",
			"",
			false,
		},

		// Unknown user
		{
			"cecil",
			"",
			false,
		},

		// Alice, wrong password
		{
			"alice",
			"bob",
			false,
		},

		// Alice, correct password
		{
			"alice",
			"shhhh",
			true,
		},

		// Bob, correct (empty) password
		{
			"bob",
			"",
			true,
		},
	}

	c := Creds(creds)
	for ii, tt := range tests {
		got := c.Check(tt.username, tt.password)
		if got != tt.valid {
			t.Errorf("[%d] c.Check(%#v, %#v) = %#v, expected %#v", ii, tt.username, tt.password, got, tt.valid)
		}
	}

	var nilCreds map[string]string
	c = Creds(nilCreds)

	if c.Check("alice", "") {
		t.Errorf("nil Creds should return false")
	}
}

func TestNone(t *testing.T) {
	n := None{}
	if !n.Check("", "") {
		t.Errorf("n.Check(\"\", \"\") = false, expected: true")
	}
}

func handlerFuncOK(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(http.StatusText(http.StatusOK)))
	return
}

func testHandlerUnauthorised(t *testing.T, url string, h http.Handler) {
	r, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Fatalf("unexpected error creating request: %v", err)
	}

	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("w.Code = %d, expected: %d", w.Code, http.StatusUnauthorized)
	}

	if w.Header().Get("WWW-Authenticate") != "Basic" {
		t.Errorf("w.Header().Get(\"WWW-Authenticate\") = %s, expected: %s", w.Header().Get("WWW-Authenticate"), "Basic")
	}

	body := w.Body
	if body.String() != http.StatusText(http.StatusUnauthorized) {
		t.Errorf("w.Body = %q, expected: %q", body.String(), http.StatusText(http.StatusUnauthorized))
	}
}

func testHandlerOK(t *testing.T, url string, h http.Handler) {
	r, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Fatalf("unexpected error creating request: %v", err)
	}

	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("w.Code = %d, expected: %d", w.Code, http.StatusOK)
	}

	body := w.Body
	if body.String() != http.StatusText(http.StatusOK) {
		t.Errorf("w.Body = %q, expected: %q", body.String(), http.StatusText(http.StatusOK))
	}
}

type fixedChecker bool

func (c fixedChecker) Check(username, password string) bool { return bool(c) }

func TestHandler(t *testing.T) {
	c := fixedChecker(false)
	h := NewHandler(c, http.HandlerFunc(handlerFuncOK))
	testHandlerUnauthorised(t, "/", h)

	c = fixedChecker(true)
	h = NewHandler(c, http.HandlerFunc(handlerFuncOK))
	testHandlerOK(t, "/", h)
}

func TestHandlerFunc(t *testing.T) {
	c := fixedChecker(false)
	h := HandlerFunc(c, handlerFuncOK)
	testHandlerUnauthorised(t, "/", h)

	c = fixedChecker(true)
	h = HandlerFunc(c, handlerFuncOK)
	testHandlerOK(t, "/", h)
}

func TestDefaultHandle(t *testing.T) {
	c := fixedChecker(false)
	HandleFunc(c, "/hfu", handlerFuncOK)
	testHandlerUnauthorised(t, "/hfu", http.DefaultServeMux)

	Handle(c, "/hu", http.HandlerFunc(handlerFuncOK))
	testHandlerUnauthorised(t, "/hu", http.DefaultServeMux)

	c = fixedChecker(true)
	HandleFunc(c, "/hfok", handlerFuncOK)
	testHandlerOK(t, "/hfok", http.DefaultServeMux)

	Handle(c, "/hok", http.HandlerFunc(handlerFuncOK))
	testHandlerOK(t, "/hok", http.DefaultServeMux)
}

func TestServeMux(t *testing.T) {
	c := fixedChecker(false)

	m := http.NewServeMux()
	w := NewServeMux(c, m)
	w.HandleFunc("/f", handlerFuncOK)
	testHandlerUnauthorised(t, "/f", m)

	w.Handle("/h", http.HandlerFunc(handlerFuncOK))
	testHandlerUnauthorised(t, "/h", m)

	c = fixedChecker(true)

	m = http.NewServeMux()
	w = NewServeMux(c, m)
	w.HandleFunc("/f", handlerFuncOK)
	testHandlerOK(t, "/f", m)

	w.Handle("/h", http.HandlerFunc(handlerFuncOK))
	testHandlerOK(t, "/h", m)
}
