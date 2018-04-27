// Copyright 2015, David Howden
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package httpauth provides a wrapper for http.Handler implementing basic HTTP authentication.
package httpauth

import "net/http"

// Checker defines the Check method which provides username-password checking.
type Checker interface {
	// Check returns true if and only if the username-password pair is valid.
	Check(username, password string) bool
}

// Creds creates a Checker which uses the map of user-password pairs.
func Creds(m map[string]string) Checker {
	return creds{
		m: m,
	}
}

type creds struct {
	m map[string]string
}

// Check implements Checker.
func (c creds) Check(username, password string) bool {
	p, ok := c.m[username]
	return ok && p == password
}

// None is an implementation of Checker in which Check always returns true.
type None struct{}

// Check implements Checker.
func (n None) Check(username, password string) bool { return true }

// HandlerFunc returns an http.HandlerFunc which checks basic HTTP authentication header
// values using Checker and passes requests to the given http.HandlerFunc when Check returns
// true (responds with http.StatusUnauthorized if the call to Check returns false).
func HandlerFunc(c Checker, f http.HandlerFunc) http.HandlerFunc {
	h := NewHandler(c, f)
	return http.HandlerFunc(h.ServeHTTP)
}

type handler struct {
	http.Handler
	c Checker
}

// NewHandler returns an http.Handler which checks basic HTTP authentication header values
// using the Checker and passes requests to the given http.Handler when Check returns true
// (responds with http.StatusUnauthorized if the call to Check returns false).
func NewHandler(c Checker, h http.Handler) http.Handler {
	return &handler{
		Handler: h,
		c:       c,
	}
}

// ServeHTTP implements http.Handler.
func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	username, password, _ := r.BasicAuth()
	if !h.c.Check(username, password) {
		w.Header().Add("WWW-Authenticate", "Basic")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(http.StatusText(http.StatusUnauthorized)))
		return
	}
	h.Handler.ServeHTTP(w, r)
}

// Handle is a convenience function which calls http.Handle with the pattern and wrapped
// http.Handler (see NewHandler).
func Handle(c Checker, pattern string, h http.Handler) {
	http.Handle(pattern, NewHandler(c, h))
}

// HandleFunc is a convenience function which calls http.HandleFunc with the pattern and
// wrapped http.HandlerFunc (see HandlerFunc).
func HandleFunc(c Checker, pattern string, h http.HandlerFunc) {
	http.HandleFunc(pattern, HandlerFunc(c, h))
}

// ServeMux is a convenience type which wraps Handle and HandleFunc calls on an http.ServeMux
// for the same Checker.
type ServeMux struct {
	Checker
	*http.ServeMux
}

// NewServeMux creates a new http.ServeMux which wraps calls to Handle and Handler for the
// same Checker.
func NewServeMux(c Checker, m *http.ServeMux) ServeMux {
	return ServeMux{c, m}
}

func (m ServeMux) Handle(pattern string, h http.Handler) {
	m.ServeMux.Handle(pattern, NewHandler(m.Checker, h))
}

func (m ServeMux) HandleFunc(pattern string, h http.HandlerFunc) {
	m.ServeMux.Handle(pattern, HandlerFunc(m.Checker, h))
}
