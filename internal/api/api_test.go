package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Stopped while waiting, the request is withdrawn; a lapsed request is said to have lapsed.
func TestWait(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	withdrawn := false
	go func() { time.Sleep(1500 * time.Millisecond); cancel() }()
	_, err := Wait(ctx, Request{Interval: time.Second},
		func(context.Context) (Decision, error) { return Decision{State: "pending"}, nil },
		func(context.Context) error { withdrawn = true; return nil })
	if err == nil || !withdrawn {
		t.Fatalf("%v withdrawn=%v", err, withdrawn)
	}
	_, err = Wait(context.Background(), Request{Interval: time.Second},
		func(context.Context) (Decision, error) { return Decision{}, &Error{Status: 404, Message: "not found"} }, nil)
	if err == nil || !strings.Contains(err.Error(), "lapsed") {
		t.Fatal(err)
	}
	_, err = Wait(context.Background(), Request{Interval: time.Second},
		func(context.Context) (Decision, error) { return Decision{State: "declined"}, nil }, nil)
	if err == nil || !strings.Contains(err.Error(), "declined") {
		t.Fatal(err)
	}
}

// A call follows no redirect, so the token is never sent anywhere else.
func TestNoRedirect(t *testing.T) {
	var elsewhere []string
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		elsewhere = append(elsewhere, r.Header.Get("Authorization"))
	}))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusFound)
	}))
	defer srv.Close()
	err := Call(context.Background(), "GET", srv.URL, "secret", nil, nil)
	if !IsStatus(err, 302) || len(elsewhere) != 0 {
		t.Fatal(err, elsewhere)
	}
}
