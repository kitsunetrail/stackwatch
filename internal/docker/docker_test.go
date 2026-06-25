package docker

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newTestClient(srv *httptest.Server) *Client {
	return newClient(srv.URL, srv.Client())
}

func TestRunningImages_DedupesAndSorts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/containers/json" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[
			{"Id":"a","Image":"nginx:1.25","Names":["/web1"]},
			{"Id":"b","Image":"nginx:1.25","Names":["/web2"]},
			{"Id":"c","Image":"redis:7.0","Names":["/cache"]},
			{"Id":"d","Image":"postgres:16","Names":["/db"]}
		]`))
	}))
	defer srv.Close()

	imgs, err := newTestClient(srv).RunningImages(context.Background())
	if err != nil {
		t.Fatalf("RunningImages: %v", err)
	}
	want := []string{"nginx:1.25", "postgres:16", "redis:7.0"}
	if len(imgs) != len(want) {
		t.Fatalf("got %v, want %v", imgs, want)
	}
	for i := range want {
		if imgs[i] != want[i] {
			t.Errorf("imgs[%d] = %q, want %q (sorted unique)", i, imgs[i], want[i])
		}
	}
}

func TestRunningImages_Empty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	imgs, err := newTestClient(srv).RunningImages(context.Background())
	if err != nil {
		t.Fatalf("RunningImages: %v", err)
	}
	if len(imgs) != 0 {
		t.Errorf("got %v, want empty", imgs)
	}
}

func TestRunningImages_SkipsBlankImage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[{"Id":"a","Image":""},{"Id":"b","Image":"alpine:3.20"}]`))
	}))
	defer srv.Close()

	imgs, err := newTestClient(srv).RunningImages(context.Background())
	if err != nil {
		t.Fatalf("RunningImages: %v", err)
	}
	if len(imgs) != 1 || imgs[0] != "alpine:3.20" {
		t.Errorf("got %v, want [alpine:3.20]", imgs)
	}
}

func TestRunningImages_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("boom"))
	}))
	defer srv.Close()

	if _, err := newTestClient(srv).RunningImages(context.Background()); err == nil {
		t.Fatal("expected error on 500")
	}
}
