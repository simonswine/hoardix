package hoardix

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type uploadMsg struct {
	body []byte
	name string
}

type fakeStorage struct {
	uploadCh chan uploadMsg
}

func (f *fakeStorage) Name() string {
	return "fake"
}

func (f *fakeStorage) Upload(ctx context.Context, name string, body io.Reader) error {
	if f.uploadCh != nil {
		body, err := io.ReadAll(body)
		if err != nil {
			return err
		}
		f.uploadCh <- uploadMsg{
			body: body,
			name: name,
		}
	}
	return nil
}

func (f *fakeStorage) Exists(ctx context.Context, name string) (bool, error) {
	return false, errors.New("TODO: unimplemented")
}

func (f *fakeStorage) Get(ctx context.Context, name string) (io.ReadCloser, error) {
	return nil, errors.New("TODO: unimplemented")
}

func (f *fakeStorage) IsObjNotFoundErr(e error) bool {
	return false
}

const narinfoUploadBody = `{
  "cSig": null,
  "cStoreHash": "k5qnmarf6aqxfsgjmmpj07kkxh5msfvb",
  "cNarHash": "sha256:0yragrhr04ncri2b6lzs11j1jzzdnfdnalvscyjlbc1jzjyx7m9h",
  "cFileHash": "a6c7ac172301ad5968d2d592c4af745833a22b14f6f3bfab73d63789f8260a8e",
  "cDeriver": "8194kvzxdfnhfyasnmvph3vixqnzwraj-lolhello.drv",
  "cFileSize": 37188,
  "cStoreSuffix": "lolhello",
  "cReferences": [
    "0c7c96gikmzv87i7lv3vq5s1cmfjd6zf-glibc-2.31-74",
    "k5qnmarf6aqxfsgjmmpj07kkxh5msfvb-lolhello"
  ],
  "cNarSize": 188056
}`

func TestHandlerUploadNar(t *testing.T) {
	a := New()
	uploadCh := make(chan uploadMsg, 1)
	a.storage = &fakeStorage{uploadCh: uploadCh}

	handler := a.initRouter()

	bodyHash := sha256.New()
	f, err := os.Open("testdata/lolhello.nar")
	require.NoError(t, err)

	req, err := http.NewRequest("POST", "http://host/api/v1/cache/my-cache/nar", io.TeeReader(f, bodyHash))
	require.NoError(t, err)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// TODO: figure out if this is the desired output
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "[]\n", w.Body.String())

	upload := <-uploadCh
	storageData := sha256.New()
	_, err = storageData.Write(upload.body)
	require.NoError(t, err)

	assert.Equal(t, "my-cache/nar/13ha4vw8jdynffmvzwzn2hms4csqfjpw94nms9l5kb814cbsrix6.nar.xz", upload.name)
	assert.Equal(t, bodyHash.Sum(nil), storageData.Sum(nil))

}

func TestHandlerUploadNarinfo(t *testing.T) {
	a := New()
	uploadCh := make(chan uploadMsg, 1)
	a.storage = &fakeStorage{uploadCh: uploadCh}

	handler := a.initRouter()

	req, err := http.NewRequest("POST", "http://host/api/v1/cache/my-cache/xyz.narinfo", bytes.NewReader([]byte(narinfoUploadBody)))
	require.NoError(t, err)

	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "", w.Body.String())

	upload := <-uploadCh
	assert.Equal(t, "my-cache/k5qnmarf6aqxfsgjmmpj07kkxh5msfvb.narinfo", upload.name)
	assert.Equal(t, `StorePath: /nix/store/k5qnmarf6aqxfsgjmmpj07kkxh5msfvb-lolhello
URL: nar/13ha4vw8jdynffmvzwzn2hms4csqfjpw94nms9l5kb814cbsrix6.nar.xz
Compression: xz
FileHash: sha256:13ha4vw8jdynffmvzwzn2hms4csqfjpw94nms9l5kb814cbsrix6
FileSize: 37188
NarHash: sha256:0yragrhr04ncri2b6lzs11j1jzzdnfdnalvscyjlbc1jzjyx7m9h
NarSize: 188056
References: 0c7c96gikmzv87i7lv3vq5s1cmfjd6zf-glibc-2.31-74 k5qnmarf6aqxfsgjmmpj07kkxh5msfvb-lolhello
Deriver: 8194kvzxdfnhfyasnmvph3vixqnzwraj-lolhello.drv
`, string(upload.body))

}
