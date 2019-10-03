package kamekazi

import (
	"crypto/rand"
	"html/template"
	"net/http"
	"time"

	uuid "github.com/nu7hatch/gouuid"

	"strings"

	"fmt"
	"io"

	"encoding/hex"

	"golang.org/x/crypto/nacl/secretbox"
	"google.golang.org/appengine"
	"google.golang.org/appengine/memcache"
)

type msgAndSecretKeys struct {
	MsgKey    string
	SecretKey string
	URLMsg    string
}

var tpl *template.Template

func init() {
	tpl = template.Must(template.ParseGlob("./*.html"))

	http.HandleFunc("/", index)
	http.HandleFunc("/msg/", message)
}

// create a message
func index(w http.ResponseWriter, r *http.Request) {
	ctx := appengine.NewContext(r)
	var keySystem msgAndSecretKeys

	if r.Method == http.MethodPost {
		msg := r.FormValue("umsg")
		mkey, _ := uuid.NewV4()
		skey := generatePassword()
		encryptedMessage := encrypt(msg, skey)

		keySystem.MsgKey = mkey.String()
		keySystem.SecretKey = fmt.Sprintf("%x", skey)
		keySystem.URLMsg = "/msg/" + keySystem.MsgKey

		// store message in memcache
		item := &memcache.Item{
			Key:   keySystem.MsgKey,
			Value: []byte(encryptedMessage),
		}

		err := memcache.Add(ctx, item)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		err = tpl.ExecuteTemplate(w, "secret.html", keySystem)

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		err := tpl.ExecuteTemplate(w, "index.html", nil)

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
}

// return a message based on its id
func message(w http.ResponseWriter, r *http.Request) {
	ctx := appengine.NewContext(r)

	// extracting key from url
	key := strings.SplitN(r.URL.Path, "/", 3)[2]

	// extracting item from google appengine memcache
	item, err := memcache.Get(ctx, key)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	var password [32]byte
	bs, err := hex.DecodeString(r.FormValue("secret"))
	if err != nil || len(bs) != 32 {
		http.Error(w, err.Error(), 500)
		return
	}

	copy(password[:], bs)
	decryptedMessage, err := decrypt(string(item.Value), password)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	// memcache.Delete(ctx, key), use this for super duper tight security, message is burned the second its opened
	// this one below for specified seconds expiration, will destroy message after some time
	if item.Flags == 0 {
		item.Expiration = 30 * time.Second
		item.Flags = 1
		memcache.Set(ctx, item)
	}

	err = tpl.ExecuteTemplate(w, "message.html", decryptedMessage)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func decrypt(encrypted string, password [32]byte) (string, error) {
	var nonce [24]byte
	parts := strings.SplitN(encrypted, ":", 2)
	if len(parts) < 2 {
		return "", fmt.Errorf("expected nonce")
	}

	bs, err := hex.DecodeString(parts[0])
	if err != nil || len(bs) != 24 {
		return "", fmt.Errorf("invalid nonce")
	}
	copy(nonce[:], bs)

	bs, err = hex.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("invalid message")
	}

	decrypted, ok := secretbox.Open(nil, bs, &nonce, &password)

	if !ok {
		return "", fmt.Errorf("invalid message")
	}

	return string(decrypted), nil
}

func encrypt(decrypted string, password [32]byte) string {
	var nonce [24]byte
	io.ReadAtLeast(rand.Reader, nonce[:], 24)
	encrypted := secretbox.Seal(nil, []byte(decrypted), &nonce, &password)

	return fmt.Sprintf("%x:%x", nonce[:], encrypted)
}

func generatePassword() [32]byte {
	var password [32]byte
	io.ReadAtLeast(rand.Reader, password[:], 32)

	return password
}
