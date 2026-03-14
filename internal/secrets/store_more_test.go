package secrets

import (
	"encoding/json"
	"errors"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/99designs/keyring"

	"github.com/steipete/gogcli/internal/config"
)

var errTestKeychain = errors.New("test -25308 error")

func TestKeyringStore_ListDeleteDefault(t *testing.T) {
	ring := keyring.NewArrayKeyring(nil)
	store := &KeyringStore{ring: ring}
	client := config.DefaultClientName

	tok1 := Token{Email: "a@b.com", RefreshToken: "rt1", CreatedAt: time.Now()}
	if err := store.SetToken(client, tok1.Email, tok1); err != nil {
		t.Fatalf("SetToken: %v", err)
	}

	tok2 := Token{Email: "c@d.com", RefreshToken: "rt2", CreatedAt: time.Now()}
	if err := store.SetToken(client, tok2.Email, tok2); err != nil {
		t.Fatalf("SetToken: %v", err)
	}

	tokens, err := store.ListTokens()
	if err != nil {
		t.Fatalf("ListTokens: %v", err)
	}

	if len(tokens) != 2 {
		t.Fatalf("expected 2 tokens, got %d", len(tokens))
	}

	err = store.DeleteToken(client, tok1.Email)
	if err != nil {
		t.Fatalf("DeleteToken: %v", err)
	}

	if _, getErr := store.GetToken(client, tok1.Email); getErr == nil {
		t.Fatalf("expected error for deleted token")
	}

	err = store.SetDefaultAccount(client, "a@b.com")
	if err != nil {
		t.Fatalf("SetDefaultAccount: %v", err)
	}

	if def, err := store.GetDefaultAccount(client); err != nil {
		t.Fatalf("GetDefaultAccount: %v", err)
	} else if def != "a@b.com" {
		t.Fatalf("unexpected default account: %q", def)
	}

	emptyStore := &KeyringStore{ring: keyring.NewArrayKeyring(nil)}
	if def, err := emptyStore.GetDefaultAccount(client); err != nil || def != "" {
		t.Fatalf("expected empty default account, got %q err=%v", def, err)
	}
}

func TestParseTokenKey(t *testing.T) {
	if client, email, ok := ParseTokenKey("token:a@b.com"); !ok || email != "a@b.com" || client != config.DefaultClientName {
		t.Fatalf("unexpected parse: client=%q email=%q ok=%v", client, email, ok)
	}

	if client, email, ok := ParseTokenKey("token:org:a@b.com"); !ok || email != "a@b.com" || client != "org" {
		t.Fatalf("unexpected parse: client=%q email=%q ok=%v", client, email, ok)
	}

	if _, _, ok := ParseTokenKey("nope"); ok {
		t.Fatalf("expected invalid token key")
	}
}

func TestParseTokenKey_WindowsFileSafeKey(t *testing.T) {
	encoded := windowsFileKeyPrefix + "dG9rZW46b3JnOmFAYi5jb20"

	client, email, ok := ParseTokenKey(encoded)
	if !ok {
		t.Fatalf("expected encoded key to parse")
	}
	if client != "org" || email != "a@b.com" {
		t.Fatalf("unexpected parse: client=%q email=%q", client, email)
	}
}

func TestAllowedBackends(t *testing.T) {
	if _, err := allowedBackends(KeyringBackendInfo{Value: "keychain"}); err != nil {
		t.Fatalf("keychain allowed: %v", err)
	}

	if _, err := allowedBackends(KeyringBackendInfo{Value: "file"}); err != nil {
		t.Fatalf("file allowed: %v", err)
	}
}

func TestWrapKeychainError(t *testing.T) {
	wrapped := wrapKeychainError(errTestKeychain)
	if runtime.GOOS == "darwin" {
		if !errors.Is(wrapped, errTestKeychain) || !strings.Contains(wrapped.Error(), "keychain is locked") {
			t.Fatalf("expected wrapped keychain error, got: %v", wrapped)
		}

		return
	}

	if !errors.Is(wrapped, errTestKeychain) || wrapped.Error() != errTestKeychain.Error() {
		t.Fatalf("expected passthrough error, got: %v", wrapped)
	}
}

func TestFileKeyringPasswordFuncFrom(t *testing.T) {
	fn := fileKeyringPasswordFuncFrom("pw", false)
	if got, err := fn("prompt"); err != nil {
		t.Fatalf("expected password, got err: %v", err)
	} else if got != "pw" {
		t.Fatalf("unexpected password: %q", got)
	}

	fn = fileKeyringPasswordFuncFrom("", false)
	if _, err := fn("prompt"); err == nil || !errors.Is(err, errNoTTY) {
		t.Fatalf("expected no TTY error, got: %v", err)
	}
}

func TestKeyringStoreSetTokenErrors(t *testing.T) {
	store := &KeyringStore{ring: keyring.NewArrayKeyring(nil)}
	client := config.DefaultClientName

	if err := store.SetToken(client, " ", Token{RefreshToken: "rt"}); !errors.Is(err, errMissingEmail) {
		t.Fatalf("expected missing email, got %v", err)
	}

	if err := store.SetToken(client, "a@b.com", Token{}); !errors.Is(err, errMissingRefreshToken) {
		t.Fatalf("expected missing refresh token, got %v", err)
	}
}

func TestSetSecretMissingKey(t *testing.T) {
	if err := SetSecret(" ", []byte("data")); !errors.Is(err, errMissingSecretKey) {
		t.Fatalf("expected missing key, got %v", err)
	}
}

func TestOpenDefaultError(t *testing.T) {
	origOpen := openKeyringFunc

	t.Cleanup(func() { openKeyringFunc = origOpen })

	openKeyringFunc = func() (keyring.Keyring, error) {
		return nil, errTestKeychain
	}

	if _, err := OpenDefault(); err == nil {
		t.Fatalf("expected error")
	}
}

func TestKeyringStoreDeleteAndDefaultErrors(t *testing.T) {
	store := &KeyringStore{ring: keyring.NewArrayKeyring(nil)}
	client := config.DefaultClientName

	if err := store.DeleteToken(client, " "); !errors.Is(err, errMissingEmail) {
		t.Fatalf("expected missing email, got %v", err)
	}

	if err := store.SetDefaultAccount(client, " "); !errors.Is(err, errMissingEmail) {
		t.Fatalf("expected missing email, got %v", err)
	}
}

func TestKeyringStoreWritePathsSetLabel(t *testing.T) {
	setupUserConfigEnv(t)

	ring := keyring.NewArrayKeyring(nil)
	store := &KeyringStore{ring: ring}
	email := "A@B.COM"
	client := config.DefaultClientName
	tok := Token{RefreshToken: "rt", CreatedAt: time.Now().UTC()}

	if err := store.SetToken(client, email, tok); err != nil {
		t.Fatalf("SetToken: %v", err)
	}

	for _, k := range []string{
		keyringStorageKey(tokenKey(client, normalize(email))),
		keyringStorageKey(legacyTokenKey(normalize(email))),
	} {
		it, err := ring.Get(k)
		if err != nil {
			t.Fatalf("Get(%q): %v", k, err)
		}

		if it.Label != config.AppName {
			t.Fatalf("expected label %q for key %q, got %q", config.AppName, k, it.Label)
		}
	}

	if err := store.SetDefaultAccount(client, email); err != nil {
		t.Fatalf("SetDefaultAccount: %v", err)
	}

	for _, k := range []string{
		keyringStorageKey(defaultAccountKeyForClient(client)),
		defaultAccountKey,
	} {
		it, err := ring.Get(k)
		if err != nil {
			t.Fatalf("Get(%q): %v", k, err)
		}

		if it.Label != config.AppName {
			t.Fatalf("expected label %q for key %q, got %q", config.AppName, k, it.Label)
		}
	}
}

func TestGetTokenMigrationSetsLabel(t *testing.T) {
	setupUserConfigEnv(t)

	ring := keyring.NewArrayKeyring(nil)
	store := &KeyringStore{ring: ring}
	email := "a@b.com"
	client := config.DefaultClientName

	payload, err := json.Marshal(storedToken{
		RefreshToken: "rt",
		CreatedAt:    time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	// Simulate an old legacy item created before label support.
	if setErr := ring.Set(keyring.Item{Key: legacyTokenKey(email), Data: payload}); setErr != nil {
		t.Fatalf("Set legacy token: %v", setErr)
	}

	if _, getErr := store.GetToken(client, email); getErr != nil {
		t.Fatalf("GetToken: %v", getErr)
	}

	it, err := ring.Get(keyringStorageKey(tokenKey(client, email)))
	if err != nil {
		t.Fatalf("Get migrated key: %v", err)
	}

	if it.Label != config.AppName {
		t.Fatalf("expected migrated label %q, got %q", config.AppName, it.Label)
	}
}

func TestSetSecretSetsLabel(t *testing.T) {
	ring := keyring.NewArrayKeyring(nil)
	origOpen := openKeyringFunc

	t.Cleanup(func() { openKeyringFunc = origOpen })

	openKeyringFunc = func() (keyring.Keyring, error) { return ring, nil }

	key := "test/secret"
	if err := SetSecret(key, []byte("value")); err != nil {
		t.Fatalf("SetSecret: %v", err)
	}

	it, err := ring.Get(key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	if it.Label != config.AppName {
		t.Fatalf("expected label %q, got %q", config.AppName, it.Label)
	}
}

type failingRemoveKeyring struct {
	*keyring.ArrayKeyring
	failKey string
	err     error
}

func (k *failingRemoveKeyring) Remove(key string) error {
	if key == k.failKey {
		return k.err
	}

	return k.ArrayKeyring.Remove(key)
}

type failingGetKeyring struct {
	*keyring.ArrayKeyring
	failKey string
	err     error
}

func (k *failingGetKeyring) Get(key string) (keyring.Item, error) {
	if key == k.failKey {
		return keyring.Item{}, k.err
	}

	return k.ArrayKeyring.Get(key)
}

func TestRemoveCompatibleKey_PropagatesFallbackRemoveError(t *testing.T) {
	setupUserConfigEnv(t)

	ring := &failingRemoveKeyring{
		ArrayKeyring: keyring.NewArrayKeyring(nil),
		err:          errTestKeychain,
	}

	rawKey := tokenKey(config.DefaultClientName, "a@b.com")
	safeKey := keyringStorageKey(rawKey)
	ring.failKey = rawKey

	if err := ring.Set(keyring.Item{Key: safeKey, Data: []byte("value")}); err != nil {
		t.Fatalf("Set safe key: %v", err)
	}

	if err := ring.Set(keyring.Item{Key: rawKey, Data: []byte("legacy")}); err != nil {
		t.Fatalf("Set raw key: %v", err)
	}

	if err := removeCompatibleKey(ring, rawKey); !errors.Is(err, errTestKeychain) {
		t.Fatalf("expected fallback remove error, got %v", err)
	}
}

func TestGetCompatibleItem_PropagatesFallbackGetError(t *testing.T) {
	setupUserConfigEnv(t)

	ring := &failingGetKeyring{
		ArrayKeyring: keyring.NewArrayKeyring(nil),
		err:          errTestKeychain,
	}

	rawKey := tokenKey(config.DefaultClientName, "a@b.com")
	ring.failKey = rawKey

	if _, _, err := getCompatibleItem(ring, rawKey); !errors.Is(err, errTestKeychain) {
		t.Fatalf("expected fallback get error, got %v", err)
	}
}

func TestKeyringStore_WindowsFileBackendReadsLegacyRawTokenKey(t *testing.T) {
	ring := keyring.NewArrayKeyring(nil)
	store := &KeyringStore{ring: ring}
	origGOOS := currentGOOS

	t.Cleanup(func() { currentGOOS = origGOOS })

	currentGOOS = "windows"
	t.Setenv("GOG_KEYRING_BACKEND", "file")

	payload, err := json.Marshal(storedToken{
		RefreshToken: "rt",
		CreatedAt:    time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	rawKey := tokenKey(config.DefaultClientName, "a@b.com")
	if setErr := ring.Set(keyring.Item{Key: rawKey, Data: payload}); setErr != nil {
		t.Fatalf("Set raw key: %v", setErr)
	}

	tok, err := store.GetToken(config.DefaultClientName, "a@b.com")
	if err != nil {
		t.Fatalf("GetToken: %v", err)
	}
	if tok.RefreshToken != "rt" {
		t.Fatalf("unexpected token: %#v", tok)
	}

	safeKey := keyringStorageKey(rawKey)
	if _, getErr := ring.Get(safeKey); getErr != nil {
		t.Fatalf("expected migrated safe key %q: %v", safeKey, getErr)
	}
}

func TestKeyringStore_WindowsFileBackendUsesSafeDefaultAccountKey(t *testing.T) {
	ring := keyring.NewArrayKeyring(nil)
	store := &KeyringStore{ring: ring}
	origGOOS := currentGOOS

	t.Cleanup(func() { currentGOOS = origGOOS })

	currentGOOS = "windows"
	t.Setenv("GOG_KEYRING_BACKEND", "file")

	if err := store.SetDefaultAccount(config.DefaultClientName, "a@b.com"); err != nil {
		t.Fatalf("SetDefaultAccount: %v", err)
	}

	safeKey := keyringStorageKey(defaultAccountKeyForClient(config.DefaultClientName))
	if _, err := ring.Get(safeKey); err != nil {
		t.Fatalf("expected safe default-account key %q: %v", safeKey, err)
	}
}

func TestKeyringStore_WindowsFileBackendMigratesRawDefaultAccountKey(t *testing.T) {
	ring := keyring.NewArrayKeyring(nil)
	store := &KeyringStore{ring: ring}
	origGOOS := currentGOOS

	t.Cleanup(func() { currentGOOS = origGOOS })

	currentGOOS = "windows"
	t.Setenv("GOG_KEYRING_BACKEND", "file")

	rawKey := defaultAccountKeyForClient(config.DefaultClientName)
	if err := ring.Set(keyring.Item{Key: rawKey, Data: []byte("a@b.com")}); err != nil {
		t.Fatalf("Set raw default account: %v", err)
	}

	got, err := store.GetDefaultAccount(config.DefaultClientName)
	if err != nil {
		t.Fatalf("GetDefaultAccount: %v", err)
	}
	if got != "a@b.com" {
		t.Fatalf("unexpected default account: %q", got)
	}

	safeKey := keyringStorageKey(rawKey)
	it, err := ring.Get(safeKey)
	if err != nil {
		t.Fatalf("expected migrated safe default-account key %q: %v", safeKey, err)
	}
	if it.Label != config.AppName {
		t.Fatalf("expected migrated label %q, got %q", config.AppName, it.Label)
	}
}
