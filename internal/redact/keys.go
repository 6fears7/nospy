package redact

import "strings"

// One definition of "this key names a secret", shared by the free-text key=value rule, dotenv
// lines and JSON tool-argument keys. A key is split into words (snake_case, kebab-case, dotted,
// camelCase) and only its last word, or its last two joined, is judged. That keeps max_tokens,
// token_count, secret_name and secretKeyRef out while sessionSecret, secret_key and DB_PASS in.

type keyScope uint8

const (
	scopeArg  keyScope = iota // JSON tool arguments: auth, pwd, pass and key are ordinary arguments there
	scopeText                 // key=value anywhere in text: adds auth and pwd
	scopeEnv                  // dotenv lines: adds pass, dsn and the bare word key
)

var (
	// secretKeySuffixes match the end of the last word (dbpassword, csrftoken) or of the last two
	// words joined (api+key, secret+key, connection+string), in every scope.
	secretKeySuffixes = []string{"password", "passwd", "passphrase", "secret", "token", "credential", "credentials",
		"apikey", "accesskey", "secretkey", "privatekey", "encryptionkey", "signingkey", "masterkey", "authkey", "connectionstring"}
	// Exact last words: too short or too common to match as a suffix (author, monkey, keyboard).
	textKeyWords = keySet("auth", "pwd")
	envKeyWords  = keySet("pass", "dsn", "key")
)

func keySet(ws ...string) map[string]bool {
	m := make(map[string]bool, len(ws))
	for _, w := range ws {
		m[w] = true
	}
	return m
}

// secretKey reports whether key names a secret in the given scope. Case and separators are ignored.
func secretKey(key string, scope keyScope) bool {
	w := keyWords(key)
	n := len(w)
	if n == 0 {
		return false
	}
	last := w[n-1]
	joined := last
	if n > 1 {
		joined = w[n-2] + last
	}
	for _, suf := range secretKeySuffixes {
		if strings.HasSuffix(last, suf) || strings.HasSuffix(joined, suf) {
			return true
		}
	}
	return scope >= scopeText && textKeyWords[last] || scope >= scopeEnv && envKeyWords[last]
}

// keyWords splits key into lowercase words at _ - . and at camelCase boundaries:
// "sessionSecret" and "DB_PASSWORD" give [session secret] and [db password]; "APIKey" gives [api key].
func keyWords(key string) []string {
	var words []string
	start := 0
	flush := func(end int) {
		if end > start {
			words = append(words, strings.ToLower(key[start:end]))
		}
	}
	for i := 0; i < len(key); i++ {
		c := key[i]
		switch {
		case c == '_' || c == '-' || c == '.':
			flush(i)
			start = i + 1
		case i > start && isUpper(c) && (!isUpper(key[i-1]) || i+1 < len(key) && isLower(key[i+1])):
			flush(i)
			start = i
		}
	}
	flush(len(key))
	return words
}

func isUpper(c byte) bool { return c >= 'A' && c <= 'Z' }
func isLower(c byte) bool { return c >= 'a' && c <= 'z' }
