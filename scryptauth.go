/*
scryptauth is a GO library for secure password handling using scrypt

It uses sha256_hmac(scrypt(user_password, salt), server_key) to protect against
both dictionary attacks and DB leaks.

scryptauth additionally provides encode/decode routines using base64 to create strings
for storing into a DB.

Copyright: Michael Gebetsroither 2012 (michael \x40 mgeb \x2e org)

License: BSD 2 clause
*/
package scryptauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"golang.org/x/crypto/scrypt"
)

type Context struct {
	HmacKey []byte // HMAC key used to secure scrypt hash
	PwCost  uint   // PwCost parameter used to calculate N parameter of scrypt (1<<PwCost == N)
	R       int    // r parameter of scrypt
	P       int    // p parameter of scrypt
}

const (
	// Key length and salt length are 32 bytes (256 bits)
	KeyLength = 32

	// scrypt default parameters as used by New()
	DefaultR = 8
	DefaultP = 1
)

// New creates a new Context struct. This is a convenience function to produce a context.
// You might as well produce the Context struct yourself.
func New(pwCost uint, hmacKey []byte) (*Context, error) {
	if pwCost > 31 {
		return nil, errors.New("scryptauth new() - invalid pwCost specified")
	}
	if len(hmacKey) != KeyLength {
		return nil, errors.New("scryptauth new() - unsupported hmacKey length")
	}
	return &Context{HmacKey: hmacKey, PwCost: pwCost, R: DefaultR, P: DefaultP}, nil
}

// Hash produces the hash using password and salt. This is used by Gen() and Check()
// to generate/check password hashes.
func (c *Context) Hash(password, salt []byte) (hash []byte, err error) {
	scrypt_hash, err := scrypt.Key(password, salt, 1<<c.PwCost, c.R, c.P, KeyLength)
	if err != nil {
		return
	}
	hmac := hmac.New(sha256.New, c.HmacKey)
	if _, err = hmac.Write(scrypt_hash); err != nil {
		return
	}
	hash = hmac.Sum(nil)
	return
}

// Check verifies password against hash/salt
func (c *Context) Check(hash, password, salt []byte) (chk bool, err error) {
	result_hash, err := c.Hash(password, salt)
	if err != nil {
		return false, err
	}
	if subtle.ConstantTimeCompare(result_hash, hash) != 1 {
		return false, errors.New("Error: Hash verification failed")
	}
	return true, nil
}

// Gen generates hash for password using a new salt from crypto.rand
func (c *Context) Gen(password []byte) (hash, salt []byte, err error) {
	salt = make([]byte, KeyLength)
	salt_length, err := rand.Read(salt)
	if salt_length != KeyLength {
		return nil, nil, errors.New("Insufficient random bytes for salt")
	}
	if err != nil {
		return nil, nil, err
	}

	hash, err = c.Hash(password, salt)
	if err != nil {
		return nil, nil, err
	}
	return
}
