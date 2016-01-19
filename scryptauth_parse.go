package scryptauth

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// DecodeBase64 parses "ctxID:base64(hash):base64(salt)"
func DecodeBase64(str string) (ctxID uint, hash, salt []byte, err error) {
	tmp := strings.SplitN(str, ":", 3)
	tmpParamId, err := strconv.ParseUint(tmp[0], 10, 0)
	if err != nil {
		err = errors.New("Error: parsing ctxID parameter")
		return
	}
	ctxID = uint(tmpParamId)
	hash, err = base64.URLEncoding.DecodeString(tmp[1])
	if err != nil {
		err = errors.New("Error: decoding base64 hash")
		return
	}
	salt, err = base64.URLEncoding.DecodeString(tmp[2])
	if err != nil {
		err = errors.New("Error: decoding base64 salt")
		return
	}
	return
}

// EncodeBase64 encodes into "ctxID:base64(hash):base64(salt)"
func EncodeBase64(ctxID uint, hash, salt []byte) (str string) {
	b64_salt := base64.URLEncoding.EncodeToString(salt)
	b64_hash := base64.URLEncoding.EncodeToString(hash)
	str = fmt.Sprintf("%d:%s:%s", ctxID, b64_hash, b64_salt)
	return
}
