package scryptauth

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Parses "paramId:base64(hash):base64(salt)"
func DecodeBase64(str string) (paramId uint, hash, salt []byte, err error) {
	tmp := strings.SplitN(str, ":", 3)
	tmpParamId, err := strconv.ParseUint(tmp[0], 10, 0)
	if err != nil {
		err = errors.New("Error: parsing paramId parameter")
		return
	}
	paramId = uint(tmpParamId)
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

// Encodes into "paramId:base64(hash):base64(salt)"
func EncodeBase64(paramId uint, hash, salt []byte) (str string) {
	b64_salt := base64.URLEncoding.EncodeToString(salt)
	b64_hash := base64.URLEncoding.EncodeToString(hash)
	str = fmt.Sprintf("%d:%s:%s", paramId, b64_hash, b64_salt)
	return
}
