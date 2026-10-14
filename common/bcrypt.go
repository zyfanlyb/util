package common

import "golang.org/x/crypto/bcrypt"

func Bcrypt(key string) (hash string, err error) {
	var b []byte
	b, err = bcrypt.GenerateFromPassword([]byte(key), bcrypt.DefaultCost)
	hash = string(b)
	if err != nil {
		return
	}
	return hash, nil
}

func VerifyBcrypt(key, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(key))
	return err == nil
}