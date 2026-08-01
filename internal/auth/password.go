package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	argonMemoryKiB        = 64 * 1024
	argonIterations       = 3
	argonParallelism      = 2
	passwordSaltBytes     = 16
	passwordHashBytes     = 32
	minimumPasswordLength = 14
)

var ErrPasswordTooShort = fmt.Errorf("password must contain at least %d characters", minimumPasswordLength)

type argonParameters struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	keyLength   uint32
}

func HashPassword(password string) (string, error) {
	if len([]rune(password)) < minimumPasswordLength {
		return "", ErrPasswordTooShort
	}
	salt := make([]byte, passwordSaltBytes)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}
	hash := argon2.IDKey([]byte(password), salt, argonIterations, argonMemoryKiB, argonParallelism, passwordHashBytes)
	return encodePasswordHash(salt, hash), nil
}

func VerifyPassword(encoded, password string) (bool, error) {
	parameters, salt, expected, err := decodePasswordHash(encoded)
	if err != nil {
		return false, err
	}
	actual := argon2.IDKey([]byte(password), salt, parameters.iterations, parameters.memory, parameters.parallelism, parameters.keyLength)
	return subtle.ConstantTimeCompare(actual, expected) == 1, nil
}

func encodePasswordHash(salt, hash []byte) string {
	encoding := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version,
		argonMemoryKiB, argonIterations, argonParallelism,
		encoding.EncodeToString(salt), encoding.EncodeToString(hash))
}

func decodePasswordHash(encoded string) (argonParameters, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return argonParameters{}, nil, nil, errors.New("invalid Argon2id password hash")
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return argonParameters{}, nil, nil, errors.New("unsupported Argon2id version")
	}
	parameters := argonParameters{}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &parameters.memory, &parameters.iterations, &parameters.parallelism); err != nil {
		return argonParameters{}, nil, nil, errors.New("invalid Argon2id parameters")
	}
	encoding := base64.RawStdEncoding
	salt, err := encoding.DecodeString(parts[4])
	if err != nil {
		return argonParameters{}, nil, nil, errors.New("invalid Argon2id salt")
	}
	hash, err := encoding.DecodeString(parts[5])
	if err != nil || len(hash) == 0 {
		return argonParameters{}, nil, nil, errors.New("invalid Argon2id digest")
	}
	parameters.keyLength = uint32(len(hash))
	if parameters.memory == 0 || parameters.iterations == 0 || parameters.parallelism == 0 {
		return argonParameters{}, nil, nil, errors.New("unsafe Argon2id parameters")
	}
	return parameters, salt, hash, nil
}
