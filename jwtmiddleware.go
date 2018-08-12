package jwtmiddleware

import (
	"log"
	"net/http"
	"strings"
	"fmt"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

type ExtractorType int32
const (
	FROM_HEADER ExtractorType = 0
	FROM_AUTH_HEADER_BEAREN_TOKEN ExtractorType = 1
	FROM_CUSTOM_FUNC ExtractorType = 2
)

type Config struct {

	Callback func(r *http.Request, claims jwt.Claims) bool

	Secret string

	ExtractJwt ExtractorType

	HeaderName string

	CustomExtractFunc func(r *http.Request) (string, error)
}

// New creates a jwtmiddleware to parse JWT tokens from the Authorization header
func New(conf Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		
		var tk string
		var err error
		if conf.ExtractJwt == FROM_AUTH_HEADER_BEAREN_TOKEN {
			tk, err = extractFromAuthHeader(c.Request)
		}

		if conf.ExtractJwt == FROM_HEADER {
			tk, err = extractFromHeader(c.Request, conf.HeaderName)
		}

		if conf.ExtractJwt == FROM_CUSTOM_FUNC {
			tk, err = conf.CustomExtractFunc(c.Request)
		}

		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"message": "Unauthorized",
			})
			c.Abort()
			return
		}

		token, err := jwt.Parse(tk, func(token *jwt.Token) (interface{}, error) {
			return []byte(conf.Secret), nil
		})
		if err != nil {
			log.Printf("error parsing token: %v", err)
			c.JSON(http.StatusUnauthorized, gin.H{
				"message": "Unauthorized",
			})
			c.Abort()
			return
		}

		if token.Valid {
			c.Set("TokenClaims", token.Claims)
			if conf.Callback != nil { conf.Callback(c.Request, token.Claims) }
			c.Next()
		} else {
			log.Printf("Invalid token: %v, %v", err, token.Valid)
			c.JSON(http.StatusUnauthorized, gin.H{
				"message": "Unauthorized",
			})
			c.Abort()
		}
	}
}

func extractFromHeader(r *http.Request, headerName string) (string, error) {

	authHeader := r.Header.Get(headerName)
	parts := strings.Fields(authHeader)
	if len(parts) <= 1 {
		return "", fmt.Errorf("Header not present")
	}
	return parts[1], nil		
}

func extractFromAuthHeader (r *http.Request) (string, error) {
	return extractFromHeader(r,"Authorization")
}
