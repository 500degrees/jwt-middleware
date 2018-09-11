package jwtmiddleware

import (
	"fmt"
	"log"
	"net/http"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

type Config struct {
	Secret          string
	ExtractStrategy func(r *http.Request) (string, error)
}

// New creates a jwtmiddleware to parse JWT tokens from the Authorization header
func New(conf Config) gin.HandlerFunc {
	return func(c *gin.Context) {

		tk, err := conf.ExtractStrategy(c.Request)

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

func ExtractFromHeader(headerName string) func(r *http.Request) (string, error) {

	return func(r *http.Request) (string, error) {
		authHeader := r.Header.Get(headerName)
		parts := strings.Fields(authHeader)
		if len(parts) <= 1 {
			return "", fmt.Errorf("Header not present")
		}
		return parts[1], nil
	}
}

func ExtractFromAuthHeader() func(r *http.Request) (string, error) {
	return ExtractFromHeader("Authorization")
}
