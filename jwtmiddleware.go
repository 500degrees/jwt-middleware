package jwtmiddleware

import (
	"log"
	"net/http"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

// New creates a jwtmiddleware to parse JWT tokens from the Authorization header
func New(secret string) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.Request.Header.Get("Authorization")
		parts := strings.Fields(authHeader)
		if len(parts) <= 1 {
			log.Println("Authorization header not present")
			c.JSON(http.StatusUnauthorized, gin.H{
				"message": "Unauthorized",
			})
			c.Abort()
			return
		}
		tokenString := parts[1]
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return []byte(secret), nil
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
