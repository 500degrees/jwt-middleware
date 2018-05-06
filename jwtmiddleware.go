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
	log.Println("creating middleware with secret", secret)
	return func(c *gin.Context) {
		authHeader := c.Request.Header.Get("Authorization")
		parts := strings.Split(authHeader, " ")
		if len(parts) <= 1 {
			log.Println("Authorization header not present")
			c.JSON(http.StatusUnauthorized, gin.H{
				"message": "Unauthorized",
			})
			c.Abort()
			return
		}
		tokenString := parts[1]
		log.Println("TOKEN:", tokenString)

		type TokenClaims struct {
			ID    string `json:"id,omitempty"`
			Email string `json:"email"`
			jwt.StandardClaims
		}

		token, err := jwt.ParseWithClaims(tokenString, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
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

		if claims, ok := token.Claims.(TokenClaims); ok && token.Valid {
			log.Printf("setting claims: %v", claims)
			c.Set("Claims", claims)
			c.Next()
		} else {
			log.Printf("something weird: %v", err)
			c.JSON(http.StatusUnauthorized, gin.H{
				"message": "Unauthorized",
			})
			c.Abort()
		}
	}
}
