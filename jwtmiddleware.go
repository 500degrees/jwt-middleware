package jwtmiddleware

import (
	"fmt"
	"net/http"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

// New creates a jwtmiddleware to parse JWT tokens from the Authorization header
func New(secret string, method interface{}) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.Request.Header.Get("Authorization")
		parts := strings.Split(authHeader, " ")
		tokenString := parts[1]
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Don't forget to validate the alg is what you expect:
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			}

			return []byte(secret), nil
		})

		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			c.Set("Claims", claims)
			c.Next()
		} else {
			fmt.Println(err)
			c.JSON(http.StatusUnauthorized, gin.H{
				"message": "Unauthorized",
			})
		}
	}
}
