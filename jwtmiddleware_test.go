package jwtmiddleware

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"gitlab.com/500degrees/basketball-tracker/services/auth/models"
)

const secret = "test_secret"

func TestJWTMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	middleware := New(secret)
	router := setupRouter(middleware)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test_auth", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code, "should not be authorized if no Authorization header")

	token := getToken()

	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/test_auth", nil)
	req.Header.Add("Authorization", fmt.Sprintf("JWT %s", token))
	router.ServeHTTP(w, req)
	t.Log(req)
	assert.Equal(t, http.StatusOK, w.Code, "should be authorized if Authorization header present with correct token")

}

func setupRouter(m gin.HandlerFunc) *gin.Engine {
	r := gin.Default()
	r.Use(m)
	r.GET("/test_auth", func(c *gin.Context) {
		c.String(http.StatusOK, "authorized")
	})
	return r
}

func getToken() string {
	// Create the Claims
	claims := models.TokenClaims{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Minute * 2).Unix(),
			Issuer:    "issuer",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ss, err := token.SignedString([]byte(secret))
	if err != nil {
		panic("Error signing token")
	}
	return ss
}
