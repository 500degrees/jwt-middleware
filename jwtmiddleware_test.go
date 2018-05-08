package jwtmiddleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestJWTMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	middleware := New("test_secret")
	router := setupRouter(middleware)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test_auth", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code, "should not be authorized if no Authorization header")
}

func setupRouter(m gin.HandlerFunc) *gin.Engine {
	r := gin.Default()
	r.Use(m)
	r.GET("/test_auth", func(c *gin.Context) {
		c.String(http.StatusOK, "authorized")
	})
	return r
}
