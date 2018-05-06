package jwtmiddleware

import (
	"log"

	"github.com/gin-gonic/gin"
)

func New() gin.HandlerFunc {
	return func(c *gin.Context) {
		log.Println("handling jwt ...")
	}
}
