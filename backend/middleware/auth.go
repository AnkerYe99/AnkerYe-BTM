package middleware

import (
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"ankerye-flow/config"
	"ankerye-flow/util"
)

type Claims struct {
	UserID   int64  `json:"uid"`
	Username string `json:"uname"`
	jwt.RegisteredClaims
}

func GenToken(userID int64, username string) (string, error) {
	claims := &Claims{
		UserID:   userID,
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(config.Global.Server.JWTExpireHours) * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(config.Global.Server.JWTSecret))
}

func JWT() gin.HandlerFunc {
	return func(c *gin.Context) {
		h := c.GetHeader("Authorization")
		if !strings.HasPrefix(h, "Bearer ") {
			util.Fail(c, 401, "未登录")
			return
		}
		tokenStr := strings.TrimPrefix(h, "Bearer ")
		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
			return []byte(config.Global.Server.JWTSecret), nil
		})
		if err != nil || !token.Valid {
			util.Fail(c, 401, "token 无效或过期")
			return
		}
		c.Set("uid", claims.UserID)
		c.Set("uname", claims.Username)
		c.Next()
	}
}
