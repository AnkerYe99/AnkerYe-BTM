package handler

import (
	"database/sql"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"

	"ankerye-flow/db"
	"ankerye-flow/middleware"
	"ankerye-flow/util"
)

func Login(c *gin.Context) {
	var req struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		util.Fail(c, 400, "参数错误")
		return
	}
	var id int64
	var hash string
	err := db.DB.QueryRow(`SELECT id,password_hash FROM users WHERE username=?`, req.Username).Scan(&id, &hash)
	if err == sql.ErrNoRows {
		util.Fail(c, 401, "用户名或密码错误")
		return
	}
	if err != nil {
		util.Fail(c, 500, err.Error())
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)); err != nil {
		util.Fail(c, 401, "用户名或密码错误")
		return
	}
	token, err := middleware.GenToken(id, req.Username)
	if err != nil {
		util.Fail(c, 500, err.Error())
		return
	}
	util.OK(c, gin.H{"token": token, "username": req.Username})
}

func Profile(c *gin.Context) {
	uid := c.GetInt64("uid")
	uname := c.GetString("uname")
	util.OK(c, gin.H{"uid": uid, "username": uname})
}

func ChangePassword(c *gin.Context) {
	var req struct {
		OldPassword string `json:"old_password" binding:"required"`
		NewPassword string `json:"new_password" binding:"required,min=6"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		util.Fail(c, 400, "参数错误")
		return
	}
	uid := c.GetInt64("uid")
	var hash string
	if err := db.DB.QueryRow(`SELECT password_hash FROM users WHERE id=?`, uid).Scan(&hash); err != nil {
		util.Fail(c, 500, err.Error())
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.OldPassword)); err != nil {
		util.Fail(c, 400, "原密码错误")
		return
	}
	newHash, _ := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	db.DB.Exec(`UPDATE users SET password_hash=? WHERE id=?`, string(newHash), uid)
	util.OK(c, gin.H{"msg": "已修改"})
}

func ChangeProfile(c *gin.Context) {
	var req struct {
		Username    string `json:"username"`
		OldPassword string `json:"old_password" binding:"required"`
		NewPassword string `json:"new_password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		util.Fail(c, 400, "参数错误")
		return
	}
	uid := c.GetInt64("uid")
	var hash string
	if err := db.DB.QueryRow(`SELECT password_hash FROM users WHERE id=?`, uid).Scan(&hash); err != nil {
		util.Fail(c, 500, err.Error())
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.OldPassword)); err != nil {
		util.Fail(c, 400, "原密码错误")
		return
	}
	if req.Username != "" {
		var exists int
		db.DB.QueryRow(`SELECT COUNT(*) FROM users WHERE username=? AND id!=?`, req.Username, uid).Scan(&exists)
		if exists > 0 {
			util.Fail(c, 400, "用户名已存在")
			return
		}
		db.DB.Exec(`UPDATE users SET username=? WHERE id=?`, req.Username, uid)
	}
	if req.NewPassword != "" {
		if len(req.NewPassword) < 6 {
			util.Fail(c, 400, "新密码至少 6 位")
			return
		}
		newHash, _ := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
		db.DB.Exec(`UPDATE users SET password_hash=? WHERE id=?`, string(newHash), uid)
	}
	util.OK(c, gin.H{"msg": "已修改"})
}

// 初始化默认用户 admin/admin123
func EnsureAdmin() error {
	var count int
	db.DB.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&count)
	if count > 0 {
		return nil
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte("admin123"), bcrypt.DefaultCost)
	_, err := db.DB.Exec(`INSERT INTO users(username,password_hash,role) VALUES('admin',?,'admin')`, string(hash))
	return err
}
