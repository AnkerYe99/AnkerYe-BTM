package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server struct {
		Port            int    `yaml:"port"`
		JWTSecret       string `yaml:"jwt_secret"`
		JWTExpireHours  int    `yaml:"jwt_expire_hours"`
	} `yaml:"server"`
	Database struct {
		Path string `yaml:"path"`
	} `yaml:"database"`
	Nginx struct {
		ConfDir      string `yaml:"conf_dir"`
		CertDir      string `yaml:"cert_dir"`
		LogDir       string `yaml:"log_dir"`
		LogrotateDir string `yaml:"logrotate_dir"`
		ReloadCmd    string `yaml:"reload_cmd"`
		TestCmd      string `yaml:"test_cmd"`
	} `yaml:"nginx"`
	HealthCheck struct {
		DefaultInterval int `yaml:"default_interval"`
		DefaultTimeout  int `yaml:"default_timeout"`
	} `yaml:"health_check"`
	Cert struct {
		RenewBeforeDays int `yaml:"renew_before_days"`
		CheckHour       int `yaml:"check_hour"`
	} `yaml:"cert"`
}

var Global Config

func Load(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := yaml.Unmarshal(data, &Global); err != nil {
		return err
	}
	// defaults
	if Global.Server.Port == 0 {
		Global.Server.Port = 9000
	}
	if Global.Server.JWTExpireHours == 0 {
		Global.Server.JWTExpireHours = 24
	}
	if Global.Database.Path == "" {
		Global.Database.Path = "/opt/AnkerYe-BTM/data/ankerye-btm.db"
	}
	if Global.Nginx.ConfDir == "" {
		Global.Nginx.ConfDir = "/etc/nginx/conf.d"
	}
	if Global.Nginx.CertDir == "" {
		Global.Nginx.CertDir = "/etc/nginx/certs"
	}
	if Global.Nginx.LogDir == "" {
		Global.Nginx.LogDir = "/var/log/AnkerYe-BTM"
	}
	if Global.Nginx.LogrotateDir == "" {
		Global.Nginx.LogrotateDir = "/etc/logrotate.d"
	}
	if Global.Nginx.ReloadCmd == "" {
		Global.Nginx.ReloadCmd = "nginx -s reload"
	}
	if Global.Nginx.TestCmd == "" {
		Global.Nginx.TestCmd = "nginx -t"
	}
	if Global.HealthCheck.DefaultInterval == 0 {
		Global.HealthCheck.DefaultInterval = 10
	}
	if Global.HealthCheck.DefaultTimeout == 0 {
		Global.HealthCheck.DefaultTimeout = 3
	}
	if Global.Cert.RenewBeforeDays == 0 {
		Global.Cert.RenewBeforeDays = 10
	}
	if Global.Cert.CheckHour == 0 {
		Global.Cert.CheckHour = 2
	}
	return nil
}
