package engine

import (
	"fmt"
	"os"
	"path/filepath"

	"ankerye-flow/config"
	"ankerye-flow/model"
)

func WriteLogrotate(r *model.Rule) error {
	content := RenderLogrotate(r)
	path := filepath.Join(config.Global.Nginx.LogrotateDir, fmt.Sprintf("ankerye-flow-%d", r.ID))
	return os.WriteFile(path, []byte(content), 0644)
}

// RenderLogrotate returns the exact logrotate file written for a rule.
// Keeping rendering side-effect free lets ApplyAll stage and compare the whole
// managed file set before it changes anything on disk.
func RenderLogrotate(r *model.Rule) string {
	size := r.LogMaxSize
	if size == "" {
		size = "5M"
	}
	return fmt.Sprintf(`%s/rule_%d_*.log {
    size %s
    rotate 3
    compress
    delaycompress
    missingok
    notifempty
    sharedscripts
    postrotate
        /bin/kill -USR1 $(cat /run/nginx.pid 2>/dev/null) 2>/dev/null || true
    endscript
}
`, config.Global.Nginx.LogDir, r.ID, size)
}
