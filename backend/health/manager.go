package health

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"ankerye-flow/db"
	"ankerye-flow/engine"
	"ankerye-flow/model"
)

type worker struct {
	ruleID int64
	cancel context.CancelFunc
}

var (
	mu      sync.Mutex
	workers = map[int64]*worker{}
)

// 启动/重启某规则的 worker
func RestartRule(ruleID int64) {
	mu.Lock()
	defer mu.Unlock()
	if w, ok := workers[ruleID]; ok {
		w.cancel()
		delete(workers, ruleID)
	}
	r, err := engine.LoadRule(ruleID)
	if err != nil || r.Status != 1 || r.HCEnabled != 1 {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	workers[ruleID] = &worker{ruleID: ruleID, cancel: cancel}
	go runWorker(ctx, ruleID)
}

func StopRule(ruleID int64) {
	mu.Lock()
	defer mu.Unlock()
	if w, ok := workers[ruleID]; ok {
		w.cancel()
		delete(workers, ruleID)
	}
}

func StartAll() {
	rows, _ := db.DB.Query(`SELECT id FROM rules WHERE status=1 AND hc_enabled=1`)
	if rows == nil {
		return
	}
	var ids []int64
	for rows.Next() {
		var id int64
		rows.Scan(&id)
		ids = append(ids, id)
	}
	rows.Close()
	for _, id := range ids {
		RestartRule(id)
	}
}

func runWorker(ctx context.Context, ruleID int64) {
	// 初始立即检查一次
	checkOnce(ruleID)
	// 之后按 interval 循环
	r, err := engine.LoadRule(ruleID)
	if err != nil {
		return
	}
	interval := time.Duration(r.HCInterval) * time.Second
	if interval <= 0 {
		interval = 10 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			checkOnce(ruleID)
		}
	}
}

func checkOnce(ruleID int64) {
	r, err := engine.LoadRule(ruleID)
	if err != nil {
		return
	}
	stateChanged := false
	for i := range r.Servers {
		s := &r.Servers[i]
		if s.State == "disabled" {
			continue
		}
		res := Probe(s, r)
		prevState := s.State
		now := time.Now().Format("2006-01-02 15:04:05")

		if res.OK {
			newSuccess := s.SuccessCount + 1
			newFail := 0
			if s.State == "down" && newSuccess >= r.HCRise {
				s.State = "up"
				stateChanged = true
				db.AsyncExec(`INSERT INTO health_check_logs(server_id,rule_id,state,latency_ms,message) VALUES(?,?,?,?,?)`,
					s.ID, r.ID, "up", res.Latency, "recovered")
				log.Printf("[health] rule=%d server=%s:%d RECOVERED", r.ID, s.Address, s.Port)
				go engine.SendNotify("notify_server_up",
					fmt.Sprintf("节点恢复 — %s:%d", s.Address, s.Port),
					fmt.Sprintf("规则：%s\n节点：%s:%d\n延迟：%dms\n时间：%s",
						r.Name, s.Address, s.Port, res.Latency, now))
			}
			db.AsyncExec(`UPDATE upstream_servers SET state=?,fail_count=?,success_count=?,last_check_at=?,last_err='' WHERE id=?`,
				s.State, newFail, newSuccess, now, s.ID)
		} else {
			newFail := s.FailCount + 1
			newSuccess := 0
			if s.State == "up" && newFail >= r.HCFall {
				s.State = "down"
				stateChanged = true
				db.AsyncExec(`INSERT INTO health_check_logs(server_id,rule_id,state,latency_ms,message) VALUES(?,?,?,?,?)`,
					s.ID, r.ID, "down", res.Latency, res.Err)
				log.Printf("[health] rule=%d server=%s:%d DOWN: %s", r.ID, s.Address, s.Port, res.Err)
				go engine.SendNotify("notify_server_down",
					fmt.Sprintf("节点下线 — %s:%d", s.Address, s.Port),
					fmt.Sprintf("规则：%s\n节点：%s:%d\n错误：%s\n时间：%s",
						r.Name, s.Address, s.Port, res.Err, now))
			}
			db.AsyncExec(`UPDATE upstream_servers SET state=?,fail_count=?,success_count=?,last_check_at=?,last_err=? WHERE id=?`,
				s.State, newFail, newSuccess, now, res.Err, s.ID)
		}
		_ = prevState
	}
	if stateChanged {
		// 重新渲染 nginx 配置
		if err := engine.ApplyRule(ruleID); err != nil {
			log.Printf("[health] apply rule %d failed: %v", ruleID, err)
		}
	}
}

// 外部查询节点状态
func GetState(serverID int64) *model.Server {
	s := &model.Server{}
	row := db.DB.QueryRow(`SELECT id,rule_id,address,port,weight,state,fail_count,success_count,
		IFNULL(last_check_at,''),IFNULL(last_err,''),created_at FROM upstream_servers WHERE id=?`, serverID)
	if err := row.Scan(&s.ID, &s.RuleID, &s.Address, &s.Port, &s.Weight, &s.State,
		&s.FailCount, &s.SuccessCount, &s.LastCheckAt, &s.LastErr, &s.CreatedAt); err != nil {
		return nil
	}
	return s
}
