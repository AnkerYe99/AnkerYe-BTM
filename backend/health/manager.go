package health

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"strings"
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

	// RestartRule cancels the prior worker but does not wait for an in-flight
	// probe to return. Serialize rounds for the same rule so their counters and
	// compare-and-swap state transitions cannot overlap.
	ruleCheckLocks sync.Map // map[int64]*sync.Mutex

	// 通知冷却：同一节点 down/up 各自 1 小时硬冷却，状态切换不重置
	// 防止节点抖动 (up ↔ down) 时邮件不停发
	notifyMu     sync.Mutex
	notifyDownAt = map[int64]time.Time{} // 上次发 down 通知时间
	notifyUpAt   = map[int64]time.Time{} // 上次发 up 通知时间
)

const notifyCooldown = time.Hour

type healthTransaction interface {
	ExecContext(context.Context, string, ...interface{}) (sql.Result, error)
	Commit() error
	Rollback() error
}

type healthUpdate struct {
	before       model.Server
	state        string
	failCount    int
	successCount int
	lastCheckAt  string
	lastErr      string
	result       ProbeResult
	transition   bool
	logID        int64
}

var (
	probeHealthServer = Probe
	applyHealthRule   = engine.ApplyRule
	beginHealthTx     = func(ctx context.Context) (healthTransaction, error) {
		return db.DB.BeginTx(ctx, nil)
	}
	healthNow            = time.Now
	dispatchHealthNotify = func(key, subject, body string) {
		go func() {
			if err := engine.SendNotify(key, subject, body); err != nil {
				log.Printf("[health] notify failed: %v", err)
			}
		}()
	}
	dispatchHealthCritical = func(subject, body string) {
		go func() {
			if err := engine.SendNotify("", subject, body); err != nil {
				log.Printf("[health] CRITICAL notify failed: %v", err)
			}
		}()
	}
)

func canNotifyDown(serverID int64) bool {
	notifyMu.Lock()
	defer notifyMu.Unlock()
	last, ok := notifyDownAt[serverID]
	if !ok || time.Since(last) >= notifyCooldown {
		notifyDownAt[serverID] = time.Now()
		return true
	}
	return false
}

func canNotifyUp(serverID int64) bool {
	notifyMu.Lock()
	defer notifyMu.Unlock()
	last, ok := notifyUpAt[serverID]
	if !ok || time.Since(last) >= notifyCooldown {
		notifyUpAt[serverID] = time.Now()
		return true
	}
	return false
}

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
	lockValue, _ := ruleCheckLocks.LoadOrStore(ruleID, &sync.Mutex{})
	lock := lockValue.(*sync.Mutex)
	lock.Lock()
	defer lock.Unlock()

	if err := checkRuleOnce(context.Background(), ruleID); err != nil {
		log.Printf("[health] rule=%d check failed: %v", ruleID, err)
	}
}

func checkRuleOnce(ctx context.Context, ruleID int64) error {
	r, err := engine.LoadRule(ruleID)
	if err != nil {
		return fmt.Errorf("load rule: %w", err)
	}
	now := healthNow()
	nowText := now.Format("2006-01-02 15:04:05")
	updates := make([]healthUpdate, 0, len(r.Servers))
	for i := range r.Servers {
		s := &r.Servers[i]
		if s.State == "disabled" {
			continue
		}
		res := probeHealthServer(s, r)
		update := healthUpdate{
			before:      *s,
			state:       s.State,
			lastCheckAt: nowText,
			result:      res,
		}

		if res.OK {
			update.successCount = s.SuccessCount + 1
			update.failCount = 0
			if s.State == "down" && update.successCount >= r.HCRise {
				update.state = "up"
				update.transition = true
			}
		} else {
			update.failCount = s.FailCount + 1
			update.successCount = 0
			update.lastErr = res.Err
			if s.State == "up" && update.failCount >= r.HCFall {
				update.state = "down"
				update.transition = true
			}
		}
		updates = append(updates, update)
	}
	if len(updates) == 0 {
		return nil
	}
	if err := persistHealthUpdates(ctx, r.ID, updates); err != nil {
		return fmt.Errorf("persist probe results: %w", err)
	}

	hasTransition := false
	for i := range updates {
		if updates[i].transition {
			hasTransition = true
			break
		}
	}
	if !hasTransition {
		return nil
	}

	if err := applyHealthRule(ruleID); err != nil {
		compensateErr := compensateHealthUpdates(ctx, r.ID, updates, err)
		if compensateErr != nil {
			message := fmt.Sprintf("rule=%d apply failed: %v; compensation failed: %v", ruleID, err, compensateErr)
			log.Printf("[health] CRITICAL %s", message)
			dispatchHealthCritical(
				fmt.Sprintf("BTM 健康状态补偿失败 - 规则 %d", ruleID),
				message,
			)
			return fmt.Errorf("apply rule: %w; CRITICAL compensation failed: %v", err, compensateErr)
		}
		log.Printf("[health] rule=%d apply failed, database state compensated: %v", ruleID, err)
		return fmt.Errorf("apply rule: %w (database state compensated)", err)
	}

	for i := range updates {
		update := &updates[i]
		if !update.transition {
			continue
		}
		emitHealthTransition(r, update, nowText)
	}
	return nil
}

func persistHealthUpdates(ctx context.Context, ruleID int64, updates []healthUpdate) error {
	tx, err := beginHealthTx(ctx)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()

	for i := range updates {
		update := &updates[i]
		result, err := tx.ExecContext(ctx, `UPDATE upstream_servers
			SET state=?,fail_count=?,success_count=?,last_check_at=?,last_err=?
			WHERE id=? AND rule_id=? AND state=? AND address=? AND port=?`,
			update.state, update.failCount, update.successCount, update.lastCheckAt, update.lastErr,
			update.before.ID, ruleID, update.before.State, update.before.Address, update.before.Port)
		if err != nil {
			return fmt.Errorf("update server %d: %w", update.before.ID, err)
		}
		if err := requireOneRow(result, fmt.Sprintf("update server %d", update.before.ID)); err != nil {
			return err
		}
		if !update.transition {
			continue
		}
		message := update.result.Err
		if update.state == "up" {
			message = "recovered"
		}
		result, err = tx.ExecContext(ctx,
			`INSERT INTO health_check_logs(server_id,rule_id,state,latency_ms,message) VALUES(?,?,?,?,?)`,
			update.before.ID, ruleID, update.state, update.result.Latency, message)
		if err != nil {
			return fmt.Errorf("insert health log for server %d: %w", update.before.ID, err)
		}
		update.logID, err = result.LastInsertId()
		if err != nil {
			return fmt.Errorf("read health log id for server %d: %w", update.before.ID, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}
	return nil
}

func compensateHealthUpdates(ctx context.Context, ruleID int64, updates []healthUpdate, applyErr error) error {
	tx, err := beginHealthTx(ctx)
	if err != nil {
		return fmt.Errorf("begin compensation: %w", err)
	}
	defer tx.Rollback()

	for i := range updates {
		update := &updates[i]
		result, err := tx.ExecContext(ctx, `UPDATE upstream_servers
			SET state=?,fail_count=?,success_count=?,last_check_at=NULLIF(?,''),last_err=?
			WHERE id=? AND rule_id=? AND state=? AND address=? AND port=? AND fail_count=? AND success_count=?
				AND IFNULL(last_check_at,'')=? AND IFNULL(last_err,'')=?`,
			update.before.State, update.before.FailCount, update.before.SuccessCount,
			update.before.LastCheckAt, update.before.LastErr,
			update.before.ID, ruleID, update.state, update.before.Address, update.before.Port,
			update.failCount, update.successCount,
			update.lastCheckAt, update.lastErr)
		if err != nil {
			return fmt.Errorf("restore server %d: %w", update.before.ID, err)
		}
		if err := requireOneRow(result, fmt.Sprintf("restore server %d", update.before.ID)); err != nil {
			return err
		}
		if !update.transition {
			continue
		}
		message := update.result.Err
		if update.state == "up" {
			message = "recovered"
		}
		message += "; apply failed, state compensated: " + compactHealthError(applyErr)
		result, err = tx.ExecContext(ctx,
			`UPDATE health_check_logs SET message=? WHERE id=? AND server_id=? AND rule_id=?`,
			message, update.logID, update.before.ID, ruleID)
		if err != nil {
			return fmt.Errorf("audit health log %d: %w", update.logID, err)
		}
		if err := requireOneRow(result, fmt.Sprintf("audit health log %d", update.logID)); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit compensation: %w", err)
	}
	return nil
}

func requireOneRow(result sql.Result, operation string) error {
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("%s rows affected: %w", operation, err)
	}
	if rows != 1 {
		return fmt.Errorf("%s compare-and-swap conflict: affected %d rows", operation, rows)
	}
	return nil
}

func compactHealthError(err error) string {
	message := strings.NewReplacer("\r", " ", "\n", " ").Replace(err.Error())
	runes := []rune(message)
	if len(runes) > 512 {
		return string(runes[:512])
	}
	return message
}

func emitHealthTransition(r *model.Rule, update *healthUpdate, now string) {
	s := &update.before
	if update.state == "up" {
		log.Printf("[health] rule=%d server=%s:%d RECOVERED", r.ID, s.Address, s.Port)
		if canNotifyUp(s.ID) {
			dispatchHealthNotify("notify_server_up",
				fmt.Sprintf("%s-节点恢复", r.Name),
				fmt.Sprintf("规则：%s\n节点：%s:%d\n延迟：%dms\n时间：%s",
					r.Name, s.Address, s.Port, update.result.Latency, now))
		}
		return
	}
	log.Printf("[health] rule=%d server=%s:%d DOWN: %s", r.ID, s.Address, s.Port, update.result.Err)
	if canNotifyDown(s.ID) {
		dispatchHealthNotify("notify_server_down",
			fmt.Sprintf("%s-节点异常", r.Name),
			fmt.Sprintf("规则：%s\n节点：%s:%d\n错误：%s\n时间：%s",
				r.Name, s.Address, s.Port, update.result.Err, now))
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
