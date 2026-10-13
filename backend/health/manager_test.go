package health

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ankerye-flow/db"
	"ankerye-flow/engine"
	"ankerye-flow/model"
)

const healthTestNowText = "2026-10-14 01:30:00"

func setupHealthManagerTest(t *testing.T) {
	t.Helper()
	oldProbe := probeHealthServer
	oldApply := applyHealthRule
	oldBegin := beginHealthTx
	oldNow := healthNow
	oldNotify := dispatchHealthNotify
	oldCritical := dispatchHealthCritical
	t.Cleanup(func() {
		probeHealthServer = oldProbe
		applyHealthRule = oldApply
		beginHealthTx = oldBegin
		healthNow = oldNow
		dispatchHealthNotify = oldNotify
		dispatchHealthCritical = oldCritical
	})

	notifyMu.Lock()
	notifyDownAt = map[int64]time.Time{}
	notifyUpAt = map[int64]time.Time{}
	notifyMu.Unlock()
	healthNow = func() time.Time {
		value, err := time.ParseInLocation("2006-01-02 15:04:05", healthTestNowText, time.Local)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	dispatchHealthNotify = func(string, string, string) {}
	dispatchHealthCritical = func(string, string) {}

	if err := db.Init(filepath.Join(t.TempDir(), "health.db")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.DB.Close() })
	if _, err := db.DB.Exec(`INSERT INTO rules(
		id,name,protocol,listen_port,listen_stack,server_name,lb_method,
		hc_enabled,hc_interval,hc_timeout,hc_path,hc_rise,hc_fall,status
	) VALUES(1,'health-race','http',8080,'v4','api.example.invalid','round_robin',
		1,10,3,'/health',2,2,1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstream_servers(
		id,rule_id,address,port,weight,state,fail_count,success_count,last_check_at,last_err
	) VALUES
		(1,1,'192.0.2.10',8080,1,'up',0,0,NULL,''),
		(2,1,'192.0.2.11',8080,1,'down',0,1,'2026-10-14 01:00:00','old failure')`); err != nil {
		t.Fatal(err)
	}
}

func TestRecoveryCommitsBeforeRenderAndIncludesRecoveredServer(t *testing.T) {
	setupHealthManagerTest(t)
	probeHealthServer = func(_ *model.Server, _ *model.Rule) ProbeResult {
		return ProbeResult{OK: true, Latency: 12}
	}
	events := []string{}
	applyHealthRule = func(ruleID int64) error {
		events = append(events, "apply")
		rule, err := engine.LoadRule(ruleID)
		if err != nil {
			return err
		}
		if rule.Servers[1].State != "up" {
			return fmt.Errorf("apply observed stale state %q", rule.Servers[1].State)
		}
		text, err := engine.RenderRule(rule)
		if err != nil {
			return err
		}
		if !strings.Contains(text, "server 192.0.2.11:8080") {
			return errors.New("recovered server missing from rendered upstream")
		}
		return nil
	}
	dispatchHealthNotify = func(string, string, string) {
		events = append(events, "notify")
	}

	if err := checkRuleOnce(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(events, ","), "apply,notify"; got != want {
		t.Fatalf("event order=%q want=%q", got, want)
	}
	state, failCount, successCount, lastCheck, lastErr := readHealthServer(t, 2)
	if state != "up" || failCount != 0 || successCount != 2 || lastCheck != healthTestNowText || lastErr != "" {
		t.Fatalf("recovered state=%q fail=%d success=%d lastCheck=%q lastErr=%q",
			state, failCount, successCount, lastCheck, lastErr)
	}
	var logState, message string
	if err := db.DB.QueryRow(`SELECT state,message FROM health_check_logs WHERE server_id=2`).Scan(&logState, &message); err != nil {
		t.Fatal(err)
	}
	if logState != "up" || message != "recovered" {
		t.Fatalf("health log state=%q message=%q", logState, message)
	}
}

func TestDownTransitionsCommitTogetherAndRenderOnlyFallback(t *testing.T) {
	setupHealthManagerTest(t)
	if _, err := db.DB.Exec(`UPDATE upstream_servers SET state='up',fail_count=1,success_count=0,last_err=''`); err != nil {
		t.Fatal(err)
	}
	probeHealthServer = func(_ *model.Server, _ *model.Rule) ProbeResult {
		return ProbeResult{OK: false, Latency: 7, Err: "synthetic failure"}
	}
	applyCalls := 0
	applyHealthRule = func(ruleID int64) error {
		applyCalls++
		rule, err := engine.LoadRule(ruleID)
		if err != nil {
			return err
		}
		text, err := engine.RenderRule(rule)
		if err != nil {
			return err
		}
		if strings.Contains(text, "server 192.0.2.10:8080") {
			return errors.New("first down server was not excluded")
		}
		if !strings.Contains(text, "server 192.0.2.11:8080") {
			return errors.New("existing all-down fallback semantics changed")
		}
		return nil
	}

	if err := checkRuleOnce(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	if applyCalls != 1 {
		t.Fatalf("apply calls=%d want=1", applyCalls)
	}
	var downCount, logCount int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM upstream_servers WHERE rule_id=1 AND state='down'`).Scan(&downCount); err != nil {
		t.Fatal(err)
	}
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM health_check_logs WHERE rule_id=1 AND state='down'`).Scan(&logCount); err != nil {
		t.Fatal(err)
	}
	if downCount != 2 || logCount != 2 {
		t.Fatalf("down servers=%d logs=%d want=2/2", downCount, logCount)
	}
}

func TestNoTransitionUpdatesCountersWithoutApply(t *testing.T) {
	setupHealthManagerTest(t)
	if _, err := db.DB.Exec(`UPDATE upstream_servers SET state='up',fail_count=0,success_count=0,last_err=''`); err != nil {
		t.Fatal(err)
	}
	probeHealthServer = func(_ *model.Server, _ *model.Rule) ProbeResult {
		return ProbeResult{OK: true, Latency: 1}
	}
	applyCalls := 0
	applyHealthRule = func(int64) error {
		applyCalls++
		return nil
	}

	if err := checkRuleOnce(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	if applyCalls != 0 {
		t.Fatalf("apply calls=%d want=0", applyCalls)
	}
	for _, id := range []int64{1, 2} {
		state, failCount, successCount, lastCheck, lastErr := readHealthServer(t, id)
		if state != "up" || failCount != 0 || successCount != 1 || lastCheck != healthTestNowText || lastErr != "" {
			t.Fatalf("server %d state=%q fail=%d success=%d lastCheck=%q lastErr=%q",
				id, state, failCount, successCount, lastCheck, lastErr)
		}
	}
}

func TestCASConflictDoesNotOverwriteDisabledOrPartiallyCommit(t *testing.T) {
	setupHealthManagerTest(t)
	probeHealthServer = func(server *model.Server, _ *model.Rule) ProbeResult {
		if server.ID == 2 {
			if _, err := db.DB.Exec(`UPDATE upstream_servers SET state='disabled' WHERE id=2`); err != nil {
				t.Fatal(err)
			}
		}
		return ProbeResult{OK: true, Latency: 1}
	}
	applyCalls := 0
	applyHealthRule = func(int64) error {
		applyCalls++
		return nil
	}

	if err := checkRuleOnce(context.Background(), 1); err == nil || !strings.Contains(err.Error(), "compare-and-swap conflict") {
		t.Fatalf("error=%v want CAS conflict", err)
	}
	if applyCalls != 0 {
		t.Fatalf("apply calls=%d want=0", applyCalls)
	}
	state1, _, success1, lastCheck1, _ := readHealthServer(t, 1)
	state2, _, success2, _, _ := readHealthServer(t, 2)
	if state1 != "up" || success1 != 0 || lastCheck1 != "" {
		t.Fatalf("server 1 was partially committed: state=%q success=%d lastCheck=%q", state1, success1, lastCheck1)
	}
	if state2 != "disabled" || success2 != 1 {
		t.Fatalf("manual disable overwritten: state=%q success=%d", state2, success2)
	}
}

func TestApplyFailureRestoresDatabaseAndAuditsWithoutNotification(t *testing.T) {
	setupHealthManagerTest(t)
	probeHealthServer = func(_ *model.Server, _ *model.Rule) ProbeResult {
		return ProbeResult{OK: true, Latency: 2}
	}
	applyHealthRule = func(int64) error { return errors.New("synthetic nginx failure\nsecond line") }
	notifyCalls := 0
	dispatchHealthNotify = func(string, string, string) { notifyCalls++ }

	err := checkRuleOnce(context.Background(), 1)
	if err == nil || !strings.Contains(err.Error(), "database state compensated") {
		t.Fatalf("error=%v want compensated apply failure", err)
	}
	if notifyCalls != 0 {
		t.Fatalf("notifications=%d want=0", notifyCalls)
	}
	state1, fail1, success1, lastCheck1, lastErr1 := readHealthServer(t, 1)
	if state1 != "up" || fail1 != 0 || success1 != 0 || lastCheck1 != "" || lastErr1 != "" {
		t.Fatalf("server 1 not restored: %q %d %d %q %q", state1, fail1, success1, lastCheck1, lastErr1)
	}
	state2, fail2, success2, lastCheck2, lastErr2 := readHealthServer(t, 2)
	if state2 != "down" || fail2 != 0 || success2 != 1 || lastCheck2 != "2026-10-14 01:00:00" || lastErr2 != "old failure" {
		t.Fatalf("server 2 not restored: %q %d %d %q %q", state2, fail2, success2, lastCheck2, lastErr2)
	}
	var message string
	if err := db.DB.QueryRow(`SELECT message FROM health_check_logs WHERE server_id=2`).Scan(&message); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(message, "apply failed, state compensated: synthetic nginx failure second line") {
		t.Fatalf("missing compensation audit: %q", message)
	}
}

func TestCompensationFailureRaisesCriticalAlert(t *testing.T) {
	setupHealthManagerTest(t)
	probeHealthServer = func(_ *model.Server, _ *model.Rule) ProbeResult {
		return ProbeResult{OK: true, Latency: 2}
	}
	applyHealthRule = func(int64) error { return errors.New("synthetic apply failure") }
	realBegin := beginHealthTx
	beginCalls := 0
	beginHealthTx = func(ctx context.Context) (healthTransaction, error) {
		beginCalls++
		if beginCalls == 2 {
			return nil, errors.New("synthetic compensation begin failure")
		}
		return realBegin(ctx)
	}
	criticalCalls := 0
	dispatchHealthCritical = func(_, body string) {
		criticalCalls++
		if !strings.Contains(body, "compensation failed") {
			t.Errorf("critical body=%q", body)
		}
	}

	err := checkRuleOnce(context.Background(), 1)
	if err == nil || !strings.Contains(err.Error(), "CRITICAL compensation failed") {
		t.Fatalf("error=%v want critical compensation failure", err)
	}
	if criticalCalls != 1 {
		t.Fatalf("critical alerts=%d want=1", criticalCalls)
	}
	state, _, successCount, lastCheck, _ := readHealthServer(t, 2)
	if state != "up" || successCount != 2 || lastCheck != healthTestNowText {
		t.Fatalf("expected committed state after failed compensation: %q success=%d lastCheck=%q",
			state, successCount, lastCheck)
	}
}

func TestHealthTransactionBeginExecCommitFailuresNeverApply(t *testing.T) {
	baseUpdate := healthUpdate{
		before:       model.Server{ID: 1, RuleID: 1, State: "down", SuccessCount: 1},
		state:        "up",
		successCount: 2,
		lastCheckAt:  healthTestNowText,
		transition:   true,
		result:       ProbeResult{OK: true},
	}
	tests := []struct {
		name      string
		beginErr  error
		execErrAt int
		commitErr error
	}{
		{name: "begin", beginErr: errors.New("begin failed")},
		{name: "exec", execErrAt: 1},
		{name: "commit", commitErr: errors.New("commit failed")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oldBegin := beginHealthTx
			t.Cleanup(func() { beginHealthTx = oldBegin })
			fake := &fakeHealthTx{execErrAt: tt.execErrAt, commitErr: tt.commitErr}
			beginHealthTx = func(context.Context) (healthTransaction, error) {
				if tt.beginErr != nil {
					return nil, tt.beginErr
				}
				return fake, nil
			}
			updates := []healthUpdate{baseUpdate}
			if err := persistHealthUpdates(context.Background(), 1, updates); err == nil {
				t.Fatal("transaction unexpectedly succeeded")
			}
			if fake.commits > 1 {
				t.Fatalf("commits=%d want<=1", fake.commits)
			}
		})
	}
}

func TestMultipleTransitionsUseOneCommit(t *testing.T) {
	oldBegin := beginHealthTx
	t.Cleanup(func() { beginHealthTx = oldBegin })
	fake := &fakeHealthTx{}
	beginHealthTx = func(context.Context) (healthTransaction, error) { return fake, nil }
	updates := []healthUpdate{
		{
			before: model.Server{ID: 1, RuleID: 1, State: "down"}, state: "up",
			successCount: 2, lastCheckAt: healthTestNowText, transition: true,
			result: ProbeResult{OK: true},
		},
		{
			before: model.Server{ID: 2, RuleID: 1, State: "up"}, state: "down",
			failCount: 2, lastCheckAt: healthTestNowText, lastErr: "failed", transition: true,
			result: ProbeResult{Err: "failed"},
		},
	}
	if err := persistHealthUpdates(context.Background(), 1, updates); err != nil {
		t.Fatal(err)
	}
	if fake.commits != 1 || fake.execCalls != 4 {
		t.Fatalf("commits=%d execs=%d want=1/4", fake.commits, fake.execCalls)
	}
	if updates[0].logID == 0 || updates[1].logID == 0 {
		t.Fatalf("health log ids not captured: %+v", updates)
	}
}

func readHealthServer(t *testing.T, id int64) (state string, failCount, successCount int, lastCheck, lastErr string) {
	t.Helper()
	if err := db.DB.QueryRow(`SELECT state,fail_count,success_count,IFNULL(last_check_at,''),IFNULL(last_err,'')
		FROM upstream_servers WHERE id=?`, id).Scan(&state, &failCount, &successCount, &lastCheck, &lastErr); err != nil {
		t.Fatal(err)
	}
	return
}

type fakeSQLResult struct {
	id   int64
	rows int64
}

func (r fakeSQLResult) LastInsertId() (int64, error) { return r.id, nil }
func (r fakeSQLResult) RowsAffected() (int64, error) { return r.rows, nil }

type fakeHealthTx struct {
	execCalls int
	execErrAt int
	commits   int
	rollbacks int
	commitErr error
}

func (tx *fakeHealthTx) ExecContext(_ context.Context, _ string, _ ...interface{}) (sql.Result, error) {
	tx.execCalls++
	if tx.execErrAt == tx.execCalls {
		return nil, errors.New("synthetic exec failure")
	}
	return fakeSQLResult{id: int64(tx.execCalls), rows: 1}, nil
}

func (tx *fakeHealthTx) Commit() error {
	tx.commits++
	return tx.commitErr
}

func (tx *fakeHealthTx) Rollback() error {
	tx.rollbacks++
	return nil
}
