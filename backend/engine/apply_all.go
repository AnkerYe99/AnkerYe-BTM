package engine

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"ankerye-flow/config"
	"ankerye-flow/db"
)

// renderedFile is a side-effect-free representation of one managed file.
// ApplyAll stages every present file before comparing it with the live tree.
type renderedFile struct {
	data []byte
	mode os.FileMode
}

type applyFileIntent struct {
	present bool
	file    renderedFile
}

type applyAllPlan struct {
	files        map[string]applyFileIntent
	enabledRules int
}

// These are the two package defaults removed by the legacy ApplyAll path.
// Keeping them as a variable allows tests to use an isolated filesystem while
// production retains the exact same paths and cleanup semantics.
var nginxPackageDefaultPaths = []string{
	"/etc/nginx/conf.d/default.conf",
	"/etc/nginx/sites-enabled/default",
}

var applyAllMu sync.Mutex

func newApplyAllPlan() *applyAllPlan {
	return &applyAllPlan{files: map[string]applyFileIntent{}}
}

func (p *applyAllPlan) write(path string, data []byte, mode os.FileMode) {
	p.files[path] = applyFileIntent{
		present: true,
		file: renderedFile{
			data: append([]byte(nil), data...),
			mode: mode,
		},
	}
}

func (p *applyAllPlan) remove(path string) {
	p.files[path] = applyFileIntent{present: false}
}

func buildApplyAllPlan() (*applyAllPlan, error) {
	plan := newApplyAllPlan()
	for _, path := range nginxPackageDefaultPaths {
		plan.remove(path)
	}

	rows, err := db.DB.Query(`SELECT id FROM rules WHERE status=1 ORDER BY id`)
	if err != nil {
		return nil, err
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close() // LoadRule uses the same SQLite pool; never hold this cursor open.
	plan.enabledRules = len(ids)

	for _, id := range ids {
		r, err := LoadRule(id)
		if err != nil {
			return nil, fmt.Errorf("load rule %d: %w", id, err)
		}
		text, err := RenderRule(r)
		if err != nil {
			return nil, fmt.Errorf("render rule %d: %w", id, err)
		}
		path := ruleFilePath(r.ID, r.Protocol)
		plan.write(path, []byte(text), 0644)
		if r.Protocol == "http" || r.Protocol == "https" {
			plan.remove(filepath.Join(config.Global.Nginx.ConfDir, fmt.Sprintf("%d-stream.conf", r.ID)))
		} else {
			plan.remove(filepath.Join(config.Global.Nginx.ConfDir, fmt.Sprintf("%d-http.conf", r.ID)))
		}

		caPEM := ""
		if r.UpstreamProtocol == "https" && r.ProxySSLVerify == 1 && r.ProxySSLTrustedCAPEM != "" {
			caPEM, err = NormalizeTrustedCAPEM(r.ProxySSLTrustedCAPEM)
			if err != nil {
				return nil, fmt.Errorf("normalize rule %d upstream CA: %w", id, err)
			}
		}
		caPath := UpstreamCAPath(r.ID)
		if caPEM == "" {
			plan.remove(caPath)
		} else {
			plan.write(caPath, []byte(caPEM), 0644)
		}

		logrotatePath := filepath.Join(config.Global.Nginx.LogrotateDir, fmt.Sprintf("ankerye-flow-%d", r.ID))
		plan.write(logrotatePath, []byte(RenderLogrotate(r)), 0644)
	}

	defaults, needsCatchAllCert, err := renderPortDefaultFiles()
	if err != nil {
		return nil, fmt.Errorf("render port defaults: %w", err)
	}
	existingDefaults, err := filepath.Glob(filepath.Join(config.Global.Nginx.ConfDir, "default-*-http.conf"))
	if err != nil {
		return nil, err
	}
	for _, path := range existingDefaults {
		if _, keep := defaults[path]; !keep {
			plan.remove(path)
		}
	}
	for path, file := range defaults {
		plan.write(path, file.data, file.mode)
	}
	if needsCatchAllCert {
		if err := addCatchAllCertificateToPlan(plan); err != nil {
			return nil, err
		}
	}
	return plan, nil
}

func addCatchAllCertificateToPlan(plan *applyAllPlan) error {
	dir := filepath.Join(config.Global.Nginx.CertDir, "_catchall")
	crtPath := filepath.Join(dir, "fullchain.pem")
	keyPath := filepath.Join(dir, "privkey.pem")
	crt, crtInfo, crtErr := readRenderedFile(crtPath)
	key, keyInfo, keyErr := readRenderedFile(keyPath)
	if crtErr == nil && keyErr == nil {
		plan.write(crtPath, crt, crtInfo.Mode().Perm())
		plan.write(keyPath, key, keyInfo.Mode().Perm())
		return nil
	}
	if crtErr != nil && !os.IsNotExist(crtErr) {
		return fmt.Errorf("read catch-all certificate: %w", crtErr)
	}
	if keyErr != nil && !os.IsNotExist(keyErr) {
		return fmt.Errorf("read catch-all private key: %w", keyErr)
	}
	crt, key, err := generateCatchAllCertPair()
	if err != nil {
		return fmt.Errorf("generate catch-all certificate: %w", err)
	}
	plan.write(crtPath, crt, 0644)
	plan.write(keyPath, key, 0600)
	return nil
}

func readRenderedFile(path string) ([]byte, os.FileInfo, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, nil, err
	}
	data, err := os.ReadFile(path)
	return data, info, err
}

type transactionFileSnapshot struct {
	exists     bool
	isSymlink  bool
	linkTarget string
	data       []byte
	mode       os.FileMode
}

func captureTransactionFile(path string) (transactionFileSnapshot, error) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return transactionFileSnapshot{}, nil
	}
	if err != nil {
		return transactionFileSnapshot{}, err
	}
	snap := transactionFileSnapshot{exists: true, mode: info.Mode().Perm()}
	if info.Mode()&os.ModeSymlink != 0 {
		target, err := os.Readlink(path)
		if err != nil {
			return transactionFileSnapshot{}, err
		}
		snap.isSymlink = true
		snap.linkTarget = target
		return snap, nil
	}
	if !info.Mode().IsRegular() {
		return transactionFileSnapshot{}, fmt.Errorf("managed path is not a regular file or symlink: %s", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return transactionFileSnapshot{}, err
	}
	snap.data = data
	return snap, nil
}

func snapshotMatchesIntent(snap transactionFileSnapshot, intent applyFileIntent) bool {
	if !intent.present {
		return !snap.exists
	}
	return snap.exists && !snap.isSymlink && bytes.Equal(snap.data, intent.file.data)
}

type stagedApplyAll struct {
	root      string
	desired   map[string]string
	snapshots map[string]transactionFileSnapshot
	changed   []string
}

func stageApplyAllPlan(plan *applyAllPlan) (*stagedApplyAll, error) {
	root, err := os.MkdirTemp("", "ankerye-btm-apply-all-*")
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(root, 0700); err != nil {
		os.RemoveAll(root)
		return nil, err
	}
	staged := &stagedApplyAll{
		root:      root,
		desired:   map[string]string{},
		snapshots: map[string]transactionFileSnapshot{},
	}
	paths := sortedPlanPaths(plan.files)
	desiredDir := filepath.Join(root, "desired")
	backupDir := filepath.Join(root, "backup")
	if err := os.MkdirAll(desiredDir, 0700); err != nil {
		os.RemoveAll(root)
		return nil, err
	}
	if err := os.MkdirAll(backupDir, 0700); err != nil {
		os.RemoveAll(root)
		return nil, err
	}
	for i, path := range paths {
		intent := plan.files[path]
		if intent.present {
			stagePath := filepath.Join(desiredDir, fmt.Sprintf("%06d", i))
			if err := os.WriteFile(stagePath, intent.file.data, intent.file.mode); err != nil {
				os.RemoveAll(root)
				return nil, err
			}
			staged.desired[path] = stagePath
		}
		snap, err := captureTransactionFile(path)
		if err != nil {
			os.RemoveAll(root)
			return nil, fmt.Errorf("snapshot %s: %w", path, err)
		}
		staged.snapshots[path] = snap
		if snapshotMatchesIntent(snap, intent) {
			continue
		}
		staged.changed = append(staged.changed, path)
		// Keep a physical, mode-preserving rollback copy in the 0700 staging
		// tree. The in-memory snapshot drives recovery; this copy is evidence
		// that all current bytes were backed up before the first mutation.
		if snap.exists {
			backupPath := filepath.Join(backupDir, fmt.Sprintf("%06d", i))
			if snap.isSymlink {
				if err := os.WriteFile(backupPath+".symlink", []byte(snap.linkTarget), 0600); err != nil {
					os.RemoveAll(root)
					return nil, err
				}
			} else if err := os.WriteFile(backupPath, snap.data, snap.mode); err != nil {
				os.RemoveAll(root)
				return nil, err
			}
		}
	}
	return staged, nil
}

func sortedPlanPaths(files map[string]applyFileIntent) []string {
	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths
}

func applyStagedFiles(plan *applyAllPlan, staged *stagedApplyAll) error {
	// Materialize every replacement first, then remove files whose desired
	// state is absent. nginx does not observe the disk tree until the single
	// test/reload below.
	for _, path := range staged.changed {
		intent := plan.files[path]
		if !intent.present {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return err
		}
		data, err := os.ReadFile(staged.desired[path])
		if err != nil {
			return err
		}
		if err := writeFileAtomic(path, data, intent.file.mode); err != nil {
			return err
		}
	}
	for _, path := range staged.changed {
		if plan.files[path].present {
			continue
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func restoreTransactionFile(path string, snap transactionFileSnapshot) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	if !snap.exists {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	if snap.isSymlink {
		return os.Symlink(snap.linkTarget, path)
	}
	mode := snap.mode
	if mode == 0 {
		mode = 0644
	}
	return writeFileAtomic(path, snap.data, mode)
}

func rollbackStagedFiles(staged *stagedApplyAll) error {
	var failures []string
	for _, path := range staged.changed {
		if err := restoreTransactionFile(path, staged.snapshots[path]); err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", path, err))
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("rollback failed: %s", strings.Join(failures, "; "))
	}
	return nil
}

func applyAllFailure(staged *stagedApplyAll, cause error) error {
	if rollbackErr := rollbackStagedFiles(staged); rollbackErr != nil {
		return fmt.Errorf("%v; %w", cause, rollbackErr)
	}
	return cause
}

// ApplyAll renders every file touched by the legacy per-rule startup loop into
// a private staging tree. An identical file set causes no nginx command. A
// changed set is snapshotted, atomically replaced file-by-file, tested once,
// and activated once. Any pre-activation failure restores every changed file
// and never reloads nginx.
func ApplyAll() error {
	applyAllMu.Lock()
	defer applyAllMu.Unlock()

	plan, err := buildApplyAllPlan()
	if err != nil {
		return err
	}
	staged, err := stageApplyAllPlan(plan)
	if err != nil {
		return err
	}
	defer os.RemoveAll(staged.root)

	if len(staged.changed) == 0 {
		// Legacy startup started nginx through the first ApplyRule. Preserve
		// that responsibility without turning an identical config into reload.
		if plan.enabledRules > 0 && !nginxRunning() {
			if err := smartReload(); err != nil {
				return err
			}
		}
		return nil
	}

	if err := applyStagedFiles(plan, staged); err != nil {
		return applyAllFailure(staged, fmt.Errorf("apply staged nginx files: %w", err))
	}
	if out, err := runNginxCmd("-t"); err != nil {
		return applyAllFailure(staged, fmt.Errorf("nginx syntax error; restored previous files: %s", out))
	}
	if err := smartReload(); err != nil {
		// At most one activation command is ever attempted. Official nginx
		// reload semantics keep the old workers/config when applying the new
		// configuration fails, so restore disk state without a second reload.
		return applyAllFailure(staged, fmt.Errorf("nginx activation failed; restored previous files: %w", err))
	}
	return nil
}
