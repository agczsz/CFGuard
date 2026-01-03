package config

import (
	"encoding/json"
	"os"
	"sync"
)

type Store struct {
	path string
	mu   sync.RWMutex
	data Config
}

func NewStore(path string) *Store {
	return &Store{
		path: path,
		data: Config{
			Monitors: make([]MonitorConfig, 0),
			History:  make([]SwitchEvent, 0),
			IPDown:   make([]IPDownEvent, 0),
		},
	}
}

func (s *Store) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := os.Stat(s.path); os.IsNotExist(err) {
		return nil
	}

	file, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}

	return json.Unmarshal(file, &s.data)
}

func (s *Store) Save() error {
	s.mu.RLock()
	snapshot := cloneConfig(s.data)
	s.mu.RUnlock()

	file, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(s.path, file, 0644)
}

func (s *Store) GetSnapshot() Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneConfig(s.data)
}

func (s *Store) ListMonitors() []MonitorConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]MonitorConfig, 0, len(s.data.Monitors))
	for _, m := range s.data.Monitors {
		out = append(out, cloneMonitorConfig(m))
	}
	return out
}

func (s *Store) GetMonitor(id string) (MonitorConfig, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, m := range s.data.Monitors {
		if m.ID == id {
			return cloneMonitorConfig(m), true
		}
	}
	return MonitorConfig{}, false
}

func (s *Store) UpsertMonitor(m MonitorConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, item := range s.data.Monitors {
		if item.ID == m.ID {
			s.data.Monitors[i] = m
			return s.saveLocked()
		}
	}
	s.data.Monitors = append(s.data.Monitors, m)
	return s.saveLocked()
}

func (s *Store) DeleteMonitor(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, item := range s.data.Monitors {
		if item.ID == id {
			s.data.Monitors = append(s.data.Monitors[:i], s.data.Monitors[i+1:]...)
			return s.saveLocked()
		}
	}
	return s.saveLocked()
}

func (s *Store) GetCloudflareConfig() CloudflareConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// 如果有多个凭证账户，返回当前激活的账户
	if len(s.data.CloudflareAccounts) > 0 && s.data.ActiveAccountIndex >= 0 && s.data.ActiveAccountIndex < len(s.data.CloudflareAccounts) {
		account := s.data.CloudflareAccounts[s.data.ActiveAccountIndex]
		return CloudflareConfig{
			APIToken: account.APIToken,
			APIKey:   account.APIKey,
			Email:    account.Email,
		}
	}

	// 否则返回默认配置
	return s.data.Cloudflare
}

func (s *Store) ListCloudflareAccounts() []CloudflareAccount {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]CloudflareAccount, len(s.data.CloudflareAccounts))
	copy(out, s.data.CloudflareAccounts)
	return out
}

func (s *Store) GetActiveAccountIndex() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data.ActiveAccountIndex
}

// GetAuthToken returns the configured auth token
func (s *Store) GetAuthToken() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data.Server.Auth
}

// SetAuthToken sets the auth token
func (s *Store) SetAuthToken(token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.Server.Auth = token
	return s.saveLocked()
}

// HasAuthToken checks if auth token is configured
func (s *Store) HasAuthToken() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data.Server.Auth != ""
}

func (s *Store) AddCloudflareAccount(account CloudflareAccount) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.CloudflareAccounts = append(s.data.CloudflareAccounts, account)
	return s.saveLocked()
}

func (s *Store) UpdateCloudflareAccount(account CloudflareAccount) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, item := range s.data.CloudflareAccounts {
		if item.ID == account.ID {
			s.data.CloudflareAccounts[i] = account
			return s.saveLocked()
		}
	}
	return s.saveLocked()
}

func (s *Store) DeleteCloudflareAccount(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, item := range s.data.CloudflareAccounts {
		if item.ID == id {
			s.data.CloudflareAccounts = append(s.data.CloudflareAccounts[:i], s.data.CloudflareAccounts[i+1:]...)
			// 如果删除的是当前激活的账户，重置索引
			if s.data.ActiveAccountIndex == i {
				s.data.ActiveAccountIndex = 0
			} else if s.data.ActiveAccountIndex > i {
				s.data.ActiveAccountIndex--
			}
			return s.saveLocked()
		}
	}
	return s.saveLocked()
}

func (s *Store) ActivateCloudflareAccount(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, item := range s.data.CloudflareAccounts {
		if item.ID == id {
			s.data.ActiveAccountIndex = i
			return s.saveLocked()
		}
	}
	return s.saveLocked()
}

func (s *Store) GetDingTalkConfig() DingTalkConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data.DingTalk
}

func (s *Store) GetEmailConfig() EmailConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data.Email
}

func (s *Store) GetTelegramConfig() TelegramConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data.Telegram
}

func (s *Store) UpdateGlobalConfig(cloudflare CloudflareConfig, dingtalk DingTalkConfig, email EmailConfig, telegram TelegramConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.Cloudflare = cloudflare
	s.data.DingTalk = dingtalk
	s.data.Email = email
	s.data.Telegram = telegram
	return s.saveLocked()
}

func (s *Store) AppendSwitchEvent(evt SwitchEvent, max int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.data.History = append(s.data.History, evt)
	if max > 0 && len(s.data.History) > max {
		s.data.History = s.data.History[len(s.data.History)-max:]
	}
	return s.saveLocked()
}

func (s *Store) AppendIPDownEvent(evt IPDownEvent, max int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.data.IPDown = append(s.data.IPDown, evt)
	if max > 0 && len(s.data.IPDown) > max {
		s.data.IPDown = s.data.IPDown[len(s.data.IPDown)-max:]
	}
	return s.saveLocked()
}

func (s *Store) ListSwitchHistory(limit int) []SwitchEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if limit <= 0 || limit > len(s.data.History) {
		limit = len(s.data.History)
	}

	out := make([]SwitchEvent, 0, limit)
	for i := len(s.data.History) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, s.data.History[i])
	}
	return out
}

func (s *Store) ListIPDownEvents(limit int) []IPDownEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if limit <= 0 || limit > len(s.data.IPDown) {
		limit = len(s.data.IPDown)
	}

	out := make([]IPDownEvent, 0, limit)
	for i := len(s.data.IPDown) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, s.data.IPDown[i])
	}
	return out
}

func (s *Store) saveLocked() error {
	file, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, file, 0644)
}

func cloneConfig(in Config) Config {
	out := in

	out.Monitors = make([]MonitorConfig, 0, len(in.Monitors))
	for _, m := range in.Monitors {
		out.Monitors = append(out.Monitors, cloneMonitorConfig(m))
	}

	out.History = make([]SwitchEvent, len(in.History))
	copy(out.History, in.History)

	out.IPDown = make([]IPDownEvent, len(in.IPDown))
	copy(out.IPDown, in.IPDown)

	return out
}

func cloneMonitorConfig(in MonitorConfig) MonitorConfig {
	out := in
	out.Subdomains = make([]string, len(in.Subdomains))
	copy(out.Subdomains, in.Subdomains)
	return out
}
