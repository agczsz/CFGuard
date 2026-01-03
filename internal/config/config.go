package config

type Config struct {
	Cloudflare         CloudflareConfig    `mapstructure:"cloudflare" json:"cloudflare"`
	CloudflareAccounts []CloudflareAccount `mapstructure:"cloudflare_accounts" json:"cloudflare_accounts"`
	ActiveAccountIndex int                 `mapstructure:"active_account_index" json:"active_account_index"`
	DingTalk           DingTalkConfig      `mapstructure:"dingtalk" json:"dingtalk"`
	Email              EmailConfig         `mapstructure:"email" json:"email"`
	Telegram           TelegramConfig      `mapstructure:"telegram" json:"telegram"`
	Monitors           []MonitorConfig     `mapstructure:"monitors" json:"monitors"`
	Server             ServerConfig        `mapstructure:"server" json:"server"`
	History            []SwitchEvent       `mapstructure:"history" json:"history"`
	IPDown             []IPDownEvent       `mapstructure:"ip_down" json:"ip_down"`
}

type CloudflareConfig struct {
	APIToken string `mapstructure:"api_token" json:"api_token"`
	APIKey   string `mapstructure:"api_key" json:"api_key"`
	Email    string `mapstructure:"email" json:"email"`
}

type CloudflareAccount struct {
	ID       string `mapstructure:"id" json:"id"`
	Name     string `mapstructure:"name" json:"name"`
	APIToken string `mapstructure:"api_token" json:"api_token"`
	APIKey   string `mapstructure:"api_key" json:"api_key"`
	Email    string `mapstructure:"email" json:"email"`
}

type DingTalkConfig struct {
	AccessToken string `mapstructure:"access_token" json:"access_token"`
	Secret      string `mapstructure:"secret" json:"secret"`
	Enabled     bool   `mapstructure:"enabled" json:"enabled"`
}

type EmailConfig struct {
	Enabled  bool   `mapstructure:"enabled" json:"enabled"`
	Host     string `mapstructure:"host" json:"host"`
	Port     int    `mapstructure:"port" json:"port"`
	Username string `mapstructure:"username" json:"username"`
	Password string `mapstructure:"password" json:"password"`
	To       string `mapstructure:"to" json:"to"`
}

type TelegramConfig struct {
	Enabled  bool   `mapstructure:"enabled" json:"enabled"`
	BotToken string `mapstructure:"bot_token" json:"bot_token"`
	ChatID   string `mapstructure:"chat_id" json:"chat_id"`
}

type MonitorConfig struct {
	ID                   string   `mapstructure:"id" json:"id"`
	Name                 string   `mapstructure:"name" json:"name"`
	ZoneID               string   `mapstructure:"zone_id" json:"zone_id"`
	Subdomains           []string `mapstructure:"subdomains" json:"subdomains"`
	CheckType            string   `mapstructure:"check_type" json:"check_type"`     // ping, http, https
	CheckTarget          string   `mapstructure:"check_target" json:"check_target"` // IP or URL
	OriginalIP           string   `mapstructure:"original_ip" json:"original_ip"`
	BackupIP             string   `mapstructure:"backup_ip" json:"backup_ip"`
	FailureThreshold     int      `mapstructure:"failure_threshold" json:"failure_threshold"`
	SuccessThreshold     int      `mapstructure:"success_threshold" json:"success_threshold"`
	PingCount            int      `mapstructure:"ping_count" json:"ping_count"`
	Interval             int      `mapstructure:"interval" json:"interval"`
	TimeoutSeconds       int      `mapstructure:"timeout_seconds" json:"timeout_seconds"`
	OriginalIPCDNEnabled bool     `mapstructure:"original_ip_cdn_enabled" json:"original_ip_cdn_enabled"`
	BackupIPCDNEnabled   bool     `mapstructure:"backup_ip_cdn_enabled" json:"backup_ip_cdn_enabled"`

	// Schedule switch (hours). When enabled, periodically updates DNS to the target IP.
	// If ScheduleSwitchIP is empty, it toggles between OriginalIP and BackupIP.
	ScheduleEnabled  bool   `mapstructure:"schedule_enabled" json:"schedule_enabled"`
	ScheduleHours    int    `mapstructure:"schedule_hours" json:"schedule_hours"`
	ScheduleSwitchIP string `mapstructure:"schedule_switch_ip" json:"schedule_switch_ip"`
}

type ServerConfig struct {
	Port int    `mapstructure:"port" json:"port"`
	Auth string `mapstructure:"auth" json:"auth"`
}

type SwitchEvent struct {
	Timestamp int64  `json:"timestamp"`
	MonitorID string `json:"monitor_id"`
	Name      string `json:"name"`
	FromIP    string `json:"from_ip"`
	ToIP      string `json:"to_ip"`
	ToBackup  bool   `json:"to_backup"`
	CheckType string `json:"check_type"`
	Reason    string `json:"reason,omitempty"` // failover, restore, schedule
}

type IPDownEvent struct {
	Timestamp int64  `json:"timestamp"`
	MonitorID string `json:"monitor_id"`
	Name      string `json:"name"`
	IP        string `json:"ip"`
	Role      string `json:"role"` // original, backup
}
