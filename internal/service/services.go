package service

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/smtp"
	"net/url"
	"strings"
	"time"

	"dns-failover/internal/config"

	"github.com/cloudflare/cloudflare-go"
)

type DNSService struct {
	api *cloudflare.API
}

func NewDNSService(cfg config.CloudflareConfig) (*DNSService, error) {
	var (
		api *cloudflare.API
		err error
	)

	if cfg.APIToken != "" {
		api, err = cloudflare.NewWithAPIToken(cfg.APIToken)
	} else {
		api, err = cloudflare.New(cfg.APIKey, cfg.Email)
	}
	if err != nil {
		return nil, err
	}
	return &DNSService{api: api}, nil
}

// ListZones 获取所有域名列表
func (s *DNSService) ListZones(ctx context.Context) ([]cloudflare.Zone, error) {
	zones, err := s.api.ListZones(ctx)
	if err != nil {
		return nil, err
	}
	return zones, nil
}

// ListRecords 获取特定 Zone 的所有解析记录
func (s *DNSService) ListRecords(ctx context.Context, zoneID string) ([]cloudflare.DNSRecord, error) {
	records, _, err := s.api.ListDNSRecords(ctx, cloudflare.ZoneIdentifier(zoneID), cloudflare.ListDNSRecordsParams{})
	if err != nil {
		return nil, err
	}
	return records, nil
}

// GetRecord 获取特定解析记录详情
func (s *DNSService) GetRecord(ctx context.Context, zoneID, recordID string) (cloudflare.DNSRecord, error) {
	return s.api.GetDNSRecord(ctx, cloudflare.ZoneIdentifier(zoneID), recordID)
}

// CreateRecord 创建解析记录
func (s *DNSService) CreateRecord(ctx context.Context, zoneID string, params cloudflare.CreateDNSRecordParams) (cloudflare.DNSRecord, error) {
	return s.api.CreateDNSRecord(ctx, cloudflare.ZoneIdentifier(zoneID), params)
}

// UpdateRecord 更新解析记录
func (s *DNSService) UpdateRecord(ctx context.Context, zoneID string, params cloudflare.UpdateDNSRecordParams) (cloudflare.DNSRecord, error) {
	return s.api.UpdateDNSRecord(ctx, cloudflare.ZoneIdentifier(zoneID), params)
}

// DeleteRecord 删除解析记录
func (s *DNSService) DeleteRecord(ctx context.Context, zoneID, recordID string) error {
	return s.api.DeleteDNSRecord(ctx, cloudflare.ZoneIdentifier(zoneID), recordID)
}

// UpdateRecordBySubdomain 根据子域名更新 IP (用于 Failover)
func (s *DNSService) UpdateRecordBySubdomain(ctx context.Context, zoneID, subdomain, ip string, proxied bool) error {
	records, _, err := s.api.ListDNSRecords(ctx, cloudflare.ZoneIdentifier(zoneID), cloudflare.ListDNSRecordsParams{
		Name: subdomain,
	})
	if err != nil {
		return err
	}

	if len(records) == 0 {
		return fmt.Errorf("no DNS record found for %s", subdomain)
	}

	recordID := records[0].ID
	_, err = s.api.UpdateDNSRecord(ctx, cloudflare.ZoneIdentifier(zoneID), cloudflare.UpdateDNSRecordParams{
		ID:      recordID,
		Type:    "A",
		Name:    subdomain,
		Content: ip,
		Proxied: &proxied,
	})

	return err
}

// SearchRecords 搜索解析记录
func (s *DNSService) SearchRecords(ctx context.Context, zoneID, query string) ([]cloudflare.DNSRecord, error) {
	records, _, err := s.api.ListDNSRecords(ctx, cloudflare.ZoneIdentifier(zoneID), cloudflare.ListDNSRecordsParams{})
	if err != nil {
		return nil, err
	}

	var results []cloudflare.DNSRecord
	query = strings.ToLower(query)
	for _, record := range records {
		if strings.Contains(strings.ToLower(record.Name), query) ||
			strings.Contains(strings.ToLower(record.Content), query) ||
			strings.Contains(strings.ToLower(record.Type), query) {
			results = append(results, record)
		}
	}
	return results, nil
}

// BulkUpdateRecords 批量更新解析记录
func (s *DNSService) BulkUpdateRecords(ctx context.Context, zoneID string, updates []BulkUpdateRequest) ([]BulkUpdateResult, error) {
	var results []BulkUpdateResult

	for _, update := range updates {
		result := BulkUpdateResult{
			RecordID: update.RecordID,
			Success:  false,
		}

		record, err := s.GetRecord(ctx, zoneID, update.RecordID)
		if err != nil {
			result.Error = err.Error()
			results = append(results, result)
			continue
		}

		params := cloudflare.UpdateDNSRecordParams{
			ID:      update.RecordID,
			Type:    record.Type,
			Name:    record.Name,
			Content: update.Content,
			TTL:     update.TTL,
			Proxied: update.Proxied,
		}

		if update.Content != "" {
			params.Content = update.Content
		}
		if update.TTL > 0 {
			params.TTL = update.TTL
		}
		if update.Proxied != nil {
			params.Proxied = update.Proxied
		}

		_, err = s.UpdateRecord(ctx, zoneID, params)
		if err != nil {
			result.Error = err.Error()
		} else {
			result.Success = true
		}
		results = append(results, result)
	}

	return results, nil
}

// GetZoneAnalytics 获取域名分析数据
func (s *DNSService) GetZoneAnalytics(ctx context.Context, zoneID string) (cloudflare.ZoneAnalyticsData, error) {
	return s.api.ZoneAnalyticsDashboard(ctx, zoneID, cloudflare.ZoneAnalyticsOptions{})
}

// GetZoneSettings 获取域名设置
func (s *DNSService) GetZoneSettings(ctx context.Context, zoneID string) (*cloudflare.ZoneSettingResponse, error) {
	return s.api.ZoneSettings(ctx, zoneID)
}

// UpdateZoneSetting 更新域名设置
func (s *DNSService) UpdateZoneSetting(ctx context.Context, zoneID string, setting cloudflare.ZoneSetting) (cloudflare.ZoneSetting, error) {
	return s.api.UpdateZoneSetting(ctx, &cloudflare.ResourceContainer{Identifier: zoneID}, cloudflare.UpdateZoneSettingParams{
		Name:  setting.ID,
		Value: setting.Value,
	})
}

// BulkUpdateRequest 批量更新请求
type BulkUpdateRequest struct {
	RecordID string `json:"record_id"`
	Content  string `json:"content,omitempty"`
	TTL      int    `json:"ttl,omitempty"`
	Proxied  *bool  `json:"proxied,omitempty"`
}

// BulkUpdateResult 批量更新结果
type BulkUpdateResult struct {
	RecordID string `json:"record_id"`
	Success  bool   `json:"success"`
	Error    string `json:"error,omitempty"`
}

type NotificationService struct {
	ding     config.DingTalkConfig
	email    config.EmailConfig
	telegram config.TelegramConfig
}

func NewNotificationService(ding config.DingTalkConfig, email config.EmailConfig, telegram config.TelegramConfig) *NotificationService {
	return &NotificationService{ding: ding, email: email, telegram: telegram}
}

func (s *NotificationService) Notify(message string) {
	s.SendDingTalk(message)
	s.SendEmail(message)
	s.SendTelegram(message)
}

func (s *NotificationService) SendDingTalk(message string) {
	if !s.ding.Enabled || s.ding.AccessToken == "" {
		return
	}

	var webhookURL string

	if s.ding.Secret != "" {
		timestamp := time.Now().UnixNano() / 1e6
		stringToSign := fmt.Sprintf("%d\x0a%s", timestamp, s.ding.Secret)

		h := hmac.New(sha256.New, []byte(s.ding.Secret))
		h.Write([]byte(stringToSign))
		sign := url.QueryEscape(base64.StdEncoding.EncodeToString(h.Sum(nil)))

		webhookURL = fmt.Sprintf("https://oapi.dingtalk.com/robot/send?access_token=%s&timestamp=%d&sign=%s",
			s.ding.AccessToken, timestamp, sign)
	} else {
		webhookURL = fmt.Sprintf("https://oapi.dingtalk.com/robot/send?access_token=%s", s.ding.AccessToken)
	}

	payload := map[string]interface{}{
		"msgtype": "text",
		"text": map[string]string{
			"content": message,
		},
	}

	body, _ := json.Marshal(payload)
	resp, err := http.Post(webhookURL, "application/json", bytes.NewBuffer(body))
	if err != nil {
		log.Printf("Failed to send DingTalk notification: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("DingTalk API returned non-OK status: %d", resp.StatusCode)
	}
}

func (s *NotificationService) SendTelegram(message string) {
	if !s.telegram.Enabled || s.telegram.BotToken == "" || s.telegram.ChatID == "" {
		return
	}

	endpoint := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", s.telegram.BotToken)
	payload := map[string]interface{}{
		"chat_id": s.telegram.ChatID,
		"text":    message,
	}

	body, _ := json.Marshal(payload)
	resp, err := http.Post(endpoint, "application/json", bytes.NewBuffer(body))
	if err != nil {
		log.Printf("Failed to send Telegram notification: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Printf("Telegram API returned non-2xx status: %d", resp.StatusCode)
	}
}

func (s *NotificationService) SendEmail(message string) {
	if !s.email.Enabled || s.email.Host == "" || s.email.Port == 0 || s.email.Username == "" || s.email.Password == "" || s.email.To == "" {
		return
	}

	toList := splitCSVEmails(s.email.To)
	if len(toList) == 0 {
		return
	}

	subject := "DNS 故障切换通知"
	msg := buildHTMLEmail(s.email.Username, toList, subject, message)

	addr := fmt.Sprintf("%s:%d", s.email.Host, s.email.Port)
	auth := smtp.PlainAuth("", s.email.Username, s.email.Password, s.email.Host)

	// Port 465 uses implicit TLS.
	if s.email.Port == 465 {
		tlsConn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: s.email.Host})
		if err != nil {
			log.Printf("Failed to dial SMTP TLS: %v", err)
			return
		}
		defer tlsConn.Close()

		c, err := smtp.NewClient(tlsConn, s.email.Host)
		if err != nil {
			log.Printf("Failed to create SMTP client: %v", err)
			return
		}
		defer c.Quit()

		if err := c.Auth(auth); err != nil {
			log.Printf("SMTP auth failed: %v", err)
			return
		}

		if err := c.Mail(s.email.Username); err != nil {
			log.Printf("SMTP MAIL FROM failed: %v", err)
			return
		}
		for _, to := range toList {
			if err := c.Rcpt(to); err != nil {
				log.Printf("SMTP RCPT TO failed: %v", err)
				return
			}
		}

		w, err := c.Data()
		if err != nil {
			log.Printf("SMTP DATA failed: %v", err)
			return
		}
		if _, err := w.Write([]byte(msg)); err != nil {
			log.Printf("SMTP write failed: %v", err)
			_ = w.Close()
			return
		}
		_ = w.Close()
		return
	}

	if err := smtp.SendMail(addr, auth, s.email.Username, toList, []byte(msg)); err != nil {
		log.Printf("Failed to send Email notification: %v", err)
	}
}

func splitCSVEmails(in string) []string {
	parts := strings.Split(in, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	return out
}

func buildPlainEmail(from string, to []string, subject string, body string) string {
	headers := []string{
		fmt.Sprintf("From: %s", from),
		fmt.Sprintf("To: %s", strings.Join(to, ",")),
		fmt.Sprintf("Subject: %s", subject),
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=UTF-8",
		"",
	}
	return strings.Join(headers, "\r\n") + body + "\r\n"
}

func buildHTMLEmail(from string, to []string, subject string, body string) string {
	now := time.Now().Format("2006-01-02 15:04:05")

	htmlBody := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>%s</title>
</head>
<body style="margin: 0; padding: 0; font-family: Arial, 'Helvetica Neue', Helvetica, sans-serif; background-color: #f5f5f5;">
    <table width="100%%" cellpadding="0" cellspacing="0" style="background-color: #f5f5f5; padding: 20px 0;">
        <tr>
            <td align="center">
                <table width="600" cellpadding="0" cellspacing="0" style="background-color: #ffffff; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">
                    <!-- Header -->
                    <tr>
                        <td style="background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%); padding: 30px; border-radius: 8px 8px 0 0;">
                            <h1 style="margin: 0; color: #ffffff; font-size: 24px; font-weight: 600;">
                                🔔 DNS 故障切换通知
                            </h1>
                        </td>
                    </tr>
                    
                    <!-- Content -->
                    <tr>
                        <td style="padding: 30px;">
                            <div style="background-color: #f8f9fa; border-left: 4px solid #667eea; padding: 15px 20px; margin-bottom: 20px; border-radius: 4px;">
                                <p style="margin: 0; color: #333333; font-size: 16px; line-height: 1.6;">
                                    %s
                                </p>
                            </div>
                            
                            <table width="100%%" cellpadding="0" cellspacing="0" style="margin-top: 20px;">
                                <tr>
                                    <td style="padding: 10px 0; border-bottom: 1px solid #e9ecef;">
                                        <span style="color: #6c757d; font-size: 14px;">通知时间：</span>
                                        <span style="color: #333333; font-size: 14px; font-weight: 500;">%s</span>
                                    </td>
                                </tr>
                                <tr>
                                    <td style="padding: 10px 0;">
                                        <span style="color: #6c757d; font-size: 14px;">系统名称：</span>
                                        <span style="color: #333333; font-size: 14px; font-weight: 500;">DNS 故障切换监控系统</span>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>
                    
                    <!-- Footer -->
                    <tr>
                        <td style="background-color: #f8f9fa; padding: 20px; border-radius: 0 0 8px 8px; text-align: center;">
                            <p style="margin: 0; color: #6c757d; font-size: 12px;">
                                此邮件由 DNS 故障切换监控系统自动发送，请勿回复
                            </p>
                            <p style="margin: 10px 0 0 0; color: #6c757d; font-size: 12px;">
                                © 2024 DNS Failover Monitor. All rights reserved.
                            </p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>`, subject, body, now)

	headers := []string{
		fmt.Sprintf("From: %s", from),
		fmt.Sprintf("To: %s", strings.Join(to, ",")),
		fmt.Sprintf("Subject: %s", subject),
		"MIME-Version: 1.0",
		"Content-Type: text/html; charset=UTF-8",
		"",
	}
	return strings.Join(headers, "\r\n") + htmlBody + "\r\n"
}
