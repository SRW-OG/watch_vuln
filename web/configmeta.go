package web

type configMeta struct {
	Sections []configSection `json:"sections"`
	Pusher   pusherMeta      `json:"pusher"`
}

type configSection struct {
	Title  string      `json:"title"`
	Fields []fieldMeta `json:"fields"`
}

type fieldMeta struct {
	Key         string   `json:"key"`
	Label       string   `json:"label"`
	Help        string   `json:"help"`
	Type        string   `json:"type"`
	Placeholder string   `json:"placeholder,omitempty"`
	Options     []string `json:"options,omitempty"`
}

type pusherMeta struct {
	Types []pusherTypeMeta `json:"types"`
}

type pusherTypeMeta struct {
	Type   string      `json:"type"`
	Label  string      `json:"label"`
	Fields []fieldMeta `json:"fields"`
}

func defaultConfigMeta() configMeta {
	return configMeta{
		Sections: []configSection{
			{
				Title: "Web",
				Fields: []fieldMeta{
					{
						Key:         "web_listen",
						Label:       "监听地址",
						Type:        "text",
						Help:        "Web 服务监听地址，修改后需要重启进程生效。",
						Placeholder: "127.0.0.1:8080",
					},
					{
						Key:         "web_ui_dir",
						Label:       "前端目录",
						Type:        "text",
						Help:        "前端静态文件目录，保存后可立即生效。",
						Placeholder: "webui",
					},
				},
			},
			{
				Title: "鉴权",
				Fields: []fieldMeta{
					{
						Key:         "admin_username",
						Label:       "管理员用户名",
						Type:        "text",
						Help:        "用于登录 Web UI 的用户名，保存后可立即生效。",
						Placeholder: "admin",
					},
					{
						Key:         "admin_password",
						Label:       "管理员密码",
						Type:        "password",
						Help:        "用于登录 Web UI 的密码。留空或保留 ******** 会保留原值。",
						Placeholder: secretPlaceholder,
					},
					{
						Key:         "admin_password_bcrypt",
						Label:       "密码哈希(bcrypt)",
						Type:        "password",
						Help:        "使用 bcrypt 的密码哈希。配置后将优先使用该字段校验。留空或保留 ******** 会保留原值。",
						Placeholder: secretPlaceholder,
					},
					{
						Key:         "session_secret",
						Label:       "会话签名密钥",
						Type:        "password",
						Help:        "用于签名登录 Cookie。修改后会导致已登录会话失效，需要重新登录。",
						Placeholder: secretPlaceholder,
					},
				},
			},
			{
				Title: "数据源与抓取",
				Fields: []fieldMeta{
					{
						Key:         "db_conn",
						Label:       "数据库连接",
						Type:        "text",
						Help:        "SQLite/MySQL/Postgres 连接串。保存后可自动重连数据库；如包含密码会以 ******** 展示，留空/保留 ******** 会保留原值。",
						Placeholder: "sqlite3://vuln_v3.sqlite3",
					},
					{
						Key:         "sources",
						Label:       "抓取源",
						Type:        "tags",
						Help:        "抓取源列表，逗号分隔（如 avd,chaitin,oscs）。",
						Placeholder: "avd,nox,oscs",
					},
					{
						Key:         "interval",
						Label:       "抓取间隔",
						Type:        "text",
						Help:        "仅影响抓取进程（CLI 模式），Web UI 本身不执行抓取。",
						Placeholder: "30m",
					},
					{
						Key:         "enable_cve_filter",
						Label:       "启用 CVE 过滤",
						Type:        "bool",
						Help:        "仅影响抓取进程（CLI 模式）。",
					},
					{
						Key:         "no_github_search",
						Label:       "禁用 GitHub 搜索",
						Type:        "bool",
						Help:        "仅影响抓取进程（CLI 模式）。",
					},
					{
						Key:         "no_start_message",
						Label:       "禁用启动消息",
						Type:        "bool",
						Help:        "仅影响抓取进程（CLI 模式）。",
					},
					{
						Key:         "no_sleep",
						Label:       "禁用夜间休眠",
						Type:        "bool",
						Help:        "仅影响抓取进程（CLI 模式）。",
					},
					{
						Key:         "diff_mode",
						Label:       "Diff 模式",
						Type:        "bool",
						Help:        "仅影响抓取进程（CLI 模式）。",
					},
					{
						Key:         "white_keywords",
						Label:       "白名单关键词",
						Type:        "tags",
						Help:        "逗号分隔。",
						Placeholder: "",
					},
					{
						Key:         "black_keywords",
						Label:       "黑名单关键词",
						Type:        "tags",
						Help:        "逗号分隔。",
						Placeholder: "",
					},
					{
						Key:         "proxy",
						Label:       "代理",
						Type:        "text",
						Help:        "仅影响抓取进程（CLI 模式）。",
						Placeholder: "",
					},
					{
						Key:         "skip_tls_verify",
						Label:       "跳过 TLS 校验",
						Type:        "bool",
						Help:        "仅影响抓取进程（CLI 模式）。",
					},
					{
						Key:         "test",
						Label:       "测试模式",
						Type:        "bool",
						Help:        "仅影响抓取进程（CLI 模式）。",
					},
				},
			},
		},
		Pusher: pusherMeta{
			Types: []pusherTypeMeta{
				{
					Type:  "dingding",
					Label: "钉钉",
					Fields: []fieldMeta{
						{Key: "access_token", Label: "access_token", Type: "password", Help: "留空或保留 ******** 会保留原值。", Placeholder: secretPlaceholder},
						{Key: "sign_secret", Label: "sign_secret", Type: "password", Help: "留空或保留 ******** 会保留原值。", Placeholder: secretPlaceholder},
					},
				},
				{
					Type:  "lark",
					Label: "飞书",
					Fields: []fieldMeta{
						{Key: "access_token", Label: "access_token", Type: "password", Help: "留空或保留 ******** 会保留原值。", Placeholder: secretPlaceholder},
						{Key: "sign_secret", Label: "sign_secret", Type: "password", Help: "留空或保留 ******** 会保留原值。", Placeholder: secretPlaceholder},
					},
				},
				{
					Type:  "wechatwork",
					Label: "企业微信",
					Fields: []fieldMeta{
						{Key: "key", Label: "key", Type: "password", Help: "留空或保留 ******** 会保留原值。", Placeholder: secretPlaceholder},
					},
				},
				{
					Type:  "lanxin",
					Label: "蓝信",
					Fields: []fieldMeta{
						{Key: "domain", Label: "domain", Type: "text", Help: "", Placeholder: ""},
						{Key: "access_token", Label: "access_token", Type: "password", Help: "留空或保留 ******** 会保留原值。", Placeholder: secretPlaceholder},
						{Key: "sign_secret", Label: "sign_secret", Type: "password", Help: "留空或保留 ******** 会保留原值。", Placeholder: secretPlaceholder},
					},
				},
				{
					Type:  "bark",
					Label: "Bark",
					Fields: []fieldMeta{
						{Key: "url", Label: "url", Type: "password", Help: "留空或保留 ******** 会保留原值。", Placeholder: secretPlaceholder},
					},
				},
				{
					Type:  "serverchan",
					Label: "Server 酱",
					Fields: []fieldMeta{
						{Key: "key", Label: "key", Type: "password", Help: "留空或保留 ******** 会保留原值。", Placeholder: secretPlaceholder},
					},
				},
				{
					Type:  "pushplus",
					Label: "PushPlus",
					Fields: []fieldMeta{
						{Key: "token", Label: "token", Type: "password", Help: "留空或保留 ******** 会保留原值。", Placeholder: secretPlaceholder},
					},
				},
				{
					Type:  "telegram",
					Label: "Telegram",
					Fields: []fieldMeta{
						{Key: "bot_token", Label: "bot_token", Type: "password", Help: "留空或保留 ******** 会保留原值。", Placeholder: secretPlaceholder},
						{Key: "chat_ids", Label: "chat_ids", Type: "password", Help: "留空或保留 ******** 会保留原值。", Placeholder: secretPlaceholder},
					},
				},
				{
					Type:  "slack",
					Label: "Slack",
					Fields: []fieldMeta{
						{Key: "webhook_url", Label: "webhook_url", Type: "password", Help: "留空或保留 ******** 会保留原值。", Placeholder: secretPlaceholder},
						{Key: "channel", Label: "channel", Type: "text", Help: "可选：指定频道。", Placeholder: "#security-alerts"},
					},
				},
				{
					Type:  "webhook",
					Label: "Webhook",
					Fields: []fieldMeta{
						{Key: "url", Label: "url", Type: "password", Help: "留空或保留 ******** 会保留原值。", Placeholder: secretPlaceholder},
					},
				},
			},
		},
	}
}

