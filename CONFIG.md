# 配置文件

Watchvuln 从 `v2.0.0` 版本开始支持从文件加载配置, 使用时需要使用 `-c` 参数指定配置文件路径, 如:

```
./watchvuln -c /path/to/config.yaml
./watchvuln -c /path/to/config.json
```

同时为了简化开发和减低理解成本，我们约定，**如果指定了配置文件，那么命令行指定的任何参数将不再生效**

## 文件格式

支持 `yaml` 和 `json` 两种格式的配置文件，这两个格式本质上是互通的，你可以选择自己喜欢的后缀。
一般，你只需将 `config.example.yaml` 的内容改一下即可，一个最简单的配置大概如下:

```yaml
db_conn: sqlite3://vuln_v3.sqlite3
sources: [ "avd","nox","oscs","threatbook","seebug","struts2","kev" ]
interval: 30m
pusher:
  - type: dingding
    access_token: "xxxx"
    sign_secret: "yyyy"
```

聪明的你一定发现了，配置文件里的字段和命令行参数是一一对应的，这里就不再赘述了。

## Web 前端配置

从该版本开始，项目提供 `web` 子命令用于启动一个同域的 Web UI + API。

```bash
./watchvuln -c /path/to/config.yaml web
./watchvuln -c /path/to/config.json web
```

在配置文件中增加以下字段即可：

```yaml
web_listen: 127.0.0.1:8080
web_ui_dir: webui
admin_username: admin
admin_password: "your-password" # 或使用 admin_password_bcrypt
session_secret: "your-long-random-secret"
```

当使用 `-c` 指定配置文件启动 Web 后，Web UI 的“配置”页会支持读取/保存该配置文件：
- 敏感字段会以 `********` 展示；保存时如果仍为 `********` 或留空，会保留原值，避免误覆盖。
- 配置文件的注释会在保存时丢失（会重新序列化为 yaml/json）。

实际上，配置文件的出现主要是为了解决多推送的问题，比如你有两个钉钉群需要推送，那么可以写成这样

```yaml
db_conn: sqlite3://vuln_v3.sqlite3
sources: [ "avd","nox","oscs","threatbook","seebug","struts2","kev" ]
interval: 30m
pusher:
  - type: dingding
    access_token: "xxxx"
    sign_secret: "yyyy"
   
  - type: dingding
    access_token: "pppp"
    sign_secret: "qqqq"
```
