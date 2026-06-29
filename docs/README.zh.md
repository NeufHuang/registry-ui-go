# Registry UI

轻量级 Docker Distribution / OCI Registry 镜像管理界面，Harbor 的极简替代方案，资源占用极低。

- 单静态二进制，内嵌 Web UI
- SQLite 持久化（无需外部数据库）
- Web UI 与 Docker CLI 共用同一端口
- Registry V2 API 反向代理
- Tag 策略、保留策略、回收站、审计日志、RBAC

[English](../README.md) | [API 文档](API.md)

## 特性

- **轻量**：纯 Go 单二进制，无 Node.js/Nginx/Caddy 运行时依赖
- **统一入口**：Web 界面与 Docker CLI 共用同一 host:port
- **SQLite 存储**：纯 Go 驱动（`modernc.org/sqlite`），无需 CGO
- **Tag 策略**：保护模式（允许覆盖/不可变/规则匹配）、覆盖动作（回收/保留）、保留数量
- **回收站**：删除前快照 manifest，GC 前可恢复
- **垃圾回收**：手动/自动 GC，GC 期间自动拦截 push
- **RBAC**：基于命名空间的非管理员权限控制
- **审计日志**：记录 pull/push/delete/login/用户管理 等操作
- **不可变 Tag 规则**：Glob 通配符防止生产 tag 被覆盖
- **Webhook**：push/delete/untag/restore 事件通知
- **API Token**：Bearer Token 认证供 API 客户端使用
- **国际化**：中英文界面
- **HTTPS**：在 UI 中管理 —— 开启开关、上传证书与私钥、重启生效
- **OCI Artifacts**：支持 Helm Chart、SBOM 等非 Docker 镜像的 OCI 制品

## 快速开始

### Docker Compose（推荐）

UI 与 Registry 分容器运行，隔离更清晰：

```bash
docker compose up -d --build
```

访问：http://localhost:8080

默认账号：`admin` / `change-me`（首次登录必须修改密码）

### All-in-One 单容器

UI 与 Registry 在同一容器，适合小型部署：

```bash
docker compose -f docker-compose.aio.yml up -d --build
```

### Docker Run（连接已有 Registry）

```bash
docker build -t registry-ui .
docker run -d -p 8080:8080 \
  -e REGISTRY_URL=http://your-registry:5000 \
  -e AUTH_MODE=basic \
  -e V2_AUTH_MODE=ui \
  -v ./data:/data \
  registry-ui
```

### 本地开发

```bash
cp .env.example .env
# 编辑 REGISTRY_URL 等配置
export $(grep -v '^#' .env | xargs)
go run ./backend/cmd/registry-ui
```

## 配置

所有配置通过环境变量：

| 变量 | 默认值 | 说明 |
|---|---|---|
| `SERVER_ADDR` | `:8080` | 服务监听地址 |
| `AUTH_MODE` | `off` | `off` 或 `basic`（开启登录） |
| `V2_AUTH_MODE` | `registry` | `/v2/` 认证：`ui`/`registry`/`off` |
| `REGISTRY_URL` | - | Registry 地址，如 `http://registry:5000` |
| `REGISTRY_USERNAME` | - | Registry Basic Auth 用户名 |
| `REGISTRY_PASSWORD` | - | Registry Basic Auth 密码 |
| `REGISTRY_TLS_SKIP_VERIFY` | `false` | 跳过 Registry TLS 校验 |
| `ENABLE_DELETE` | `true` | 允许删除 manifest |
| `ALLOW_WEBHOOK_PRIVATE_IP` | `false` | 允许 Webhook 指向内网 IP |
| `DATA_DIR` | `./data` | 持久化数据根目录 |

### 数据目录结构

```
data/
├── db/registry-ui.db    # SQLite：设置、用户、审计、回收站
├── certs/               # TLS 证书
├── uploads/             # Logo、头像
└── registry/            # Registry 存储（AIO/双容器模式）
```

## 使用说明

### Docker CLI

```bash
docker login localhost:8080
docker pull localhost:8080/library/nginx:latest
docker push localhost:8080/library/nginx:latest
```

### Helm Charts（OCI）

```bash
# 登录（与 docker login 共用账号）
helm registry login localhost:8080 --username admin --password change-me --insecure

# 打包并推送
helm create mychart
helm package mychart/
helm push mychart-0.1.0.tgz oci://localhost:8080/library --plain-http

# 拉取
helm pull oci://localhost:8080/library/mychart --version 0.1.0
```

> **注意**：HTTP registry 推送 Helm chart 时需要加 `--plain-http` 标志（Helm 3.13+）。

### Web 界面

- **仓库**：按命名空间浏览、搜索、多选
- **Tag**：查看 tag 列表、manifest 详情、多架构信息、配置
- **Pull 命令**：根据制品类型自动显示 `docker pull`（镜像）或 `helm pull`（Helm Chart）
- **Tag 策略**：单仓库设置保护模式、覆盖动作、保留数量、匿名拉取
- **保留策略**：按镜像个数预览并清理旧镜像（按 digest 分组）
- **回收站**：GC 前恢复已删除的 tag
- **设置**：主题、语言、分页大小、GC 天数、全局策略
- **管理**：用户管理、权限、不可变规则、Webhook、API Token

### Tag 保护模式

| 模式 | 行为 |
|---|---|
| `overwrite`（允许覆盖） | 允许 push 覆盖已有 tag |
| `immutable`（不可变） | 所有 tag 禁止覆盖 |
| `rules`（规则匹配，默认） | 仅匹配不可变规则的 tag 受保护 |

### 覆盖动作

保护模式为"允许覆盖"时：

| 动作 | 行为 |
|---|---|
| `recycle`（回收，默认） | 旧 manifest 进入回收站后再覆盖 |
| `keep`（保留） | 保留旧 manifest 为无 tag 镜像 |

## 安全说明

- **协议自适应安全 Cookie**：仅检测到 HTTPS 时才标记 `Secure`
- **CSRF 防护**：所有非 GET/HEAD 的 API 请求需携带 CSRF Token
- **密码哈希**：bcrypt，支持从旧版 SHA256 自动升级
- **会话管理**：7 天过期，后台自动清理
- **SSRF 防护**：默认禁止 Webhook 指向回环/内网地址
- **安全响应头**：CSP、HSTS（HTTPS）、nosniff、frame deny
- **命名空间 RBAC**：非管理员仅可见授权仓库

### HTTPS / TLS

TLS 完全在 **设置 → HTTPS / TLS**（仅管理员）中管理：

1. 打开 **启用 HTTPS** 开关。
2. 点击 **上传证书**，以 PEM 格式粘贴（或选择文件）证书与私钥。系统会校验配对，
   存到 `CERT_DIR`（`cert.pem` `0644`、`key.pem` `0600`），私钥绝不经 HTTP 暴露，
   TLS 强制 1.2 及以上。
3. **重启服务** 后生效（单端口无法在 HTTP↔HTTPS 间热切换）。

自签名证书需让 Docker 客户端信任（无需改 `daemon.json`，仅对该 registry 生效）：

```bash
sudo mkdir -p /etc/docker/certs.d/<host>:<port>
sudo cp cert.pem /etc/docker/certs.d/<host>:<port>/ca.crt
```

或在 `daemon.json` 的 `insecure-registries` 加入该地址（跳过校验，安全等级等同明文）后重启 Docker。

#### UI↔registry 内部链路仍走 HTTP（无需担心）

双容器 Compose 部署下，`registry` 服务**不映射任何端口**，UI 通过 Docker 内部网络
的 `http://registry:5000` 访问它。开启 HTTPS 时只有对外的 UI 端口（`8080`）被加密，
UI↔registry 这一跳始终停留在 Docker 桥接网络内，明文 HTTP 是预期行为，也与官方
"registry 置于反向代理之后"的做法一致。

> **不要**给 `registry` 服务加 `ports: 5000:5000`。那会在宿主机上暴露一个无鉴权、
> 明文的 registry，绕过 UI 的认证。只有当 UI 与 registry 跨**不同主机**、经不可信
> 网络通信时，才需要给内部链路加 TLS。

#### 置于外部反向代理之后（Nginx）

在 UI 中**关闭** HTTPS（让其只跑明文 HTTP），由 Nginx 终止 TLS。将 UI 绑定到回环
地址，使其仅可被反代访问：

```yaml
# docker-compose.yml
ports:
  - "127.0.0.1:8080:8080"
```

```nginx
server {
    listen 443 ssl http2;
    server_name registry.example.com;

    ssl_certificate     /etc/nginx/certs/fullchain.pem;
    ssl_certificate_key /etc/nginx/certs/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;

    client_max_body_size 0;   # 允许推送大镜像层

    location / {
        proxy_pass http://127.0.0.1:8080;

        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;   # Secure cookie 必需

        proxy_request_buffering off;   # 流式传输大层
        proxy_buffering         off;
        proxy_read_timeout      900s;
    }
}

server {
    listen 80;
    server_name registry.example.com;
    return 301 https://$host$request_uri;
}
```

`X-Forwarded-Proto` **必须设置**：TLS 在 Nginx 终止，UI 只看到明文 HTTP，要靠此头
才会给会话 Cookie 打上 `Secure` 标志。`client_max_body_size 0` 与关闭缓冲可避免大
镜像层推送时出现 `413`/超时。

## 开发

```bash
# 构建
go build -o bin/registry-ui ./backend/cmd/registry-ui

# 测试
go test ./...

# 构建 Alpine 静态二进制
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o bin/registry-ui ./backend/cmd/registry-ui
```

## 许可证

Apache 2.0 - 详见 [LICENSE](../LICENSE)
