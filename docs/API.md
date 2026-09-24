# Registry UI API 文档

本文档描述 Registry UI 后端提供的全部 HTTP 接口，供前端、自动化脚本和 CI/CD 对接使用。

- 所有 `/api/*` 接口默认返回 `application/json; charset=utf-8`。
- Docker Registry API 通过 `/v2/*` 反向代理透传，遵循 OCI Distribution 规范。
- 除特别说明外，时间字段为 RFC3339（UTC）格式。

---

## 1. 认证与安全

服务通过 `AUTH_MODE` 环境变量决定是否启用认证：

| AUTH_MODE | 说明 |
|-----------|------|
| `off`（默认） | 不鉴权，所有接口公开（仅用于本地开发） |
| `basic` | 启用认证（Cookie 会话 / Basic / API Token 三种方式） |

启用认证后，支持以下三种认证方式：

### 1.1 Cookie 会话（浏览器 UI）

1. `POST /api/login` 提交用户名密码，成功后服务下发两个 Cookie：
   - `registry_ui_session`：`HttpOnly`、`SameSite=Lax`，有效期 7 天。
   - `csrf_token`：非 HttpOnly（供前端 JS 读取），`SameSite=Lax`。
2. 两个 Cookie 的 `Secure` 标志**按协议自适应**：仅在 HTTPS（直连 TLS 或反代设置 `X-Forwarded-Proto: https`）时设置 `Secure`，因此默认 HTTP 部署也能登录。**生产环境务必启用 HTTPS。**
3. 会话存储在服务进程内存中（单实例设计，重启即登出，不支持多副本水平扩展），7 天过期并有后台清理。
4. 后续请求自动携带会话 Cookie。
5. **首次启动的默认管理员 `admin/change-me` 被标记 `mustChangePassword`，在修改密码前调用除 `/api/user`、`/api/me`、`/api/user/password`、`/api/logout` 外的接口会返回 `403`。**

### 1.2 CSRF 防护

所有**非 GET/HEAD/OPTIONS** 请求必须在请求头携带 CSRF Token：

```
X-CSRF-Token: <csrf_token cookie 的值>
```

例外（无需 CSRF）：`/api/login`、`/v2/*`，以及携带 `Authorization: Bearer <token>` 的请求
（Bearer Token 不是浏览器自动携带的凭证，跨站请求无法附加该头，因此不存在 CSRF 风险）。

校验失败返回 `403`：

```json
{ "error": "CSRF token validation failed, please refresh the page" }
```

### 1.3 Basic Auth（API 客户端 / Docker CLI）

在 `Authorization` 头携带标准 Basic 凭证：

```
Authorization: Basic base64(username:password)
```

> 密码统一以 bcrypt 存储；历史 SHA256 哈希会在用户成功登录（含 Basic Auth）时自动升级为 bcrypt。Basic Auth 命中 `/v2/*` 时不会创建会话（避免 Docker CLI 高频请求把会话写入内存）。

### 1.4 Bearer API Token（推荐用于自动化）

通过「管理 → API Token」创建 Token（见 §9），在请求头携带：

```
Authorization: Bearer ru_<prefix>_<hex>
```

- Token 格式固定为 `ru_<prefix>_<hex>`，仅在创建时返回一次完整值。
- 适用于全部 `/api/*` 接口（不适用于 `/v2/*` 代理，后者由 `V2_AUTH_MODE` 决定），且无需 CSRF Token。
- Token 过期后自动失效；所属用户被停用后 Token 立即失效。

---

## 2. 通用约定

### 错误响应

```json
{ "error": "Bad Request", "details": "具体错误信息" }
```

### 常见状态码

| 状态码 | 含义 |
|--------|------|
| 200 | 成功 |
| 201 | 创建成功 |
| 202 | 已接受（异步处理，如删除 manifest） |
| 400 | 请求参数错误 |
| 401 | 未认证 |
| 403 | 无权限 / CSRF 校验失败 |
| 404 | 资源不存在 |
| 405 | 方法不允许 |
| 500 | 服务内部错误 |
| 502 | 上游 Registry 不可达 |

### 权限说明

- **公开**：无需认证（`AUTH_MODE=off` 时全部公开）。
- **登录**：任意已登录用户。
- **管理员**：仅 `isAdmin=true` 用户。
- **读**：对该仓库所属命名空间有 `canRead` 权限（管理员不限）。
- **写**：对该仓库所属命名空间有 `canWrite` 权限（管理员不限）。
- 非管理员用户仅能访问与其命名空间权限（前缀匹配）相符的仓库。
- 所有**修改类**接口（`POST`/`PUT`/`PATCH`/`DELETE`）在 `/api/repositories/{repo}/*` 下都要求**写**权限，
  包括 Tag 策略、批量删除、retention 清理、`init`、仓库描述；命名空间增删、导出、全局统计要求**管理员**。
  回收站 restore/删除记录要求**写**权限。

---

## 3. 认证与会话

### POST /api/login

登录，创建会话。**无需 CSRF。**

请求体：

```json
{ "username": "admin", "password": "change-me" }
```

响应 `200`：

```json
{ "username": "admin", "isAdmin": true, "mustChangePassword": true }
```

失败返回 `401 {"error":"invalid credentials"}`。

### POST /api/logout

清除会话并删除会话 Cookie，返回 `200 {"loggedOut": true}`。**需 CSRF**（已从旧的 GET 改为 POST，避免跨站强制登出）。

### GET /api/me

返回当前登录用户的完整信息（权限：登录）。

```json
{ "id": 6, "username": "admin", "isAdmin": true, "enabled": true, "mustChangePassword": true }
```

### GET /api/my-permissions

返回当前用户的命名空间权限数组；管理员返回空数组（拥有全部权限）。

```json
[ { "id": 1, "userId": 8, "namespacePattern": "library", "canRead": true, "canWrite": false } ]
```

---

## 4. 用户自助

### GET /api/user

返回当前用户信息（含头像、authMode）。

```json
{
  "id": 6,
  "username": "admin",
  "avatar": "/uploads/avatar-default-xxxx.svg",
  "authMode": "basic",
  "isAdmin": true,
  "mustChangePassword": true
}
```

### PUT /api/user

更新头像。请求体 `{ "avatar": "<url 或 data uri>" }`。

### POST /api/user/password

修改当前用户密码。

```json
{ "oldPassword": "...", "newPassword": "..." }
```

- 新密码至少 6 位，否则 `400`。
- 旧密码错误返回 `403`。
- 成功后清除 `mustChangePassword` 标记。

---

## 5. 命名空间

### GET /api/namespaces

列出命名空间。

### POST /api/namespaces

创建命名空间。权限：**管理员**。请求体 `{ "name": "library" }`。

### DELETE /api/namespaces/{name}

删除命名空间及其下的仓库与镜像记录（同一事务内）。权限：**管理员**。

---

## 6. 仓库 / Tag / Manifest

### GET /api/repositories

列出仓库目录。支持分页查询参数 `n`（数量）、`last`（游标）。非管理员仅返回有读权限的仓库。

```json
{ "repositories": ["library/nginx", "library/redis"] }
```

### GET /api/repositories/{repo}/tags

列出仓库下所有 tag，并同步到本地 images 表。

### GET /api/repositories/{repo}/manifests/{ref}

获取 manifest 详情（`ref` 可为 tag 或 digest），含 config、artifactType 等解析信息。

### HEAD /api/repositories/{repo}/manifests/{ref}

仅返回 `Docker-Content-Digest` 与 `Content-Type` 头。

### DELETE /api/repositories/{repo}/manifests/{ref}

删除 manifest。删除前自动快照到回收站（`pending_gc`，GC 前可恢复），并触发 `delete` webhook 事件。返回 `202`：

```json
{ "deleted": true, "name": "library/nginx", "digest": "sha256:...", "snapshotCount": 1, "gcRequired": true, "message": "..." }
```

### POST /api/repositories/{repo}/manifests/batch-delete

按**标签语义**批量删除标签。请求体 `{ "tags": ["v1", "v1.0", ...] }`。

由于 Registry V2 API 只能按 digest 删除（会抹掉指向该 digest 的所有标签），本端点按 digest 分组处理：

- **取消标签（untag）**：当某 digest 仍有未被选中的标签时，先删除该 manifest，再把保留的标签重新 PUT 回去（GC 前 blob 仍在，等价于仅移除标签指针）。不进回收站，触发 `untag` webhook 事件。
- **删除镜像（delete）**：当某 digest 的最后一个标签被删除时，先快照到回收站再真正删除该 digest，GC 后释放磁盘。触发 `delete` webhook 事件。

响应：

```json
{ "results": [ { "tag": "v1", "action": "untag", "ok": true } ], "snapshotCount": 1 }
```

`action` 为 `untag` 或 `delete`。

> 单标签删除 `DELETE /api/repositories/{repo}/manifests/{ref}`：当 `ref` 为标签时同样走上述标签语义；当 `ref` 为 digest（`sha256:...`）时按显式整体删除处理。

### POST /api/repositories/{repo}/init

用最小 manifest 初始化一个空仓库。

### GET /api/repositories/{repo}/stats

返回该仓库的拉取/推送统计。

### GET|PUT /api/repositories/{repo}/tag-policy

读取 / 设置该仓库的 Tag 保护策略。GET 权限：**读**；PUT 权限：**写**。

### GET /api/repositories/{repo}/retention-preview

预览基于保留**镜像**数量的清理候选。`keepCount` 按 digest 分组计数（同 digest 的多标签计为 1 个镜像），保留最近 N 个镜像，清理更旧的镜像的全部标签。

响应：

```json
{ "keepCount": 5, "totalImages": 12, "candidates": [
  { "digest": "sha256:abc...", "tags": ["v1","v1.0","latest"], "createdAt": "2026-06-01T00:00:00Z" }
]}
```

### POST /api/repositories/{repo}/retention-run

执行保留清理。按 digest 分组，清理超出保留数量的镜像（同 digest 的全部标签一并清理，最后一个标签时 digest 进入回收站）。

### GET|PUT /api/repo-description/{repo}

读取 / 更新仓库描述（支持 Markdown）。GET 权限：**读**；PUT 权限：**写**。

---

## 7. 收藏 / 最近 / 审计 / 回收站

### GET /api/favorites

列出收藏镜像。

### POST /api/favorites / DELETE /api/favorites/{id}

添加 / 取消收藏与备注。

### GET /api/recent

返回当前用户最近访问记录（按用户隔离，上限约 20 条）。

### GET /api/audit

返回操作审计日志（按 `created_at` 倒序）。

### GET /api/recycle

列出回收站记录。

### POST /api/recycle/{id}/restore

恢复回收站记录（将快照的 manifest 重新 PUT 回 repo/tag），触发 `restore` webhook 事件。仅 `pending_gc` 状态可恢复，否则返回 `409`。权限：对该 repo 有**写**权限（管理员不限）；无权限返回 `403`。

### DELETE /api/recycle/{id}

删除单条回收站记录（丢弃最后一份可恢复的快照）。权限：对该 repo 有**写**权限（管理员不限）；无权限返回 `403`。

---

## 8. 设置 / 系统 / 上传

### GET|PUT /api/settings

读取 / 更新 UI 与系统设置（键值白名单，如 `theme`、`language`、`pageSize`、`recycleGCDays`、`allow_anonymous_pull` 等）。GET 权限：登录；**PUT 权限：管理员**。PUT 写入非白名单键返回 `400`。

### GET /api/health

健康检查与统计概览。

```json
{
  "ok": true,
  "registryStatus": 200,
  "dockerDistributionApiVersion": "registry/2.0",
  "repoCount": 9,
  "tagCount": 17,
  "body": "{}"
}
```

### GET /api/disk-usage

返回数据库、上传目录、Registry 存储的磁盘占用。

### POST /api/gc/run

手动触发垃圾回收。权限：**管理员**。回收站元数据清理 + 调用 `registry garbage-collect` 回收未引用 blob。

- 默认只清理回收站中**已超过 `recycleGCDays` 保留天数**的记录（与自动 GC 一致）；`recycleGCDays=0`（禁用）时不做任何事并返回 `skipped`。
- 若要清空整个回收站（忽略保留天数，不可恢复），显式传 `?all=true` 或 JSON body `{"all":true}`。
- GC 在后台上下文（带超时）中执行，客户端断开不会中断；期间所有 push 请求返回 `503`（pull 不受影响）。
- 同一时刻只允许一个 GC 运行，重复触发返回 `409`。

```json
{
  "deletedCount": 3,
  "blobDeleted": 12,
  "freedBytes": 104857600,
  "blobError": "registry garbage-collect failed: ..."
}
```

`blobError` 非空表示元数据已清理但存储未回收（例如 registry 二进制/配置不可用、或 config 的 `rootdirectory` 与 `REGISTRY_DATA_DIR` 不一致），前端应明确提示而不是显示成功。`freedBytes` 由 GC 前后目录大小差值计算。

### GET /api/gc/status

返回 `{ "running": true|false }`，供前端轮询 GC 进度，避免长时间挂在一个请求上。

### POST /api/uploads/logo / POST /api/uploads/avatar

上传 Logo / 头像（`multipart/form-data`）。

### GET /api/export?format=json|csv

导出全部仓库 tag 清单（含 digest、content-type、size）。权限：**管理员**（会遍历整个 catalog，不按用户命名空间权限过滤）。

### GET /api/repo-stats

返回所有仓库的拉取/推送统计列表。权限：**管理员**。

---

## 9. API Token（管理）

Token 按用户隔离：每个登录用户管理自己的 Token；删除时**所属用户本人或任意管理员**均可删除。

### GET /api/admin/tokens

列出当前用户的 Token（权限：登录）。`tokenHash` 永不返回。

```json
{
  "tokens": [
    {
      "id": 1,
      "userId": 6,
      "name": "ci-deploy",
      "tokenPrefix": "a1b2c3d4e5f6",
      "description": "",
      "expiresAt": "2026-12-31T00:00:00Z",
      "lastUsedAt": "2026-06-24T08:00:00Z",
      "createdAt": "2026-06-01T00:00:00Z"
    }
  ]
}
```

### POST /api/admin/tokens

创建 Token（权限：登录）。

请求体：

```json
{ "name": "ci-deploy", "description": "可选", "expiresIn": 0 }
```

- `name`：必填。
- `expiresIn`：有效期小时数，`0` 表示永不过期。

响应 `201`（**`fullToken` 仅此一次返回，请立即保存**）：

```json
{
  "token": {
    "id": 1,
    "userId": 6,
    "name": "ci-deploy",
    "tokenPrefix": "a1b2c3d4e5f6",
    "createdAt": "2026-06-24T08:00:00Z"
  },
  "fullToken": "ru_a1b2c3d4e5f6_<64位hex>"
}
```

### DELETE /api/admin/tokens/{id}

删除 Token。权限：**所属用户本人或任意管理员**；越权返回 `403`，不存在返回 `404`。删除会记录审计 `token.delete`。

### 使用示例

```bash
# 创建（需先登录拿到 CSRF）
curl -b cookies.txt -H "X-CSRF-Token: $CSRF" \
  -X POST http://localhost:8080/api/admin/tokens \
  -H 'Content-Type: application/json' \
  -d '{"name":"ci-deploy","expiresIn":0}'

# 使用 Bearer Token 调用任意 API
curl -H "Authorization: Bearer ru_a1b2c3d4e5f6_<hex>" \
  http://localhost:8080/api/repositories
```

---

## 10. Webhook（管理）

Webhook 在发生 `push` / `delete` / `restore` 事件时，异步向配置的 URL 发送 POST 回调。全部接口仅**管理员**可访问。

### 触发时机

| 事件 | 触发点 |
|------|--------|
| `push` | 成功 PUT manifest（推送镜像） |
| `delete` | 删除某 digest 的最后一个标签，digest 被真正删除 |
| `untag` | 移除标签但 digest 仍有其他标签保留（重新 PUT 存活标签） |
| `restore` | 从回收站恢复 |

### 回调请求

- 方法：`POST`，`Content-Type: application/json`。
- 客户端超时：10 秒；失败仅记录日志，不重试。
- 若配置了 `secretHeader`（格式 `Key:Value`），会作为自定义请求头注入，用于接收端校验。

回调 Payload：

```json
{
  "event": "push",
  "repo": "library/nginx",
  "ref": "v1.0",
  "digest": "sha256:...",
  "time": "2026-06-24T08:00:00Z"
}
```

### GET /api/admin/webhooks

列出所有 Webhook。

```json
{
  "webhooks": [
    {
      "id": 1,
      "url": "https://example.com/hook",
      "secretHeader": "X-Hub-Signature:secret",
      "events": "push,delete,untag,restore",
      "enabled": true,
      "createdAt": "2026-06-24T08:00:00Z"
    }
  ]
}
```

### POST /api/admin/webhooks

创建 Webhook。

```json
{
  "url": "https://example.com/hook",
  "secretHeader": "X-Hub-Signature:secret",
  "events": "push,delete,untag,restore",
  "enabled": true
}
```

- `url`：必填。**经 SSRF 校验**：必须为 http/https，且默认拒绝解析到 loopback/内网/链路本地地址的目标（可用 `ALLOW_WEBHOOK_PRIVATE_IP=true` 放开）。投递时会再次校验，拦截历史脏数据。
- `events`：逗号分隔；为空时默认 `push,delete,untag,restore`。事件采用**精确分割匹配**（不会出现子串误匹配）。
- 响应 `201` 返回创建的 Webhook 对象。

### PUT /api/admin/webhooks/{id}

更新 Webhook（字段同 POST）。

### DELETE /api/admin/webhooks/{id}

删除 Webhook。

---

## 11. 管理 - 用户与权限

全部仅**管理员**可访问。

### GET /api/admin/users

列出全部用户。

### POST /api/admin/users

创建用户。请求体 `{ "username", "password", "isAdmin" }`。

### GET|PUT|DELETE /api/admin/users/{id}

查询 / 更新 / 删除指定用户。删除时禁止删除自己、禁止删除最后一个管理员。

### POST /api/admin/users/{id}/disable

停用用户（停用后无法登录，已有会话与 Token 下次请求即失效）。禁止停用自己或最后一个启用的管理员。

### POST /api/admin/users/{id}/enable

启用用户。

### GET /api/admin/users/{id}/permissions

列出该用户的命名空间权限。

### POST /api/admin/users/{id}/permissions

新增 / 更新权限（幂等 upsert，按 `namespace_pattern` 去重）。

```json
{ "patterns": ["library", "team-a"], "canRead": true, "canWrite": false }
```

- `canWrite=true` 隐含 `canRead=true`。
- 同一命名空间重复提交会更新而非新增。

### DELETE /api/admin/users/{id}/permissions

按命名空间删除权限。请求体 `{ "namespacePattern": "library" }`。

### PUT|DELETE /api/admin/users/{id}/permissions/{permId}

按权限 id 更新 / 删除单条权限。

---

## 12. 管理 - 不可变 Tag 规则

仅**管理员**可访问。

### GET /api/admin/immutable-rules

列出不可变 Tag 规则。

### POST /api/admin/immutable-rules

新增规则。请求体 `{ "pattern": "release-*", "description": "..." }`（支持 `*` `?` 通配符）。

### PUT|DELETE /api/admin/immutable-rules/{id}

更新 / 删除规则。

---

## 13. Docker Registry 代理（/v2/*）

`/v2/*` 通过反向代理透传到配置的上游 Registry，遵循 OCI Distribution 规范，供 `docker pull/push` 使用。

代理鉴权由 `V2_AUTH_MODE` 决定：

| V2_AUTH_MODE | 行为 |
|--------------|------|
| `registry`（默认） | 透传，由上游 Registry 自行鉴权 |
| `ui` / `basic` / `same` | 由本服务做 UI 认证 + 命名空间授权；可对开启匿名拉取的仓库放行 GET/HEAD manifest、blobs |
| `proxy` / `off` | 不干预，交由上游处理 |

- **未携带凭证**访问 `/v2/`、`/v2`（ping）返回 `401` 并带
  `WWW-Authenticate: Basic realm="Registry UI"`（符合 OCI 规范与 Docker CLI 预期）。
  这个 challenge 是必须的：Docker 客户端据此得知本仓库使用 Basic 认证，
  `docker login` 也据此真正校验密码——否则密码错误也会显示 `Login Succeeded`。
- **只要请求带了 `Authorization`，凭证一律校验**；无效则返回 `401`，不会静默忽略。
  这样"凭证过期/写错"会在 `docker login` 或 `docker pull` 时明确报错，而不是只在
  关闭匿名拉取的命名空间上以 `unauthorized` 的形式暴露。
- **匿名拉取**：请求未携带凭证时，对 `anonymous_pull` 已开启的仓库，
  `GET/HEAD .../manifests/...` 与 `.../blobs/...` 直接透传，`docker pull` 无需登录。
  `/v2/` ping 返回 `401` 不影响匿名拉取（匿名授权按仓库在内容接口上判定）。
- 非管理员访问无权限仓库返回 `403`。
- 客户端曾用错误密码登录导致凭证被缓存时，先 `docker logout <registry>` 再重新登录。
