# ssh-ca — 内部 SSH 证书 CA 服务

用 OpenSSH 证书替换"分发公钥到各服务器"的模式：运维离职只用在 CA 吊销证书，各服务器拉取 KRL 即生效。

- 自己实现 OpenSSH 证书线格式（`PROTOCOL.certkeys`），签发的证书可被 `ssh-keygen -L` 解析、被真实 sshd 接受
- 用户证书 + 主机证书；principals、有效期、force-command、source-address、permit-* 扩展
- 签名 CA：ed25519（默认）和 ecdsa nistp256；被签公钥支持 ssh-ed25519 / ecdsa-sha2-nistp{256,384,521} / ssh-rsa
- 签发走审批流（requester 提交 → admin 批准才签）
- 吊销生成 KRL（`PROTOCOL.krl`，与 `ssh-keygen -k` 输出同格式），服务器定时拉取即可
- 审计日志：谁申请、谁批准、谁下载了哪台机器的证书、谁吊销、谁拉了 KRL
- 零运行时依赖，纯 Node ≥ 20 + TypeScript

## 快速开始

```bash
npm install
npm run build
node dist/server.js --data ./data --port 8443
```

首次启动自动生成两把 CA 私钥（`data/ca/ed25519.pem`、`nistp256.pem`，0600）和
`data/config.json`（内含 admin / requester 两个随机 token，启动时也会打印到 stdout）。

管理页面：http://127.0.0.1:8443/ （粘贴 token 即可用）

## 流程

```bash
# 1. 运维提交申请（requester token）
curl -X POST -H "Authorization: Bearer $REQ_TOKEN" -H 'content-type: application/json' \
  -d '{
    "type": "user",
    "publicKey": "ssh-ed25519 AAAA... alice@laptop",
    "principals": ["alice", "ops"],
    "validBefore": 1735689600,
    "criticalOptions": {"forceCommand": "/usr/bin/rrsync /backup",
                        "sourceAddress": ["10.0.0.0/8"]},
    "extensions": ["permit-pty", "permit-agent-forwarding"],
    "comment": "ticket-1234"
  }' http://127.0.0.1:8443/api/requests

# 2. 管理员审批（admin token）→ 返回签发好的证书
curl -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
  http://127.0.0.1:8443/api/requests/<id>/approve

# 3. 下载证书（放到 ~/.ssh/id_ed25519-cert.pub 即可直接用）
curl -H "Authorization: Bearer $REQ_TOKEN" \
  http://127.0.0.1:8443/api/certs/<serial>/cert.pub

# 4. 吊销 + 拉 KRL
curl -X POST -H "Authorization: Bearer $ADMIN_TOKEN" -d '{"reason":"left"}' \
  -H 'content-type: application/json' http://127.0.0.1:8443/api/certs/<serial>/revoke
curl -H "Authorization: Bearer $REQ_TOKEN" http://127.0.0.1:8443/api/krl -o revoked.krl
```

## 服务器侧配置

```sshd_config
TrustedUserCAKeys /etc/ssh/ca_user.pub   # GET /api/ca 里的 ed25519 公钥
HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub
RevokedKeys /etc/ssh/revoked.krl
```

KRL 定时同步（crontab）：

```
*/5 * * * * curl -sf -H "Authorization: Bearer <token>" http://ca:8443/api/krl -o /etc/ssh/revoked.krl.tmp && mv /etc/ssh/revoked.krl.tmp /etc/ssh/revoked.krl
```

## API 一览

| 方法 | 路径 | 角色 | 说明 |
|---|---|---|---|
| GET | `/api/ca` | 任意 | CA 公钥与指纹 |
| POST | `/api/requests` | 任意 | 提交签发申请 |
| GET | `/api/requests?status=pending` | 任意 | 申请列表 |
| POST | `/api/requests/:id/approve` | admin | 批准并签发 |
| POST | `/api/requests/:id/reject` | admin | 拒绝 |
| GET | `/api/certs` | 任意 | 已签发证书列表 |
| GET | `/api/certs/:serial/cert.pub` | 任意 | 下载证书（记审计） |
| POST | `/api/certs/:serial/revoke` | admin | 吊销 |
| GET | `/api/krl` | 任意 | 下载 KRL（记审计） |
| GET | `/api/audit` | admin | 审计日志 |

角色在 `data/config.json` 的 `tokens` 里配置（`admin` / `requester`）。

## 验收

```bash
npm run acceptance   # bash test/acceptance.sh
```

45 项断言：证书被 `ssh-keygen -L` 正确解析（principals / force-command /
source-address / 扩展 / 有效期 / 签名 CA）、KRL 被 `ssh-keygen -Q` 正确判定、
审批与权限边界、审计完整性，以及端到端——用真实 `/usr/sbin/sshd` 验证
证书登录、force-command 强制执行、吊销后 KRL 拒绝登录。

## 目录结构

```
src/wire.ts    SSH 线格式编解码（string/mpint/uint64）
src/keys.ts    公钥解析、CA 密钥生成/加载、SSH 签名（ed25519 + ecdsa DER→mpint）
src/cert.ts    证书构造（PROTOCOL.certkeys）
src/krl.ts     KRL 生成（与 openssh krl.c 对齐：format v1、证书节头部、签名节）
src/store.ts   JSON 持久化：申请/证书/吊销/审计 + 配置
src/server.ts  HTTP API + 路由 + 认证
src/ui.ts      管理页面（单页）
test/acceptance.sh  验收脚本
```
