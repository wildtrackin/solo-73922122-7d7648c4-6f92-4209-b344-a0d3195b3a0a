# systemd 沙箱策略离线核查服务（HTTPS + 证书热更换）

面向 Linux 服务维护人员的**纯离线**工具：给定一个 systemd unit 的沙箱策略 JSON，
以及按时间排列的进程审计事件（派生、切换工作目录、读写/执行绝对或相对路径），
逐步回放并判断守护进程的真实操作会不会被沙箱阻断，输出**首个失败原因、完整判定轨迹
和每一步命中的策略项**，直接指导 unit 修改。

判定引擎（`app/engine.py`）只依赖 Python 标准库；FastAPI 仅用于提供 HTTPS API 与 `/docs`。
服务运行期不发起任何外部网络请求。

本版本在原业务能力之上增加了**单进程 HTTPS 与不中断服务的 TLS 证书热更换**：

- 原 API（`/api/v1/evaluate`、`/health`）与 `/docs` 全部经真实 TLS 提供，
  容器内**不存在任何明文监听端口**，对外只暴露 HTTPS（默认 8443）。
- 证书管理接口凭**启动配置的管理密钥**（`X-Admin-Key` 头，恒定时间比较）鉴权。
- 更换证书时**已有连接继续可用**，之后新连接的完整 TLS 握手使用新证书。
- 证书与私钥**整份原子持久化**，进程重启加载最后成功版本，绝不加载半份组合。
- 私钥以 0600 保存，**不出现在任何响应或日志中**。

## 支持的策略项

| 策略 | 取值 | 判定语义 |
| --- | --- | --- |
| `ProtectSystem` | `off` / `full` / `strict`（`yes` 等同 `full`） | `full`：`/usr` `/boot` `/efi` `/etc` 只读；`strict`：除 `/proc` `/sys` `/dev` 外整文件系统只读；只限制写 |
| `ProtectHome` | `off` / `yes` / `read-only` | `yes`：`/home` `/root` `/run/user` 完全不可见（所有操作拒绝）；`read-only`：仅拒绝写 |
| `ReadWritePaths` | 绝对路径数组 | 可写白名单，以绑定挂载覆盖上面两项的只读限制 |
| `InaccessiblePaths` | 绝对路径数组 | 命名空间内挂载为空文件/目录，**拒绝优先级最高**，即使同路径在 `ReadWritePaths` 中也拒绝 |
| `PrivateTmp` | `true`/`false` | `/tmp`、`/var/tmp` 重映射到私有 tmpfs，可写且与主机隔离，轨迹中标注沙箱内路径 |

### 判定顺序（每一步轨迹都可对照）

1. **路径规范化**：相对路径按进程当前 cwd 拼接，词法折叠 `.`/`..`（不访问真实文件系统）。
2. **进程继承**：`fork` 事件让子进程继承父进程 cwd；`chdir` 需要目录可搜索（execute），成功后更新该 PID 的 cwd。
3. **InaccessiblePaths 优先**：命中即拒绝，且优先于一切可写放行。
4. **PrivateTmp**：命中 `/tmp`、`/var/tmp` 时标注私有命名空间映射并放行。
5. **ProtectHome**：`yes` 全拒绝；`read-only` 仅写拒绝。
6. **ProtectSystem**：对其余目录的写操作生效（`full` 限定前缀，`strict` 覆盖全局）。
7. **ReadWritePaths 放行**：可覆盖第 5、6 步的只读阻断，不能覆盖第 3 步。
8. 其余目录默认可写；`read`/`execute` 不受只读策略限制。

遇到首个拒绝事件即停止评估，`events_evaluated` 标明实际判定到第几个事件。

## 目录结构

```
app/
  engine.py    # 纯标准库判定引擎（路径规范化、cwd 继承、策略匹配）
  schemas.py   # pydantic v2 请求/响应模型（含证书更换模型）
  main.py      # FastAPI 应用：HTTPS /docs、/health、评估与 TLS 管理端点
  server.py    # 单进程 HTTPS 启动入口（外部可变 SSLContext 接入 uvicorn）
  tls.py       # 证书校验、整份原子持久化、热切换与重启加载
  pki.py       # 本地演示 PKI 生成（本地 CA + 两套同域名证书 + 错配材料）
  cli.py       # 离线命令行入口（无需 FastAPI）
scripts/
  entrypoint.sh  # 容器入口：init-pki 生成证书 / serve 降权运行 HTTPS
  demo_rotate.py # 端到端演示：更换、409 冲突、SAN/私钥错配拒绝
tests/
  test_engine.py       # 引擎测试，python3 直接运行（仅标准库）
  test_api_stub.py     # 无 FastAPI 环境下的 API/鉴权接线测试（内置最小 stub）
  test_tls_manager.py  # 证书校验/热更换/持久化/重启/半份组合拒绝（需 cryptography）
examples/request.json
Dockerfile
docker-compose.yml
requirements.txt
.env.example
```

## 方式一：Docker Compose（推荐，含本地 CA 与 /docs 演示）

```bash
# 可选：覆盖默认管理密钥
cp .env.example .env && sed -i "s/change-me.*/$(openssl rand -hex 32)/" .env

docker compose up --build -d
```

Compose 会先运行一次性任务 `pki-init`，在命名卷里生成：

- 本地根 CA：`ca/ca.pem`、`ca/ca-key.pem`
- 两套**同域名**（SAN 含 `sandbox.local`、`localhost`）证书：`certs/v1`、`certs/v2`
- 错配材料：`certs/wrong-san`（SAN 不含配置域名）、`certs/foreign`（同域名但异密钥）

业务服务以 v1 为启动证书，仅把容器 8443（HTTPS）映射到宿主，容器内无明文端口。

```bash
# 健康检查（-k 因自签跳过校验；导入本地 CA 后可去掉）
curl -sk https://localhost:8443/health

# 业务接口
curl -sk -X POST https://localhost:8443/api/v1/evaluate \
  -H 'Content-Type: application/json' --data @examples/request.json | jq .

# 浏览器交互文档（先导入 pki 卷里的 ca/ca.pem 再访问可去告警）
#   https://localhost:8443/docs
```

容器以非 root（uid 10001）运行，带 `read_only` 根文件系统、`no-new-privileges`、
drop 全部 capabilities；证书状态写入命名卷 `tls-state`，PKI 卷对业务服务只读挂载。

### 在容器内运行完整演示（更换 / 409 / 错配拒绝）

```bash
docker compose exec sandbox-checker python scripts/demo_rotate.py
```

脚本依次验证：HTTPS `/docs` 可达 → 错误密钥 401 → 长连接在更换后仍持旧证书 →
新连接完整握手拿到新证书 → 过期指纹 409 → 私钥不匹配 400 → SAN 错误 400 →
加密私钥 400 → 拒绝后旧版继续服务。

## 证书热更换 API

所有管理接口都要求请求头 `X-Admin-Key: <启动配置密钥>`。

### 查询当前证书（不含私钥）

```bash
curl -sk https://localhost:8443/api/v1/tls/certificate \
  -H "X-Admin-Key: $ADMIN_KEY"
# {"dns_name":"sandbox.local","fingerprint_sha256":"…","subject":"…","not_after":"…"}
```

### 提交更换

请求体三要素：**单张 PEM 证书、未加密 PEM 私钥、当前证书的 SHA-256 指纹**。

```bash
FP=$(curl -sk https://localhost:8443/api/v1/tls/certificate \
        -H "X-Admin-Key: $ADMIN_KEY" | jq -r .fingerprint_sha256)

curl -sk -X POST https://localhost:8443/api/v1/tls/certificate/rotate \
  -H "X-Admin-Key: $ADMIN_KEY" -H 'Content-Type: application/json' \
  -d "$(jq -n --arg cert "$(cat certs/v2/cert.pem)" \
                   --arg key  "$(cat certs/v2/key.pem)" \
                   --arg fp   "$FP" \
        '{certificate_pem:$cert, private_key_pem:$key, current_fingerprint:$fp}')"
```

服务端校验与状态码：

| 检查 | 失败结果 |
| --- | --- |
| 管理密钥缺失/错误 | `401` |
| `current_fingerprint` 与服务当前指纹不一致（已被别的更换改变） | `409`，响应给出双方指纹 |
| 证书过期 / 尚未生效 | `400` |
| SAN 不含配置的 DNS 名（`TLS_DNS_NAME`） | `400` |
| 证书与私钥公钥不匹配 | `400` |
| 私钥已加密 / 证书不是单张 PEM / 字段为空 | `400` |

校验全部在内存中完成，**校验期间服务与已有连接完全不受影响**；任一校验失败都保留旧版。

### 热更换与持久化语义

- 单进程内只有一个 `ssl.SSLContext`。更换时对同一上下文重新 `load_cert_chain`：
  **已建立的 TCP/TLS 连接继续走旧证书**，之后的新连接完整握手使用新证书
  （上下文关闭了会话票据与会话缓存，确保新连接必定完整握手）。
- 新版本先写入以完整 SHA-256 指纹命名的版本目录（`cert.pem` 0644 / `key.pem` 0600），
  fsync 后用 `rename(2)` 原子替换 `current` 符号链接——链接永远只指向完整组合，
  因此崩溃也不会出现半份状态。
- 重启时从 `current` 加载最后成功版本；若目录缺证书或缺私钥则直接拒绝启动，
  绝不加载半份组合。
- 私钥只落盘于 0700 目录下的 0600 文件，响应只回指纹/主题/到期时间，日志只打印指纹。

## 方式二：本地 Python 运行（HTTPS）

```bash
pip install -r requirements.txt

# 1) 生成本地 CA 与两套证书到 ./pki
python -m app.pki ./pki

# 2) 以 v1 启动 HTTPS 服务
ADMIN_KEY=dev-key TLS_DNS_NAME=sandbox.local \
TLS_STATE_DIR=./tls-state \
BOOTSTRAP_CERT_FILE=./pki/certs/v1/cert.pem \
BOOTSTRAP_KEY_FILE=./pki/certs/v1/key.pem \
python -m app.server          # 监听 https://0.0.0.0:8443

# 3) 跑演示（另开终端）
BASE_URL=https://127.0.0.1:8443 ADMIN_KEY=dev-key PKI_DIR=./pki \
  python scripts/demo_rotate.py
```

## 方式三：完全离线 CLI（不需要安装任何依赖）

引擎与 CLI 仅用标准库，把整个目录拷到无网络的维护机即可：

```bash
# 被阻断时退出码 1，输入非法退出码 2，全通过退出码 0
python3 -I app/cli.py examples/request.json --fail-on-deny
# 也支持标准输入
cat examples/request.json | python3 -I app/cli.py -
```

## 请求格式

策略字段同时接受 systemd 原生写法（`ProtectSystem`）和 snake_case（`protect_system`）。
策略中的路径必须是绝对路径；相对路径只允许出现在审计事件中（相对当前 cwd 解析）。

```json
{
  "policy": {
    "ProtectSystem": "full",
    "ProtectHome": "read-only",
    "ReadWritePaths": ["/etc/app", "/var/lib/app"],
    "InaccessiblePaths": ["/etc/secret"],
    "PrivateTmp": true,
    "UnitName": "app.service"
  },
  "events": [
    {"type": "chdir",  "pid": 100, "path": "/var/lib/app"},
    {"type": "fork",   "pid": 100, "child_pid": 101, "ppid": 100},
    {"type": "access", "pid": 101, "operation": "write", "path": "state.db"},
    {"type": "access", "pid": 100, "operation": "write", "path": "/tmp/cache/idx"}
  ]
}
```

事件说明：

- `fork`：必须带 `child_pid`，子进程继承父进程当前 cwd，不做文件访问判定。
- `chdir`：带 `path`（绝对或相对），按目录搜索权限判定，成功后更新该 PID 的 cwd。
- `access`：必须带 `operation`（`read`/`write`/`execute`）与 `path`。

## 配置项（环境变量）

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `ADMIN_KEY` | 无（必填） | 管理接口密钥；未配置时管理接口 fail-closed |
| `TLS_DNS_NAME` | `sandbox.local` | 证书 SAN 必须包含的 DNS 名 |
| `TLS_STATE_DIR` | `/var/lib/sandbox-checker/tls` | 证书整份持久化目录（命名卷） |
| `BOOTSTRAP_CERT_FILE` | `/etc/sandbox-checker/tls/cert.pem` | 首次启动且无持久化证书时的 PEM 证书 |
| `BOOTSTRAP_KEY_FILE` | `/etc/sandbox-checker/tls/key.pem` | 对应的未加密 PEM 私钥 |
| `TLS_HOST` / `TLS_PORT` | `0.0.0.0` / `8443` | 唯一监听地址与端口（仅 TLS） |

## 测试

```bash
python3 -I tests/test_engine.py        # 引擎语义测试，仅标准库
python3 -I tests/test_api_stub.py      # 端点/别名/422/管理密钥接线（内置 stub，仅标准库）
python3 tests/test_tls_manager.py      # 证书校验/热更换/409/持久化/重启/半份拒绝（需 cryptography）
```

## 安全边界与建模说明

- 路径为**词法规范化**，不解析符号链接；systemd 的路径单元也是基于词法前缀匹配。
- 不建模 UID/GID、DAC 权限、`BindPaths`、`TemporaryFileSystem` 等输入之外的指令。
- 演示 CA 与证书仅用于本机/Compose，**严禁用于生产**；生产请替换为正式 CA 签发的证书，
  并通过 secret/环境变量注入强随机 `ADMIN_KEY`。
- 管理密钥与私钥均不应入库：`.gitignore` 已排除 `pki/`、`tls-state/`、`*.key*`、`.env`。
