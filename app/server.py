"""单进程 HTTPS 启动入口。

* 只监听一个 TLS 端口（默认 8443），不提供任何明文 HTTP 监听，明文端口不对外。
* 启动时优先从持久化状态目录加载"最后成功版本"；若无则用启动证书初始化。
* 把同一个可变 :class:`ssl.SSLContext` 交给 uvicorn，使运行期热更换对
  已建立连接透明、对新连接立即生效。

环境变量：
    ADMIN_KEY            管理接口密钥（必填）
    TLS_DNS_NAME         证书 SAN 必须包含的 DNS 名（默认 sandbox.local）
    TLS_STATE_DIR        证书持久化目录（默认 /var/lib/sandbox-checker/tls）
    BOOTSTRAP_CERT_FILE  首次启动且无持久化证书时的 PEM 证书（默认 /etc/sandbox-checker/tls/cert.pem）
    BOOTSTRAP_KEY_FILE   对应的未加密 PEM 私钥（默认 /etc/sandbox-checker/tls/key.pem）
    TLS_HOST             监听地址（默认 0.0.0.0）
    TLS_PORT             监听端口（默认 8443）
"""

from __future__ import annotations

import os
import ssl
import sys

import uvicorn

from .main import configure
from .tls import TLSManager


def _require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        sys.stderr.write(f"启动失败：缺少必需环境变量 {name}\n")
        raise SystemExit(2)
    return value


class _TLSConfig(uvicorn.Config):
    """复用 uvicorn 装配流程，但把 SSL 上下文替换为外部可变对象。

    uvicorn 0.34 尚无 ``ssl_context_factory``；其 ``load()`` 在 ``is_ssl``
    时依据 ssl_certfile 自行 create_ssl_context 并赋给 ``self.ssl``，而
    ``Server`` 最终把 ``config.ssl`` 传给 ``loop.create_server``。这里在父类
    装配后覆盖 ``self.ssl``，仅依赖这一稳定属性，兼容 0.34 与更新版本。
    """

    def __init__(self, app, tls_context: ssl.SSLContext, **kwargs):
        super().__init__(app, **kwargs)
        self._tls_context = tls_context

    def load(self) -> None:
        super().load()
        self.ssl = self._tls_context


def main() -> None:
    admin_key = _require_env("ADMIN_KEY")
    dns_name = os.environ.get("TLS_DNS_NAME", "sandbox.local")
    state_dir = os.environ.get("TLS_STATE_DIR", "/var/lib/sandbox-checker/tls")
    bootstrap_cert = os.environ.get(
        "BOOTSTRAP_CERT_FILE", "/etc/sandbox-checker/tls/cert.pem"
    )
    bootstrap_key = os.environ.get(
        "BOOTSTRAP_KEY_FILE", "/etc/sandbox-checker/tls/key.pem"
    )
    host = os.environ.get("TLS_HOST", "0.0.0.0")
    port = int(os.environ.get("TLS_PORT", "8443"))

    manager = TLSManager(state_dir=state_dir, expected_dns=dns_name)

    if manager.bootstrap_from_disk():
        sys.stderr.write(
            f"[tls] 已从持久化状态加载最后成功版本（指纹 {manager.fingerprint}）\n"
        )
    else:
        sys.stderr.write("[tls] 未发现持久化证书，使用启动证书初始化\n")
        with open(bootstrap_cert, encoding="utf-8") as fh:
            cert_pem = fh.read()
        with open(bootstrap_key, encoding="utf-8") as fh:
            key_pem = fh.read()
        manager.bootstrap_from_pem(cert_pem, key_pem)
        sys.stderr.write(
            f"[tls] 启动证书已加载并持久化（指纹 {manager.fingerprint}）\n"
        )

    configure(manager, admin_key)

    config = _TLSConfig(
        "app.main:app",
        manager.context,
        host=host,
        port=port,
        # 占位路径用于令 is_ssl 为真、进入 uvicorn 的 ssl 装配分支；
        # 真正的上下文在 load() 中被我们的可变对象覆盖。
        ssl_certfile=bootstrap_cert,
        ssl_keyfile=bootstrap_key,
        workers=1,  # 单服务进程：内存中的 SSLContext 即唯一真相源
        log_level=os.environ.get("LOG_LEVEL", "info"),
        access_log=os.environ.get("ACCESS_LOG", "1") == "1",
    )
    server = uvicorn.Server(config)
    server.run()


if __name__ == "__main__":
    main()
