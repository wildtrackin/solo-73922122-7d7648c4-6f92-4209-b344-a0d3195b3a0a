#!/bin/sh
# 容器入口：
#   init-pki : 生成演示用本地 CA 与两套同域名证书（一次性任务，root 运行）
#   serve    : 收敛持久化目录权限后降权到 appuser 运行单进程 HTTPS 服务（默认）
set -eu

APP_UID=10001
APP_GID=10001
PKI_DIR="${PKI_DIR:-/var/lib/sandbox-checker/pki}"
STATE_DIR="${TLS_STATE_DIR:-/var/lib/sandbox-checker/tls}"
BOOTSTRAP_CERT_FILE="${BOOTSTRAP_CERT_FILE:-/etc/sandbox-checker/tls/cert.pem}"
BOOTSTRAP_KEY_FILE="${BOOTSTRAP_KEY_FILE:-/etc/sandbox-checker/tls/key.pem}"

case "${1:-serve}" in
  init-pki)
    echo "[entrypoint] 生成演示 PKI 到 ${PKI_DIR}"
    mkdir -p "${PKI_DIR}"
    # 不加 -I：隔离模式会忽略 cwd，导致 -m app.pki 无法定位包；
    # 容器内代码只读、已降权且不挂载外部代码，安全边界由容器提供。
    python -m app.pki "${PKI_DIR}"
    mkdir -p "${STATE_DIR}"
    # 容器内 init-pki 以 root 运行，chown 成功；非 root 环境下降级容错。
    chown -R "${APP_UID}:${APP_GID}" "${PKI_DIR}" "${STATE_DIR}" 2>/dev/null || true
    chmod 0700 "${STATE_DIR}"
    echo "[entrypoint] PKI 初始化完成（启动证书：${PKI_DIR}/certs/v1）"
    ;;

  serve)
    # 持久化目录仅属主可访问（私钥落盘保护）
    mkdir -p "${STATE_DIR}"
    chmod 0700 "${STATE_DIR}" 2>/dev/null || true
    if [ "$(id -u)" = "0" ]; then
      chown -R "${APP_UID}:${APP_GID}" "${STATE_DIR}" 2>/dev/null || true
      # util-linux 自带 setpriv，无需额外安装 gosu
      exec setpriv --reuid="${APP_UID}" --regid="${APP_GID}" --init-groups \
        python -m app.server
    else
      exec python -m app.server
    fi
    ;;

  *)
    exec "$@"
    ;;
esac
