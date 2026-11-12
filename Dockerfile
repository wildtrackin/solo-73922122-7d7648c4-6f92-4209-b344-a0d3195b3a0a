# 离线 systemd 沙箱策略核查服务（单进程 HTTPS + 证书热更换）
# 构建上下文即项目根目录；构建期需要能访问 PyPI 镜像，运行期无需任何外部网络。
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /opt/sandbox-checker

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY scripts ./scripts
COPY scripts/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 0755 /usr/local/bin/entrypoint.sh scripts/*.py scripts/*.sh

# 以非 root 运行（该服务本身不需要任何特权，只做纯计算与 TLS 终止）
RUN useradd --create-home --uid 10001 appuser

# 持久化状态目录（卷挂载点）与启动证书目录
RUN install -d -m 0755 -o appuser -g appuser /var/lib/sandbox-checker/tls \
    && install -d -m 0755 /etc/sandbox-checker/tls

# 仅暴露 TLS 端口；容器内不监听任何明文端口
EXPOSE 8443

# 健康检查走 HTTPS（自签/本地 CA，故关闭校验），不暴露任何明文通道
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import ssl,urllib.request,sys; ctx=ssl._create_unverified_context(); sys.exit(0 if urllib.request.urlopen('https://127.0.0.1:8443/health', context=ctx, timeout=3).status==200 else 1)"

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["serve"]
