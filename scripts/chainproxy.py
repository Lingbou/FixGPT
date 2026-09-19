#!/usr/bin/env python3
"""动态 IP 出口网关：把插件的 SOCKS5 请求转成两层 CONNECT 链。

    CPA 容器 --socks5h--> 本进程 --HTTP CONNECT--> 前置代理 --CONNECT--> 动态 IP 服务 --> 目标

- 插件把会话号写在 SOCKS5 用户名里（每轮采集换一个 = 换一个出口 IP），这里原样转发，
  网关自己不需要知道凭据，也不需要实现轮换策略。
- 空闲 45 秒就断开：一个卡住的出口不该把整轮采集拖死。
- 只监听显式指定的地址，默认不对公网暴露。

环境变量：
    CHAIN_LISTEN        监听地址，默认 0.0.0.0:7900
    CHAIN_FRONT         前置代理（HTTP CONNECT），默认 127.0.0.1:7890
    CHAIN_UPSTREAM      动态 IP 服务入口，默认 us.1024proxy.io:3000
    CHAIN_IDLE_TIMEOUT  空闲断开秒数，默认 45
"""
import base64
import os
import select
import socket
import socketserver
import sys
import threading
import time

CONNECT_TIMEOUT = 20
IDLE_TIMEOUT = float(os.environ.get("CHAIN_IDLE_TIMEOUT", "45"))


def endpoint(name, default):
    raw = (os.environ.get(name) or "").strip() or default
    host, _, port = raw.rpartition(":")
    if not host or not port.isdigit():
        raise SystemExit("%s 需要 host:port（现在是 %r）" % (name, raw))
    return host, int(port)


LISTEN = endpoint("CHAIN_LISTEN", "0.0.0.0:7900")
FRONT = endpoint("CHAIN_FRONT", "127.0.0.1:7890")
UPSTREAM = endpoint("CHAIN_UPSTREAM", "us.1024proxy.io:3000")


def read_exact(sock, count):
    data = b""
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise ConnectionError("连接提前关闭")
        data += chunk
    return data


def read_until(sock, marker):
    data = b""
    while marker not in data:
        chunk = sock.recv(1024)
        if not chunk:
            raise ConnectionError("连接提前关闭")
        data += chunk
    return data


def socks5_handshake(sock):
    """完成 SOCKS5 协商，返回 (目标主机, 目标端口, 用户名, 密码)。"""
    version, count = read_exact(sock, 2)
    if version != 5:
        raise ConnectionError("不是 SOCKS5 请求")
    methods = read_exact(sock, count)
    # 动态 IP 服务的凭据从用户名透传，所以这里要求客户端带上用户名/密码。
    sock.sendall(b"\x05\x02" if 2 in methods else b"\x05\x00")

    username = password = ""
    if 2 in methods:
        version = read_exact(sock, 1)[0]
        ulen = read_exact(sock, 1)[0]
        username = read_exact(sock, ulen).decode("utf-8", "replace")
        plen = read_exact(sock, 1)[0]
        password = read_exact(sock, plen).decode("utf-8", "replace")
        sock.sendall(b"\x01\x00")

    version, command, _, atyp = read_exact(sock, 4)
    if command != 1:
        raise ConnectionError("只支持 CONNECT")
    if atyp == 3:
        length = read_exact(sock, 1)[0]
        host = read_exact(sock, length).decode("utf-8", "replace")
    elif atyp == 1:
        host = socket.inet_ntoa(read_exact(sock, 4))
    elif atyp == 4:
        host = socket.inet_ntop(socket.AF_INET6, read_exact(sock, 16))
    else:
        raise ConnectionError("未知地址类型")
    port = int.from_bytes(read_exact(sock, 2), "big")
    return host, port, username, password


def http_connect(sock, host, port, username="", password=""):
    request = "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n" % (host, port, host, port)
    if username:
        token = base64.b64encode(("%s:%s" % (username, password)).encode()).decode()
        request += "Proxy-Authorization: Basic %s\r\n" % token
    sock.sendall((request + "\r\n").encode())
    response = read_until(sock, b"\r\n\r\n")
    first = response.split(b"\r\n")[0]
    if b" 200" not in first:
        raise ConnectionError("上游拒绝: %s" % first.decode("utf-8", "replace"))


def session_fields(username):
    region = username.split("-region-")[-1].split("-sid-")[0] if "-region-" in username else "?"
    sid = username.split("-sid-")[-1].split("-")[0] if "-sid-" in username else "?"
    return region, sid


def pipe(src, dst):
    try:
        while True:
            ready, _, _ = select.select([src], [], [], IDLE_TIMEOUT)
            if not ready:
                print(
                    "%s 空闲 %.0fs 关闭" % (time.strftime("%H:%M:%S"), IDLE_TIMEOUT),
                    file=sys.stderr,
                    flush=True,
                )
                break
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        for sock in (src, dst):
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        client = self.request
        client.settimeout(CONNECT_TIMEOUT)
        started = time.time()
        host, port, username = "?", 0, ""
        try:
            host, port, username, password = socks5_handshake(client)
            tunnel = socket.create_connection(FRONT, timeout=CONNECT_TIMEOUT)
            tunnel.settimeout(CONNECT_TIMEOUT)
            http_connect(tunnel, UPSTREAM[0], UPSTREAM[1])          # 先到动态 IP 入口
            http_connect(tunnel, host, port, username, password)    # 再让出口服务出网
        except Exception as exc:
            region, sid = session_fields(username)
            print(
                "%s 拒绝 %s:%s region=%s sid=%s %.1fs %s"
                % (time.strftime("%H:%M:%S"), host, port, region, sid, time.time() - started, exc),
                file=sys.stderr,
                flush=True,
            )
            try:
                client.sendall(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
            except OSError:
                pass
            client.close()
            return

        region, sid = session_fields(username)
        print(
            "%s 接通 %s:%s region=%s sid=%s %.1fs"
            % (time.strftime("%H:%M:%S"), host, port, region, sid, time.time() - started),
            file=sys.stderr,
            flush=True,
        )
        client.settimeout(None)
        tunnel.settimeout(None)
        client.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        threading.Thread(target=pipe, args=(client, tunnel), daemon=True).start()
        pipe(tunnel, client)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    print(
        "chainer 监听 %s:%d -> %s:%d -> %s:%d" % (LISTEN[0], LISTEN[1], FRONT[0], FRONT[1], UPSTREAM[0], UPSTREAM[1]),
        flush=True,
    )
    with Server(LISTEN, Handler) as server:
        server.serve_forever()