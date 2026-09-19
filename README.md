# FixGPT

FixGPT 是一个 [CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI)（下称 CPA）插件：它维护 Codex 的 turn-state 并注入生成请求，避免会话被降智；同时内置 GPT 数字指纹检测，用来发现账号被切到降级后端的情况。

- **防降智**：按 CPA 最终选中的「账号 + 模型」维护 state，注入 `X-Codex-Turn-State`
- **查降智**：内置指纹检测（只跑 GPT 模型），结果直接标「正常 / 异常 / 不确定」
- **采集换 IP，业务不换**：采集时在出口池里轮换出口，复验和日常请求仍然走 CPA 原来的出口

## 工作原理

```
真实请求 → CPA 选账号 → 插件注入已复验的 state → 上游
                  │
                  └─ 没有可用 state 时自动采集（后台，不需要真实请求）
                       采集：出口池里轮一个出口 → 拿 state（312 / 模型不符就换下一个）
                       复验：切回业务出口，带着这份 state 再打一次 → 通过才存下来
```

- 状态形状：个人账号 **292** 字节（10 块）、Team **332** 字节（12 块）；**312 字节是服务端下发的降智信号**
- state 只按「账号 + 模型」存取，不跨账号、不跨模型复用
- 401 / 403 / 429 是凭据级结论：停下来，不换 IP 硬撞
- 采集失败或上游过载时，CPA 会把凭据按模型冷却，插件会读这个冷却状态并跳过，等恢复再采

## 安装

### 1. 前置条件

| 需要什么 | 说明 |
| --- | --- |
| CPA | 插件宿主。作者的 fork `Lingbou/CLIProxyAPI` 上有一个补丁分支 `feature/plugin-host-capabilities`，给插件宿主加两项能力：内部调用可以指定出口（`proxy_url`），以及内部调用能读到上游响应头（292/312 就在这里）。没打这两个补丁插件仍能跑，但采集不换 IP、也读不到 state |
| Rust | 构建插件（`rust-toolchain.toml` 里写了版本） |
| 出口池（可选） | 一组 HTTP / SOCKS5 代理。不配也能用，但只能靠真实请求触发采集，且不轮换 IP |

### 2. 构建插件

```sh
cd /root/github/FixGPT
cargo test --workspace         # 可选
./scripts/build-plugin.sh      # 产出 plugins/linux/amd64/fixgpt.so
```

### 3. 装进 CPA

把 `fixgpt.so` 放进 CPA 的插件目录，然后在 CPA 配置里打开：

```yaml
plugins:
  enabled: true
  dir: "/CLIProxyAPI/plugins/linux/amd64"
  configs:
    fixgpt:
      enabled: true
      priority: 100
```

- 文件名必须是 `fixgpt.so`
- 改完重启 CPA；或者在管理面板的 Plugins 页把 FixGPT 关一下再打开（热重载，不用重启进程）
- 加载成功的标志：日志里出现 `pluginhost: plugin registered plugin_id=fixgpt`，面板左侧多出 `FixGPT` 菜单

### 4. 准备出口池（想要「自动采集 + 换 IP」才需要）

出口池是一个 JSON 文件，放在 CPA 容器能读到的地方，默认路径：

```
/CLIProxyAPI/state/pool.json        （即部署目录里的 state/pool.json）
```

格式（每条一个出口，`label` 只用于页面显示）：

```json
{
  "proxies": [
    { "url": "http://172.18.0.1:7901", "label": "香港W01" },
    { "url": "http://172.18.0.1:7902", "label": "日本W01" },
    { "url": "socks5h://user:pass@1.2.3.4:1080", "label": "US-01" }
  ]
}
```

说明：

- 只接受 `http` / `https` / `socks5` / `socks5h`；宿主会拒绝其它协议
- 插件每 30 秒重读一次这个文件，改完不用重启
- **池子为空 = 自动采集关闭**：只有真实请求经过时才建立采集任务（插件重启后要再来一次真实请求）
- 怎么弄出这些出口，两种常见做法：
  1. **本地内核开多端口**：用 mihomo（或 Clash）把订阅里的节点每个绑一个本地 HTTP 口，例如
     ```yaml
     listeners:
       - {name: pool-1, type: http, listen: 0.0.0.0, port: 7901, proxy: "香港W01"}
       - {name: pool-2, type: http, listen: 0.0.0.0, port: 7902, proxy: "日本W01"}
     ```
     然后把这些端口地址写进 `pool.json`（容器里访问宿主用 `172.18.0.1`）
  2. **动态 IP 服务（本项目服务器上用的就是这种）**：住宅/机房动态 IP 服务一般会给一个 SOCKS5/HTTP 入口，
     用户名里带地区与会话号。插件每轮把 `{sid}` 换成新的会话号，就等于换一个出口 IP：

     ```json
     {
       "proxies": [
         { "url": "socks5h://user-region-US-sid-{sid}-t-5:pass@172.16.0.70:7900", "label": "美国" },
         { "url": "socks5h://user-region-JP-sid-{sid}-t-5:pass@172.16.0.70:7900", "label": "日本" }
       ]
     }
     ```

     多写几条不同地区 = 每轮在这些地区里轮换，命中 292 的概率明显更高（实测同一账号在不同出口 IP 上
     有的签发 292、有的直接给 312）。`{sid}` / `{random}` 是插件侧占位符，每次尝试都会换。

     如果这个服务不接受国内直连（多数住宅池都会拦），就需要一层前置代理 + 一个网关脚本，
     也就是 `scripts/chainproxy.py`：它把插件的 SOCKS5 转成「前置代理 → 动态 IP 服务」两层 CONNECT 链，
     并把空闲连接 45 秒断开（一个卡住的出口不该把整轮采集拖死）。

     ```sh
     # 前置代理（mihomo/clash 的 HTTP 端口）监听 127.0.0.1:7890 时：
     CHAIN_LISTEN=172.16.0.70:7900 CHAIN_FRONT=127.0.0.1:7890 \
       CHAIN_UPSTREAM=us.1024proxy.io:3000 python3 scripts/chainproxy.py
     ```

     注意 `CHAIN_LISTEN` 要写 CPA 容器能访问到的宿主地址（容器里看到的宿主 IP，通常是宿主内网网卡地址），
     然后 `pool.json` 里就写这个地址。

### 5. 第一次跑起来

1. 重启 CPA，确认插件已加载
2. 打开管理面板 → 左侧 `FixGPT`
3. 卡片会自动列出 CPA 里启用的 Codex 账号和候选模型
4. 池子配好的话，30 秒内它就会自己开始采集（卡片显示「state 采集中」→「正常 · 剩余 xx 分钟」）
5. 池子没配的话，用客户端（Codex CLI / 任意 OpenAI 兼容客户端）经 CPA 发一条 GPT 请求即可触发采集

## 使用

### 三步跑起来

1. 装好插件并重启 CPA（见上面「安装」），日志出现 `pluginhost: plugin registered plugin_id=fixgpt` 就是加载成功
2. 配好出口池 `state/pool.json`（留空也能跑，只是不换 IP、也不会自动采集）
3. 打开管理面板 → 左侧 `FixGPT`，卡片从「state 采集中」变成「正常 · 剩余 xx 分钟」就完事了

之后不用管：到期前会自动续采，收到 312 会自动作废重采。

### 管理页面

地址 `http(s)://<你的 CPA 地址>/management.html`，用 CPA 管理密钥登录，左侧菜单 `FixGPT`。

- 一张卡片 = 一个 Codex 账号；卡片里的下拉框选模型（每个「账号 × 模型」是独立的一份 state）
- `检测`：对这张卡片跑一次指纹检测（会真实消耗额度，最多 6 次模型调用）
- `一键检测`：所有账号一起跑
- `刷新状态`：立刻拉一次数据
- 只在页面可见时轮询：状态 5 秒一次，计数 30 秒一次；切走或关掉就停

**卡片状态**

| 显示 | 含义 | 你要做什么 |
| --- | --- | --- |
| `正常 · 剩余 xx 分钟` | 手上有复验通过的 state，正在注入 | 不用管 |
| `state 采集中` | 后台正在采集 | 等 30~60 秒 |
| `尚无 state` | 还没有可用 state，业务请求走兜底转发 | 看下面「最近采集」那行 |
| `state 已失效 · 收到 312` | 上游下发了降智信号 | 会自动重采；反复出现说明这批出口质量差 |
| `state 被上游拒绝` | 账号返回 401 / 403 / 429 | 去 CPA 处理账号本身的问题 |

**「最近采集」怎么读**

| 文案 | 含义 |
| --- | --- |
| `292 字节 · gpt-6-astra · 模型一致 · 出口 1024proxy 德国` | 采到合格 state 且复验通过 |
| `312 字节 · 降智信号（312） · 出口 …` | 这个出口只给降级 state，已停用它并换下一个 |
| `312 字节 · 实际返回 gpt-5.6-luna · 出口 …` | 要 astra 却回了 luna，同样按出口级失败处理 |
| `采集失败（尝试 N 次）：…` | 一轮里 N 个出口都没成功，冷却一会儿再试 |
| `还没有采集记录` | 这一轮还没跑完 |

### 怎么确认注入真的生效

三种办法，从直接到间接：

**1）看响应头（最直接）** —— 任意客户端经 CPA 发一条 GPT 生成请求，响应里会带：

| 响应头 | 值 | 含义 |
| --- | --- | --- |
| `X-FixGPT-State-Mode` | `injected` | 注入了（正常） |
| | `fallback-passthrough` | 没有可用 state，原样转发（可能被降智） |
| | `upstream-rejected` | 凭据被拒（401/403/429），没注入 |
| | `state-unavailable` | 严格模式下被拦下（503） |
| `X-FixGPT-State-Auth` | `codex-xxx.json` | 这次用的是哪个账号 |
| `X-FixGPT-State-Version` | 数字 | 这份 state 的版本号，换新会加一 |
| `X-FixGPT-Injected-State` | `gAAAAA…` | 实际注入的值（排查用） |

```sh
curl -sD - -o /dev/null -X POST http://127.0.0.1:8317/v1/responses \
  -H "Authorization: Bearer <CPA 的 api-key>" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-6-astra","input":"say ok","stream":false}' | grep -i fixgpt
```

**2）看页面计数**：状态条的「正常 / 降智 / 无 state」只统计 Codex 的 GPT 流量，其它 provider（Claude、Kimi、图片…）不计入。

**3）看 state 剩余时间**：正常运行时它会在 20~60 分钟之间循环，说明续采一直在工作。

### 开关与兜底策略

```sh
BASE=http://127.0.0.1:8317/v0/resource/plugins/fixgpt/injection

curl "$BASE"                        # 读当前设置
curl "$BASE?enabled=0"              # 关掉注入（等于没装插件）
curl "$BASE?enabled=1"              # 打开（默认）
curl "$BASE?fallback=passthrough"   # 没有 state 时照常转发（默认）
curl "$BASE?fallback=strict"        # 没有 state 时直接 503 + Retry-After: 30
```

严格模式适合「宁可失败也不要降智」的场景（比如跑评测）；日常用 `passthrough`。

### 立刻采一轮 / 看采集诊断

```sh
# 诊断：每个任务的 next_probe 倒计时、是否 usable、有没有被上游拒绝、上次结果
curl -s "http://127.0.0.1:8317/v0/resource/plugins/fixgpt/harvest" | python3 -m json.tool

# 立刻跑一轮（可带 auth_id / model 缩小范围；会消耗额度）
curl -s "http://127.0.0.1:8317/v0/resource/plugins/fixgpt/harvest?run=1&model=gpt-6-astra"
```

### 指纹检测

- 只对 GPT 模型做（内嵌 ModelTrace 的数值银行），结论是 `正常 / 异常 / 不确定 / 失败`
- **会真实消耗账号额度**，所以只在手动点击时发起
- 页面走的是异步任务接口；命令行也能直接调：

```sh
AUTH=codex-xxxx.json
# 1) 起任务，拿 task_id
curl -s "http://127.0.0.1:8317/v0/resource/plugins/fixgpt/modeltrace/start?auth_id=$AUTH&model=gpt-6-astra"
# {"task_id":"mt-1789912345-1"}

# 2) 轮询进度 / 结果
curl -s "http://127.0.0.1:8317/v0/resource/plugins/fixgpt/modeltrace/status?task_id=mt-1789912345-1" | python3 -m json.tool

# 3) 还在跑的任务
curl -s "http://127.0.0.1:8317/v0/resource/plugins/fixgpt/modeltrace/tasks"
```

### 改出口池

- 池子文件：容器内 `/CLIProxyAPI/state/pool.json`，也就是部署目录里的 `state/pool.json`
- 插件每 30 秒重读一次，**改完不用重启**
- 池子为空 = 不自动采集、不换出口（只有真实请求经过时才顺带建任务）

```json
{
  "proxies": [
    { "url": "http://172.18.0.1:7901", "label": "香港W01" },
    { "url": "socks5h://user-region-US-sid-{sid}-t-5:pass@172.16.0.70:7900", "label": "1024proxy 美国" }
  ]
}
```

- `{sid}` / `{random}` 是占位符：每次尝试都会换成新的会话号（动态 IP 服务靠它换出口 IP）
- 一行一个出口；一轮最多试 `HARVEST_ATTEMPTS`（默认 8）个

### 换插件 / 重启 CPA

```sh
# 换插件
cp fixgpt.so <部署目录>/plugins/linux/amd64/fixgpt.so

# 重启（按自己的 compose 写法）
CLI_PROXY_IMAGE=<镜像> docker compose up -d --force-recreate
```

插件重启后：`state/turn-state.json` 里还有效的 state 会直接恢复继续注入，不用等重新采集。

### 接口一览

| 路径 | 作用 |
| --- | --- |
| `/v0/resource/plugins/fixgpt/status` | 管理面板页面（菜单入口） |
| `/v0/resource/plugins/fixgpt/state` | 页面轮询的 JSON：账号 × 模型状态、计数、内部快照 |
| `/v0/resource/plugins/fixgpt/injection` | 读/改注入开关与兜底策略 |
| `/v0/resource/plugins/fixgpt/harvest` | 采集诊断：每个任务的 next_probe / 拒绝状态 / 上次结果；带 `run=1` 时立刻跑一轮采集 |
| `/v0/resource/plugins/fixgpt/modeltrace/start` | 启动一次检测任务（`auth_id`、`model`） |
| `/v0/resource/plugins/fixgpt/modeltrace/status` | 查询任务进度（`task_id`） |
| `/v0/resource/plugins/fixgpt/modeltrace/tasks` | 列出仍在运行的任务 |

> 注意：`/v0/resource/...` 是 CPA 的匿名资源路由（CPA 自身设计如此），公网部署要么只监听 `127.0.0.1`，要么在反向代理上加鉴权。

### 文件

| 文件（容器内 `/CLIProxyAPI/state/`） | 内容 |
| --- | --- |
| `turn-state.json` | 已经采到的 state，插件重启后直接续用 |
| `modeltrace-results.json` | 检测结果，刷新页面或重启插件后仍在 |
| `state-stats.json` | 正常 / 降智 / 无 state 的计数（只统计 Codex GPT 流量） |
| `pool.json` | 出口池（只读，插件每 30 秒重读） |

### 采集参数（想调的话）

都在 `crates/cpa-plugin/src/runtime.rs` 顶部：

| 常量 | 默认 | 含义 |
| --- | --- | --- |
| `AUTO_HARVEST_SCAN_SECONDS` | 30 | 多久扫一次账号、决定要采哪些 |
| `HARVEST_ATTEMPTS` | 8 | 一轮最多换几个出口 |
| `HARVEST_ATTEMPT_INTERVAL` | 3s | 一轮里两次尝试之间的间隔 |
| `EGRESS_DEGRADED_COOLDOWN_SECONDS` | 300 | 出口回了降级响应（312 / 没有 state）后的冷却 |
| `EGRESS_FAIL_COOLDOWN_SECONDS` | 1800 | 出口连不上或被拦后的冷却 |
| `HARVEST_FAIL_COOLDOWN_SECONDS` | 600 | 一轮全失败后，这个「账号 × 模型」的冷却 |
| `DEGRADED_HARVEST_COOLDOWN_SECONDS` | 1800 | 一整轮全是降级响应（312 / 模型被换成长 luna）时的冷却 |
| `PROBE_COOLDOWN_SECONDS` | 180 | 一轮采集结束后到下次的最短间隔 |
| `OVERLOAD_PAUSE_SECONDS` | 900 | 上游 5xx 之后全局暂停采集的时间 |
| `REJECT_COOLDOWN_SECONDS` | 180 | 凭据被 401 / 403 / 429 拒绝后的冷却 |

### 部署到服务器（参考形态）

一套已经在跑的配置：**业务流量走 mihomo，只有采集走动态住宅池**。

| 组件 | 位置 | 作用 |
| --- | --- | --- |
| CPA 部署目录 | `~/WorkSpace/github/CLIProxyAPI` | 源码 + `config.yaml` + `auths/` + `plugins/` + `state/` + `logs/` |
| 插件 | `plugins/linux/amd64/fixgpt.so` | 挂进容器 `/CLIProxyAPI/plugins` |
| 出口池 | `state/pool.json` | 挂进容器 `/CLIProxyAPI/state` |
| 采集网关 | `~/cpa-pool/chainproxy.py` + `start-chainer.sh` | 监听 `172.16.0.70:7900`，串「前置代理 → 动态 IP 服务」 |
| 业务出口 | `config.yaml` 的 `proxy-url` | 指向 mihomo，例如 `http://172.16.0.70:7890` |
| 守护 | crontab | 每 2 / 5 分钟探端口，掉了就拉起来 |

`start-chainer.sh` 把网关配置集中在一处：

```sh
export CHAIN_LISTEN=172.16.0.70:7900     # CPA 容器从这里连（写宿主内网地址）
export CHAIN_FRONT=127.0.0.1:7890        # 前置代理（mihomo / clash）
export CHAIN_UPSTREAM=us.1024proxy.io:3000
export CHAIN_IDLE_TIMEOUT=45             # 空闲连接断开秒数，别让慢出口卡住整轮
exec python3 chainproxy.py
```

对应的 crontab（`ss` 要用绝对路径：cron 的 PATH 里没有 `/usr/sbin`）：

```cron
*/5 * * * * /usr/sbin/ss -lnt | grep -q "172.16.0.70:7900" || (cd $HOME/cpa-pool && setsid nohup ./start-chainer.sh >> chainer.log 2>&1 &)
*/2 * * * * /usr/sbin/ss -lnt | grep -q "172.16.0.70:7890" || (setsid nohup socat TCP-LISTEN:7890,bind=172.16.0.70,fork,reuseaddr TCP:127.0.0.1:7890 >> $HOME/cpa-pool/socat.log 2>&1 &)
```

要点：

- CPA 容器的 `proxy-url` 要写**容器能访问到的宿主地址**（内网网卡 IP，或 docker 网桥网关），别写 `127.0.0.1`
- 动态住宅 IP 服务通常拒绝国内直连，所以 `CHAIN_FRONT` 那层前置代理是必需的
- 想全量走池子（包括业务流量）：把 `config.yaml` 的 `proxy-url` 改成池子入口，并把地区/会话写死——
  但要注意池子的计费与稳定性，日用更推荐「业务走 mihomo、采集走池子」

### 常见问题

| 现象 | 原因 / 处理 |
| --- | --- |
| 面板上看不到 FixGPT 菜单 | 插件没加载成功：看 CPA 日志有没有 `pluginhost: plugin registered plugin_id=fixgpt`；确认文件名是 `fixgpt.so`，且放在 `plugins/<os>/<arch>/` 目录下 |
| 卡片里没有账号 | CPA 里没有启用的 Codex 账号（`auth-dir` 下的 `*.json`，`disabled` 不为 true） |
| 一直「尚无 state」 | 看「最近采集」那行：`auth_unavailable` = CPA 把这条凭据冷掉了，等冷却；连续 `312 降智信号` = 这批出口都被降级，换节点或换服务商 |
| 一直「state 采集中」 | 一轮最多 8 个出口、每个几十秒，耐心等；超过 5 分钟没动静就看 `/harvest` 诊断接口 |
| 采集报 `unknown error` / 连接超时 | 采集网关或前置代理不通：用 `ss -lnt` 看 7900 端口在不在，用 `curl -x http://<前置代理> https://api.ipify.org` 看前置通不通 |
| 检测一直失败 | 检测同样消耗额度、同样走业务出口；先在 CPA 里确认账号本身可用 |
| 业务请求被降智（返回 luna 之类） | 看响应头 `X-FixGPT-State-Mode`：`fallback-passthrough` 说明那一刻没有可用 state，插件会自动重采；长期如此说明出口池采不到 292 |
| 想彻底关掉注入 | `/injection?enabled=0`，行为等于没装插件 |
| 部署到公网 | `/v0/resource/...` 是匿名路由，页面会显示账号邮箱和 state 状态；只监听 `127.0.0.1`，或在反向代理上加鉴权 |

## 边界

- 不增加账号额度，不绕过 401 / 403 / 429
- 不重放已经发到上游的生成请求
- 不落盘 OAuth / API key：只在内存里解一次 `Authorization` 的 JWT 拿 `chatgpt_plan_type`（区分个人 / Team），请求结束即丢
- 落盘的是上游下发的 state、检测结果和计数
- 指纹检测会真实消耗额度
- 指纹评分只是闭集候选分类结果，不是上游实例的证明；要结合重复样本、复测和 state 状态一起看

## 许可证与来源

本项目按 **GPL-3.0-only** 发布，见 `LICENSE`。

指纹检测部分借用了 [ModelTrace](https://github.com/xqy2006/ModelTrace)：`crates/modeltrace-core/data/gpt_bank.json` 直接取自该项目，评分逻辑按同一套规则用 Rust 重写。

- ModelTrace：MIT，Copyright (c) 2026 xqy2006

  > Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
  >
  > The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
  >
  > THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

- CLIProxyAPI：MIT，仅使用其插件 ABI 与宿主回调约定，未内置其源码。
