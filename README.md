# TLS

这是 TLS 多人控制面的公开代码仓库和用户 Agent 配对说明。仓库不包含用户的 Codex
会话、transcript、飞书密钥、SSH 私钥或长期凭据；用户已有的 Codex/Agent 读取本 README
后，在用户自己的电脑上完成配对。

## 给用户 Agent 的最短流程

当用户把这个仓库链接发给你时，按下面流程执行：

1. 提醒用户在 TLS 的飞书私聊中发送一次 `/pair`。
2. 让用户把 TLS 返回的一次性配对码，或包含配对码的完整回复，发回给你。
3. 在用户本机运行仓库中的 `tls_pair.py`，把配对码通过标准输入传给它：

   ```bash
   python3 tls_pair.py pair --code-stdin
   ```

   配对 helper 默认访问 `https://api.xhqcode.com/tls-agent`，向
   `/v1/agent/pair` 换取凭据，并将配置安全写入 `~/.config/tls/agent.env`。如果
   Agent 没有标准输入工具，再使用 `--code <一次性配对码>`，但不要把命令或配对码
   发到群聊、提交到 Git 或写入日志。

4. 使用下面的命令验证，只向用户报告 `user_id` 和 `installation_id`：

   ```bash
   python3 tls_pair.py status
   ```

`tls_pair.py` 不是 Codex Agent；它只负责一次性配对和凭据落盘。真正的用户 Agent 可以
使用自己的 Session 执行器读取 `~/.config/tls/agent.env`。用户不需要在 `automl` 或服务
器控制面上执行配对。

## 身份和安全规则

- TLS 按飞书账号维护稳定的 `user_id`；同一用户在不同群中使用同一个 TLS 身份。
- `installation_id` 表示一台本机 Agent，不等于用户身份。
- 配对码只用于一次配对，短期有效；服务端只保存摘要。
- `token` 是本机 Agent 的访问凭据，必须以 0600 权限保存在本机，不能回显。
- 不要自行生成或复制用户身份编码，也不要要求用户提供 SSH 地址、私钥或长期 Token。
- 公网 Gateway 必须通过 HTTPS 暴露；`tls_pair.py` 只允许对本机测试地址使用 HTTP。

如果 TLS 提示账号尚未登记或未通过审核，当前服务端仍要求管理员先批准该飞书账号；
README 不会绕过这个权限检查。

## 代码布局

- `tls_pair.py`：用户侧一次性配对 helper，不依赖私聊版运行库。
- `qyp_multi_registry.py`：用户、安装实例、Session、群组和任务授权的 SQLite 控制面。
- `qyp_multi_transport.py`：Agent 凭据、心跳、命令和结果队列。
- `qyp_multi_gateway.py`：标准库 HTTP Gateway；生产部署应由外层 HTTPS 终止器保护。
- `qyp_multi_adapter.py`、`qyp_multi_feishu.py`：与 Feishu ingress 对接的授权适配层。
- `tests/`：本地 SQLite、授权、队列和配对 helper 测试。

仓库不包含生产 Feishu ingress、SSH 远程执行器、服务器 systemd 单元或 incident 日志。
这些文件含有环境路径和部署边界，必须在受控服务器上单独配置，不能随用户代码分发。

## 本地验证

代码只使用 Python 标准库。运行：

```bash
python3 -m unittest discover -s tests -p 'test_*.py'
python3 -m py_compile tls_pair.py qyp_multi_*.py
```

服务端 Gateway 的本地演示应使用临时 SQLite 数据库和 `127.0.0.1`，不要连接生产网关或
把真实配对码写入测试文件。
