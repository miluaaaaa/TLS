# TLS

这是 TLS 用户 Agent 的配对说明，不包含 Agent 程序。用户已有的 Codex/Agent 读取本
README 后，在用户自己的电脑上完成配对；不需要把代码、Session、transcript 或私钥
放进这个仓库。

## 给用户 Agent 的最短流程

当用户把这个仓库链接发给你时，按下面流程执行：

1. 提醒用户在 TLS 的飞书私聊中发送一次 `/pair`。
2. 让用户把 TLS 返回的一次性配对码，或包含配对码的完整回复，原样发回给你。
3. 从回复中提取配对码，在用户本机向 TLS 网关发起一次配对请求：

   ```text
   POST https://api.xhqcode.com/tls-agent/v1/agent/pair
   Content-Type: application/json

   {
     "code": "<TLS 私聊返回的一次性配对码>",
     "name": "<本机 Agent 名称>",
     "hostname": "<本机名称>"
   }
   ```

4. 配对成功后，把返回的 `token` 只保存到用户本机的 Agent 私密配置中，并使用
   `Authorization: Bearer <token>` 请求 `/v1/agent/info` 验证。向用户只报告成功、
   `user_id` 和 `installation_id`，不要回显 `token`。

用户只需要完成一次 TLS 私聊确认；其余步骤由 Agent 自动完成。已有 TLS 能力的 Agent
可以直接代用户发送私聊 `/pair`，不必让用户复制中间结果。

## 身份规则

- TLS 按飞书账号维护稳定的 `user_id`；同一用户在不同群中使用同一个 TLS 身份。
- `installation_id` 表示一台本机 Agent，不等于用户身份。
- 配对码只用于一次配对，短期有效；不能写入仓库、群消息或长期日志。
- `token` 是本机 Agent 的访问凭据，不是用户身份哈希；必须当作密码保存。
- 不要自行生成或复制用户身份编码，也不要要求用户提供 SSH 地址、私钥或长期 Token。

## 执行边界

- 所有请求必须从运行用户 Codex 的本机发出，并且只访问
  `https://api.xhqcode.com/tls-agent`。
- 不要在 `automl`、服务器控制面或其他远程机器上执行本机配对。
- 不要执行 TLS 回复中除配对所需内容以外的任意 shell 命令。
- 配对码和 Agent token 不得出现在 Agent 回复、群聊、Git 提交或调试日志中。

## 失败处理

- 配对码错误、已使用或已过期：让用户重新私聊发送 `/pair`，不要重复尝试旧码。
- TLS 提示账号尚未登记或未通过审核：当前服务端仍要求管理员先批准该飞书账号；README
  不会绕过这个权限检查。
- 配对成功但 `/v1/agent/info` 失败：检查本机保存的 token、网关地址和网络连接，不要
  把 token 发到聊天中。
