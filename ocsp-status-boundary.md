# OCSP 状态边界分析：请求级响应状态 vs 单张证书吊销状态

## 1. 两个互不隶属的状态层级

OCSP（RFC 2560 / RFC 6960）在本仓库中被建模为**两个独立的枚举**，分别回答两个不同的问题：

| 层级 | 类型 | 定义位置 | 回答的问题 |
|------|------|----------|------------|
| 请求级（response-level） | `OCSPResponseStatus`（SUCCESSFUL / MALFORMED_REQUEST / INTERNAL_ERROR / TRY_LATER / SIG_REQUIRED / UNAUTHORIZED） | `src/cryptography/x509/ocsp.py:24` | 响应者**是否处理了这个请求** |
| 证书级（per-certificate） | `OCSPCertStatus`（GOOD / REVOKED / UNKNOWN） | `src/cryptography/x509/ocsp.py:49` | 在请求被成功处理的前提下，**某一张证书**的吊销状态 |

关键事实：**`OCSPResponseStatus.SUCCESSFUL` 只表示"响应者成功给出了答复"，绝不表示"证书有效"**。证书有效与否只能由成功响应内 `SingleResponse.cert_status` 的 `OCSPCertStatus` 表达。ASN.1 结构也体现了这一点：`OCSPResponse.responseBytes` 是 `OPTIONAL` 的（`src/rust/cryptography-x509/src/ocsp_resp.rs:11-14`），失败响应根本没有承载证书状态的容器。

## 2. 解析行为：`load_der_ocsp_response` 的边界强制

`src/rust/src/x509/ocsp_resp.rs:20-73` 在加载时就把两个层级的一致性校验完毕：

- **状态为 SUCCESSFUL 但缺少 `responseBytes`** → 直接 `ValueError("Successful OCSP response does not contain a BasicResponse")`。此类报文**根本无法构造出 `OCSPResponse` 对象**，不存在"加载成功后再判断"的窗口。
- **状态为任一失败码但携带了 `responseBytes`** → `ValueError("Unsuccessful OCSP response contains a BasicResponse")`。防止把失败响应里夹带的（可能伪造的）证书状态泄露给调用方。
- **未知状态码**（不在 0/1/2/3/5/6 内）→ `ValueError("OCSP response has an unknown status code")`。
- **`ResponseData.version != 0`** → `ValueError`，拒绝不认识的响应版本。

也就是说，解析层保证了：**任何成功返回的 `OCSPResponse` 对象，其 `response_status` 与是否含有 `BasicResponse` 必然一致**。

## 3. 构造行为：两条互斥的路径

- **失败响应**：`OCSPResponseBuilder.build_unsuccessful(response_status)`（`ocsp.py:364-375`）拒绝 `SUCCESSFUL`，且 `create_ocsp_response`（`ocsp_resp.rs:699-706`）对非成功状态直接写出 `response_bytes: None`——**不签名、无 responder_id、无任何证书字段**。
- **成功响应**：`OCSPResponseBuilder.sign()`（`ocsp.py:350-362`）强制要求先 `add_response`（恰好一个 `SingleResponse`）和 `responder_id`，产出的状态恒为 `SUCCESSFUL`。`_SingleResponse`（`ocsp.py:55-110`）进一步约束：`revocation_time`/`revocation_reason` 仅在 `cert_status is REVOKED` 时允许提供，且 REVOKED 时 `revocation_time` 必填。

构造侧同样保证两个层级不会被混写。

## 4. 三类响应各自能向调用方提供什么

### 4.1 失败响应（MALFORMED_REQUEST / INTERNAL_ERROR / TRY_LATER / SIG_REQUIRED / UNAUTHORIZED）

**可提供**：仅 `response_status`（以及 `public_bytes` 回读原始 DER）。

**必须明确失败的访问**：所有依赖 `BasicOCSPResponse` 的属性都经由 `requires_successful_response()`（`ocsp_resp.rs:92-101`）守卫，统一抛出
`ValueError("OCSP response status is not successful so the property has no value")`，包括：

- 响应者信息：`responder_name`、`responder_key_hash`、`produced_at(_utc)`
- 签名材料：`signature`、`signature_algorithm_oid`、`signature_hash_algorithm`、`tbs_response_bytes`、`certificates`
- 证书状态：`certificate_status`、`serial_number`、`issuer_key_hash`、`issuer_name_hash`、`hash_algorithm`、`this_update(_utc)`、`next_update(_utc)`、`revocation_time(_utc)`、`revocation_reason`
- 扩展：`extensions`、`single_extensions`、`responses` 迭代器

**判定依据**：失败响应在 ASN.1 层面没有 `BasicOCSPResponse`，这些字段**在报文中物理不存在**。返回 `None` 或默认值会制造"字段存在但为空"的假象，抛异常是唯一不撒谎的选择。

### 4.2 缺少可解析内容的"成功"响应

此类报文（`response_status = successful` 但无 `responseBytes`，或 version 非法）在**加载阶段即被拒绝**（见第 2 节），调用方拿到的是 `ValueError` 而非对象。这是刻意的 fail-closed 设计：一个自称成功却没有内容的响应是不可信的，绝不允许它进入"属性访问"阶段被误读。

### 4.3 合法的成功响应（含吊销响应）

- **响应者信息**：`responder_name`（ByName 时）或 `responder_key_hash`（ByKey 时），二者互斥、另一个为 `None`（`ocsp_resp.rs:158-184`）；另有 `produced_at_utc`、签名与内嵌证书链。
- **证书状态**：`certificate_status` ∈ {GOOD, REVOKED, UNKNOWN}。
  - REVOKED：`revocation_time(_utc)` 返回 `datetime`；`revocation_reason` 返回 `ReasonFlags` 或 `None`（报文中 reason 可选，`ocsp_resp.rs:642-655`）。
  - GOOD / UNKNOWN：`revocation_time(_utc)` 与 `revocation_reason` 均为 `None`（`ocsp_resp.rs:651-668`）。
- **多单响应边界**：便捷属性（`certificate_status` 等）仅在响应**恰好含 1 个** `SingleResponse` 时可用，否则抛 `ValueError` 并提示改用 `.responses` 迭代器（`ocsp_resp.rs:557-572`）。

## 5. 兼容建议与判定依据

### 5.1 不把缺失信息误判为有效证书

1. **判定顺序不可颠倒**：必须先检查 `resp.response_status is OCSPResponseStatus.SUCCESSFUL`，再读取 `certificate_status`。任何"先读证书状态、异常就当 GOOD"的写法都会把 TRY_LATER/UNAUTHORIZED 等失败响应误判为证书有效——这正是 `requires_successful_response` 抛异常而非返回 `None` 要防的错误。
2. **`None` 不是状态**：`revocation_time is None` 同时适用于 GOOD 和 UNKNOWN，绝不能据此推断证书有效；`responder_name is None` 只说明使用了 ByKey 编码，不说明响应者缺失。
3. **UNKNOWN ≠ GOOD**：`OCSPCertStatus.UNKNOWN` 表示响应者对该证书没有记录，调用方应按各自策略处理（通常视为不可确认有效），不得与 GOOD 合并。
4. **加载期异常即终态**：对"成功但无内容"的报文，`load_der_ocsp_response` 的 `ValueError` 就是最终结论，调用方不应捕获后降级为"证书状态未知但可用"。

### 5.2 保留既有读取契约

- **失败响应的属性访问继续抛 `ValueError`**，不要改为返回 `None`。理由：(a) 字段在报文中不存在，异常如实反映缺失；(b) 现有调用方以 `try/except ValueError` 或前置 `response_status` 检查为契约，静默返回 `None` 会让"未检查状态就读属性"的代码从"立刻报错"退化为"拿到空值后继续走有效分支"，属于安全语义降级；(c) 类型存根（`ocsp.pyi`）中这些属性返回非 Optional 类型，返回 `None` 会破坏类型契约。
- **构造侧约束保持不变**：`build_unsuccessful` 继续拒绝 `SUCCESSFUL`，`sign()` 继续要求恰好一个响应和 responder_id，REVOKED 继续强制 `revocation_time`。这些约束把"混用两个层级"的错误挡在构造期。
- **签名验证责任在调用方**：本库只解析与构造，不验证 `BasicOCSPResponse` 的签名或响应者授权。即使 `response_status` 与 `certificate_status` 都"正常"，调用方仍须自行验证签名、responder 身份及 `this_update`/`next_update` 时效，否则以上所有状态判定都建立在未认证的报文上。

### 5.3 推荐调用模式

```python
resp = ocsp.load_der_ocsp_response(data)          # 加载期已拒绝畸形/自相矛盾报文
if resp.response_status is not ocsp.OCSPResponseStatus.SUCCESSFUL:
    ...                                            # 失败响应：只有 response_status 可读
elif resp.certificate_status is ocsp.OCSPCertStatus.GOOD:
    ...                                            # 唯一可视为"未吊销"的分支
elif resp.certificate_status is ocsp.OCSPCertStatus.REVOKED:
    resp.revocation_time_utc, resp.revocation_reason
else:                                              # UNKNOWN
    ...                                            # 不得当作有效
```

## 6. 结论

本仓库通过**加载期一致性校验**（状态与 `responseBytes` 互斥强制）、**属性访问守卫**（`requires_successful_response`）和**构造期互斥路径**（`build_unsuccessful` vs `sign`）三层机制，把"请求是否被处理"与"证书是否被吊销"严格隔离。兼容性上应维持"缺失即抛异常"的读取契约，任何将缺失信息默认值化、可选化的改动都会打开把失败/未知误判为有效证书的缺口。
