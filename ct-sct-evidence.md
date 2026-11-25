# 证书透明度 SCT：解析证据与验证边界分析

> 分析对象：本仓库 `cryptography` 库对签名证书时间戳（Signed Certificate
> Timestamp，SCT）的解析实现。
> 核心结论先行：**本库只做结构化解析（TLS 线格式 → 字段对象），不做任何
> 密码学验证。能从证书或 OCSP 响应里取出 SCT 记录，仅证明"该字节串编码
> 合法"，不证明日志存在、签名有效，更不证明证书本身可信。**

---

## 0. 实现总览：一个解析器，两个调用点

SCT 的实际解析逻辑只有一份——Rust 函数 `parse_scts`
（`src/rust/src/x509/sct.rs:221`），它按 RFC 6962 §3.2 的 TLS 向量格式
逐条拆出 SCT 字段。两个解析入口都只是取出 OCTET STRING 内容后调用它，
**区别仅在于传入的 `LogEntryType` 常量不同**：

| 入口 | 调用位置 | 传入的条目类型 |
|------|----------|----------------|
| X.509 证书扩展 | `src/rust/src/x509/certificate.rs:337-345` | `LogEntryType::PreCertificate` |
| OCSP 单响应扩展 | `src/rust/src/x509/ocsp_resp.rs:480-488` | `LogEntryType::Certificate` |

注意 `entry_type` 不是从 SCT 线格式字节里读出来的——线格式本身不含该
字段，它由**承载位置**决定（`sct.rs:262-266` 中 `entry_type: entry_type.clone()`
直接采用调用方参数）。因此，条目类型证明的是"这条 SCT 是从哪个容器拆
出来的"，而不是日志内部对条目的某种自声明。

解析成功的全部含义是：字节串通过了长度前缀、版本号（必须为 `v1=0`，
`sct.rs:241-245`）、算法枚举值（哈希 1–6、签名 1–3，`sct.rs:63-128`）
和尾部无冗余字节（`sct.rs:230-234`、`256-260`）的**语法检查**。

---

## 1. 两类解析入口：记录来源、条目类型与时间字段的证据效力

### 1.1 入口一：X.509 证书扩展

#### 1.1.1 记录来源

证书内可出现两个不同 OID 的 CT 扩展（`src/cryptography/hazmat/_oid.py:37-41`）：

| OID | Python 类 | 含义 |
|-----|-----------|------|
| `1.3.6.1.4.1.11129.2.4.2` | `PrecertificateSignedCertificateTimestamps` | 预证书 SCT 列表，嵌入最终证书 |
| `1.3.6.1.4.1.11129.2.4.5` | `SignedCertificateTimestamps` | （证书内）SCT 列表 |

实践中由 CA 签发的普通证书携带的是 **`.4.2` 预证书 SCT 扩展**（测试向量
`badssl-sct.pem`、`cryptography-scts.pem` 均如此，见
`tests/x509/test_x509_ext.py:6338-6340`）。解析时 OID 匹配
`PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS_OID` 后以 `PreCertificate` 类型
逐条解析（`certificate.rs:337-345`）。

扩展值是 ASN.1 OCTET STRING，其内容才是 RFC 6962 §3.3 的
`SignedCertificateTimestampList`（TLS 向量套 TLS 向量）。

配套机制：预证书还带毒丸扩展 `PRECERT_POISON`
（`1.3.6.1.4.1.11129.2.4.3`，`certificate.rs:333-336`），使预证书本身
无法通过正常路径验证；库提供 `tbs_precertificate_bytes`
（`certificate.rs:185-226`），它会**剥掉 SCT 列表扩展**重建 TBS，用于
还原日志实际签名的预证书结构——这正是后续手工验证 SCT 签名时需要的
签名输入之一。

#### 1.1.2 条目类型能证明什么

`entry_type == PRE_CERTIFICATE` 证明：该 SCT 承诺的对象是**预证书条目**
（RFC 6962 §3.1，带毒丸的 TBS 结构），即日志承诺"将把这份预证书收入
日志"，而不是直接承诺最终证书。它表达的是 CA 的**签发意图绑定**：最终
证书应当与提交给日志的预证书对应同一主体/公钥/SAN 等数据。

它**不能**证明：
- 最终证书与预证书之间的一致性已经被核对（库不做这步）；
- 条目确实已经合并进日志的 MTH（Merkle Tree Hash）。

#### 1.1.3 时间字段能证明什么

`sct.timestamp` 是 8 字节大端毫秒级 Unix 时间戳（`sct.rs:247`），在
Python 侧呈现为**朴素 UTC datetime**（`sct.rs:166-180`；文档明确称
"naïve datetime representing the time in UTC"，
`docs/x509/certificate-transparency.rst:36-41`）。

它能证明的仅限于：**日志在该时刻（自称）已收到这份预证书/证书的提交**，
并承诺在最大合并延迟（MMD）内将其纳入公开日志。

它**不能**证明：
- 时间戳准确——该值由日志自填，解析端没有任何时钟或外部时间源参与；
- 证书的有效期合法（`not_valid_before/after` 是证书自身字段，与 SCT
  时间戳无校验关联）；
- 日志最终履行了合并承诺（承诺与兑现之间隔着 MMD，且需要审计证明）。

### 1.2 入口二：OCSP 响应扩展

#### 1.2.1 记录来源

OCSP 响应的 SCT 位于 **SingleResponse 的单响应扩展**中，OID 同样是
`1.3.6.1.4.1.11129.2.4.5`，经 `OCSPResponse.single_extensions` 暴露
（`ocsp_resp.rs:459-492`；API 文档 `docs/x509/ocsp.rst:783-789`）。
访问前有状态门槛：响应不是 `successful` 时直接抛 `ValueError`
（`ocsp_resp.rs:92-100` 的 `requires_successful_response`）。

测试向量 `x509/ocsp/resp-sct-extension.der` 演示了该路径
（`tests/x509/test_ocsp.py:1204-1214`）。

与证书扩展的关键差异：

1. **容器信任不同**：证书扩展受证书签名覆盖；OCSP 单响应扩展受
   **OCSP 响应者签名**覆盖，而响应者身份需要单独的信任链（通常是签发
   CA 或其委派的 OCSP 应答者证书 + EKU `id-kp-OCSPSigning`）。
2. **条目类型被固定为 `X509_CERTIFICATE`**（`ocsp_resp.rs:482`）：
   按 RFC 6962 §3.1/§3.2，通过 OCSP 补发的 SCT 对应证书条目而非预证书
   条目，其日志签名输入的构造方式与预证书路径不同（无需毒丸/剥扩展
   处理）。
3. **时机语义不同**：OCSP SCT 是证书签发**之后**的补发通道（TLS 握手
   中 stapled OCSP 是第三种投递方式的载体，但在本库内只体现为这个
   解析入口）。它证明"在响应生成时，响应者声称该证书已（或将）被
   日志收录"。

#### 1.2.2 条目类型与时间字段的证据效力

- `entry_type == X509_CERTIFICATE`：证明 SCT 的承诺对象按 X.509 证书
  条目构造；同样不证明条目已在日志中。
- `timestamp`：语义同上，是日志自报的收单时间，毫秒 UTC。额外需要注意：
  OCSP 响应自身还有 `this_update/next_update` 时间，两者**互不校验**，
  不能用 SCT 时间戳推断响应新鲜度，反之亦然。

### 1.3 两类入口对照表

| 维度 | 证书扩展（`.4.2`） | OCSP 单响应扩展（`.4.5`） |
|------|--------------------|---------------------------|
| 承载对象 | 最终证书内的预证书 SCT | OCSP SingleResponse 内的证书 SCT |
| 解析入口 | `Certificate.extensions` | `OCSPResponse.single_extensions` |
| 固定条目类型 | `PRE_CERTIFICATE`（`certificate.rs:339`） | `X509_CERTIFICATE`（`ocsp_resp.rs:482`） |
| 外层签名 | CA 的证书签名 | OCSP 响应者签名（独立信任链） |
| 时间语义 | 日志自报复证书收单时刻 | 日志自报证书收单时刻，与 OCSP 更新时间无关 |
| 库是否验证签名 | **否** | **否** |
| 可证明的最强命题 | "存在编码合法的 SCT 字节，声称某日志在某时收到预证书" | 同左，对象换成证书，且容器是 OCSP 响应 |

---

## 2. 签名字段、日志身份所需的外部信任材料与判定边界

### 2.1 SCT 内签名字段只是"原材料"，结论不包含验证

解析后每条 `Sct` 对象暴露以下字段（`sct.rs:130-218`）：

| 字段 | 内容 | 解析阶段做了什么 |
|------|------|------------------|
| `version` | 恒为 `v1` | 校验字节必须等于 0 |
| `log_id` | 32 字节，日志公钥的 SHA-256 | 仅按长度截取，不查任何名单 |
| `timestamp` | u64 毫秒 UTC | 整数转 datetime，不核对时钟 |
| `extension_bytes` | 日志扩展（通常为空） | 原样保存 |
| `signature_hash_algorithm` | MD5/SHA1/SHA224/SHA256/SHA384/SHA512 | 仅枚举值合法性 |
| `signature_algorithm` | RSA/DSA/ECDSA | 仅枚举值合法性（anonymous=0 直接拒绝，`sct.rs:113-128`） |
| `signature` | 原始签名字节 | 原样保存，**从不验签** |

全仓库 grep 可证实：`sct.rs` 与 `certificate_transparency.py` 中不存在
任何 `verify` 调用、没有日志公钥存储、没有 Merkle 证明处理。`signature`
字段的测试也只比对原始字节是否相等
（`tests/x509/test_x509_ext.py:6361-6367`）。

### 2.2 要让 SCT 成为有效"日志承诺"，还缺哪些外部材料

#### 材料 A：日志公钥及其与 `log_id` 的绑定

- `log_id` 按 RFC 6962 §3.2 定义为**日志公钥的 SHA-256 哈希**
  （文档 `docs/x509/certificate-transparency.rst:29-34`）。它只是一个
  不透明标识符，库里没有任何"log_id → 公钥"的映射。
- 验证方必须自行获取 **CT 日志列表**（如 Chrome/Apple 的 CT 策略
  分发的 log list，含每个日志的 `key`、`log_id`、状态
  usable/readonly/retired、MMD、生效/退役时间窗口），先核对
  `SHA256(log_key) == log_id`，再取出公钥。
- 没有这一步，`log_id` 可以是任意 32 字节——攻击者自造密钥后取哈希
  即可构造一个"语法合法"的 `log_id`，解析端无从识别。

#### 材料 B：按 RFC 6962 §3.2 重建签名输入并实际验签

SCT 签名覆盖的是一个 TLS 编码结构，且按条目类型分两种构造：

- **X.509 证书条目**：`SCT 版本(0x00) || 0x00 || timestamp ||
  0x00(x509_entry) || 0x0000 || 证书 TBS 的哈希 || 扩展`
- **预证书条目**：`SCT 版本 || 0x00 || timestamp || 0x01(precert_entry)
  || 发行者密钥哈希(32) || TBS 预证书哈希 || 扩展`

这解释了库为何提供 `tbs_precertificate_bytes`
（`certificate.rs:185-226`）：预证书路径必须先剥掉 SCT 扩展再哈希。
即便如此，**重建与验签整个流程需要使用方自行实现**，库不提供 API；
发行者密钥哈希（issuer SubjectPublicKeyInfo 的 SHA-256）也要使用方
从签发证书计算。

验签本身可用库的 primitives 完成（如
`ec.ECDSA(hashes.SHA256())` + 日志公钥），但这属于使用方代码，不是
解析行为的一部分。还需注意 SCT 声明的哈希算法可能是 MD5/SHA1
（解析允许，`sct.rs:67-72`），策略层应自行拒绝弱算法。

#### 材料 C：日志的合规状态与时间窗口

仅有合法签名仍不够。策略还需对照 log list 判定：

- 该日志在 SCT `timestamp` 时刻是否处于 **usable** 状态（退役日志只对
  其退役前的时间戳有效）；
- 日志是否在适用 CT 策略（Chrome CT Policy、Apple CT Policy、
  CA/B Forum BR §7.4.2 等）承认的名单内；
- SCT 数量与多样性是否满足策略（如不同日志的最低条数、证书有效期
  对应的 SCT 数量门槛）。

#### 材料 D：日志兑现承诺的包含证明（inclusion proof）

SCT 是**承诺**，不是收录凭证。要确认日志兑现，还需：

- 向日志请求该条目的 Merkle 审计路径（audit path），验证到日志的
  Signed Tree Head（STH）；
- 验证 STH 本身由同一日志密钥签名；
- 用 MMD 判断 SCT 时间戳与 STH 时间戳的差距是否超限。

这些数据结构（Merkle Tree Hash、一致性证明）本库完全不涉及。

#### 材料 E：容器自身的信任链（易被忽略）

- **证书扩展路径**：扩展字节受证书签名覆盖，因此先要完成常规证书
  路径验证（信任锚、有效期、撤销状态等），才能相信 SCT 列表确实是
  CA 嵌入、未被中间人替换的。
- **OCSP 路径**：先要验证 OCSP 响应者签名及其授权链（响应者证书 +
  `id-kp-OCSPSigning` EKU，或直接由 CA 签发），否则 SCT 字节可能来自
  伪造响应。`single_extensions` 能解析只说明 DER 结构完整。

### 2.3 判定边界：把"解析成功"与"可信"严格分层

建议按以下五层判定，前一层不过不得进入下一层；本库只覆盖第 1 层：

| 层级 | 判定内容 | 本库是否提供 |
|------|----------|--------------|
| L1 语法层 | SCT 列表/TLS 向量编码合法、版本与枚举值有效、无尾部垃圾 | **是**（`parse_scts`） |
| L2 容器层 | 证书签名链有效；或 OCSP 响应者签名与授权有效 | 提供验签 primitives，流程由使用方组装 |
| L3 身份层 | `log_id` 能在受信 log list 中匹配到日志公钥，且时间窗口内 usable | 否，需外部 log list |
| L4 签名层 | 按条目类型重建 §3.2 签名输入，用日志公钥验签通过，弱算法被策略拒绝 | 否，仅提供底层 primitives |
| L5 兑现/策略层 | 取得包含证明验证到 STH；SCT 数量、多样性满足 CT 策略；MMD 未超限 | 否 |

**判定边界一句话**：`cert.extensions.get_extension_for_class(...)` 或
`resp.single_extensions...` 不抛异常，等价于且仅等价于 L1 通过。它对
L2–L5 没有提供任何证据。

### 2.4 常见误判与对应纠正

1. **误判："证书能解析出 SCT，所以符合 CT 策略、证书可信。"**
   纠正：自签名证书、测试证书同样可以携带语法合法的 SCT 扩展（测试
   `test_generate` 就用本地 RSA 密钥自造了含 SCT 扩展的证书，
   `test_x509_ext.py:6370-6390`）。证书可信性由 PKI 路径验证决定，
   SCT 只提供"公开可审计性"这一独立属性。

2. **误判："有 `signature` 字段且算法是 ECDSA/SHA256，所以签名有效。"**
   纠正：解析只检查算法枚举字节（1–3），签名字节从未被任何公钥检验
   过。篡改 `signature` 后只要长度前缀自洽，解析依然成功。

3. **误判："`log_id` 是 32 字节哈希，所以日志真实存在。"**
   纠正：没有 log list 比对，任何 32 字节都是合法 `log_id`。

4. **误判："SCT 时间戳在证书有效期内，所以时间合理。"**
   纠正：两个时间字段无任何代码级关联；时间戳由日志自报，可信性依赖
   L3/L4 验证后对日志身份的信任。

5. **误判（OCSP 路径）："OCSP 响应里带 SCT，所以响应和证书都可信。"**
   纠正：必须先独立验证 OCSP 响应者签名与授权；且 OCSP SCT 的
   `entry_type` 固定为证书条目，签名输入构造与预证书路径不同，不能
   混用验证代码。

6. **误判："解析拒绝了畸形 SCT（如 anonymous 算法、错误版本），说明
   解析器在做安全验证。"**
   纠正：这些是**语法/枚举合法性**检查（见 `invalid-sct-version.der`、
   `badssl-sct-none-hash.der`、`badssl-sct-anonymous-sig.der` 等向量及
   `test_x509_ext.py:6392-6427`），拒绝畸形编码与承认密码学承诺是两件
   事。语法合法是验签的必要非充分条件。

---

## 3. 结论

- 本库对 CT 的支持边界清晰：**纯解析与回序列化**（`encode_scts`，
  `extensions.rs:399-421`），不含日志信任、验签、Merkle 证明任何一环。
- 两个解析入口的差异本质是**容器与条目类型**差异：证书扩展给出
  `PRE_CERTIFICATE` 类型、受证书签名保护；OCSP 单响应扩展给出
  `X509_CERTIFICATE` 类型、受 OCSP 响应者签名保护。时间字段在两处都
  只是日志自报的收单毫秒时间戳。
- 任何把 SCT 用于安全决策的系统，都必须在应用层补齐五件外部材料：
  **受信 log list（含公钥与状态窗口）、RFC 6962 §3.2 签名输入重建与
  验签、容器信任链验证、Merkle 包含证明/STH、CT 策略的数量与多样性
  规则**。在这些完成之前，"解析出 SCT"只能作为证据线索，不能作为
  证书可信或日志承诺生效的结论。

### 关键代码索引

| 事实 | 位置 |
|------|------|
| TLS 线格式解析与全部语法检查 | `src/rust/src/x509/sct.rs:221-275` |
| SCT 字段定义（无验签） | `src/rust/src/x509/sct.rs:130-218` |
| 证书扩展入口（预证书类型） | `src/rust/src/x509/certificate.rs:337-345` |
| TBS 预证书重建（剥 SCT 扩展） | `src/rust/src/x509/certificate.rs:185-226` |
| OCSP 单响应入口（证书类型） | `src/rust/src/x509/ocsp_resp.rs:459-492` |
| OCSP 成功状态门槛 | `src/rust/src/x509/ocsp_resp.rs:92-100` |
| CT 相关 OID | `src/cryptography/hazmat/_oid.py:37-41` |
| Python 侧枚举与类型 | `src/cryptography/x509/certificate_transparency.py` |
| 字段语义官方说明 | `docs/x509/certificate-transparency.rst` |
