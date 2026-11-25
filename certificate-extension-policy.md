# X.509 证书链扩展约束与策略误接纳分析

- 分析提交：`128a4324ca923cf4b6a977ef736e7e63502f787b`（`51.0.0-dev1`）
- 分析对象：`cryptography.x509.verification` 及其 Rust 实现 `cryptography-x509-verification`
- 方法：静态源码与仓库内测试分析；未执行 `nox` 或动态 PoC。行号对应该提交。

## 1. 核心结论

1. **当前公开高级验证 API 是仓库内 Rust 路径构建器，不是 OpenSSL 的 `X509_verify_cert()`。** Python 层 `cryptography/x509/verification.py:25-34` 只是重新导出 PyO3 类；核心逻辑在 `src/rust/cryptography-x509-verification/src/`。虽然 `src/_cffi_src/openssl/x509_vfy.py` 声明了 OpenSSL 验证函数，但在 `src/`、`tests/` 中未发现本 API 对 `X509_verify_cert`、`X509_STORE_CTX_init` 等的调用点。因此不能把 OpenSSL 自身的链验证行为当作本实现的行为。

2. **认证成功是一条候选路径上多项条件的合取，而不是单个扩展或回调决定。** 终端证书先过 EE profile 和服务器身份匹配；每个候选签发者再过 CA profile、算法与签名验证；CA 的 `nameConstraints` 沿名称链累积生效；最终必须有一个候选证书与 `Store` 中的信任锚精确相等。见 `lib.rs:303-313`、`lib.rs:419-566`、`policy/mod.rs:528-606`。

3. **有些约束是硬编码、回调无法关闭的；另一些只是默认可替换回调。**
   - 不可通过扩展回调关闭：签名验证、Store 信任锚、服务器目标 SAN 匹配、CA `basicConstraints.cA=true` 与 `pathLenConstraint`、名称约束引擎、未登记关键扩展拒绝、算法白名单和签发者 RSA 强度。
   - 可被同名配置覆盖而失去内置内容检查：EE 的 `cA=false`、EE/CA 的 EKU 内容、EE/CA 的 KeyUsage 内容、SAN 关键级别规则、CA AKI/NC/AIA 的内置解析检查。原因是 `with_validator()` 会整体替换该 OID 的 `ExtensionValidator`，不是在旧检查之外追加回调（`policy/extension.rs:217-240`）。

4. **信任锚不是“完全不检查扩展”，但它的自签名和上层链不再验证。** 正常路径中，Store 里的根在被选作签发者时仍经过 `permits_ca()`：有效期、v3、BC、CA 扩展策略、SPKI 算法/RSA 长度以及“它是否签了子证书”都会检查（`policy/mod.rs:447-491`、`528-606`）。递归到该锚后，名称约束仍会执行，然后 `store.contains()` 终止（`lib.rs:427-466`）。不再检查的是信任锚自身的签名和它之上的签发关系——这是信任锚的定义。

5. **Python 验证回调只是否决门，不是信任源。** 回调签名只有 `(policy, certificate, extension)`；它不能把证书加入 Store、不能改变链构建、不能指定替代信任锚，也看不到最终完整链或“当前证书是否恰为 Store 成员”。回调抛异常或返回非 `None` 都会使验证失败（`src/rust/src/x509/verify/extension_policy.rs:149-241`）。反之，传 `validator_cb=None` 或空操作函数意味着调用者接管该 OID 的全部语义校验。

6. **最需要优先辨认的误接纳面是：**
   - 把 `ClientVerifier` 的“链可信”误当成“客户端身份/账户已授权”；
   - 使用 `ExtensionPolicy.permit_all()`，或用 `None`/空回调覆盖 `BasicConstraints`、`KeyUsage`、`ExtendedKeyUsage`；
   - 把叶子或中间证书直接放进 `Store`，使管理员信任束变成逐证书白名单；
   - 长生命周期 verifier 未显式固定/刷新 `.time()`，导致构建后过期的证书仍按构建时判定；
   - 把该 API 的成功结果误解为“未吊销”；本实现没有接入 CRL/OCSP；
   - 依赖 directoryName/Subject DN 名称约束或公共后缀边界，但这些正是源码明确未完整实现或测试中跳过的领域。

---

## 2. 一次验证的实际决策顺序

入口 `cryptography_x509_verification::verify()` 创建 `ChainBuilder` 和签名/名称约束预算，然后从 leaf 开始（`lib.rs:303-313`）。

### 2.1 叶子阶段

`build_chain()` 首先解析 leaf 扩展并调用 `permits_ee()`（`lib.rs:568-590`）：

1. `permits_basic()` 对所有证书硬性检查：
   - X.509 v3（内部版本值为 `2`）；
   - 外层 `signatureAlgorithm` 与 TBS 内算法一致；
   - 序列号长度/负值规则；
   - issuer 非空；
   - 有效期编码和验证时间，边界时间均视为有效（`not_before <= time <= not_after`）。
   - 见 `policy/mod.rs:385-445`。
2. 如果是 `build_server_verifier(subject)`，`PolicyDefinition.subject=Some(...)`，则**独立于 EE 扩展策略和回调**解析并匹配 SAN；缺少 SAN 或无匹配名称均失败（`policy/mod.rs:501-508`、`627-644`）。
3. 执行 `ee_extension_policy.permits()`，包括关键级别、存在性、未识别关键扩展兜底和已配置回调（`policy/extension.rs:242-349`）。

### 2.2 名称约束与信任锚终止

进入 `build_chain_inner()` 后，当前证书自带的 `nameConstraints` 会先被解析并应用到已累积的 `NameChain`，之后才判断是否为 Store 成员（`lib.rs:427-466`）。

- 初始 `NameChain` 包含 leaf 自身 SAN（`lib.rs:584-589`），所以自定义 EE 策略即使允许 leaf 带 NC，NC 引擎仍会执行。
- 每上溯一层，新 CA 的 SAN 节点和指向下层名称链的 child 节点被加入；CA NC 因而能约束其下游证书 SAN（`lib.rs:145-165`、`517-527`）。
- 仅当 `issuer == subject` 名称相等时将证书视为 self-issued，并在构造名称链时省略其 SAN（`certificate.rs:9-11`、`lib.rs:156-162`）。这是名称相等判断，不额外验证“自签名”。
- 随后 `Store::contains()` 使用 subject 索引加证书结构相等判断；命中即成功终止（`trust_store.rs:29-40`、`ops.rs:48-52`）。

### 2.3 候选签发者阶段

若当前证书不是信任锚，则检查深度并通过 `potential_issuers()` 收集候选（`lib.rs:468-480`）：

- Store 中 subject 相同的证书；
- 调用方提供的 `intermediates` 中 subject 相同的证书；
- 仅用 AKI/SKI 做候选排序，不把 AKI/SKI 不匹配作为拒绝条件（`lib.rs:382-415`）。
- 不会从 AIA、网络或其他位置获取签发者；候选集合只有 Store 和入参 intermediates（`lib.rs:373-380`）。

对每个候选签发者调用 `valid_issuer()`（`policy/mod.rs:528-606`）：

1. `permits_ca()`：
   - 同样执行 `permits_basic()`；
   - 硬性要求存在 `basicConstraints`；
   - 解析 BC，检查 `pathLenConstraint` 和 `cA=true`；
   - 执行 CA `ExtensionPolicy`。
2. 检查签发者 SPKI 算法是否在硬编码白名单。
3. 检查**子证书**的签名算法是否在白名单。
4. 加载签发者公钥；RSA 签发者密钥必须至少 2048 位。
5. 消耗签名预算并实际调用后端验证子证书签名。

一个候选失败通常记录为 `last_err` 后继续尝试下一个候选；只有部分 `FatalError`（如名称约束预算/特定严重错误）会立即中止（`lib.rs:480-545`）。因此最终错误中的 “candidates exhausted” 表示所有可能路径均失败。

---

## 3. 关键扩展的责任矩阵

默认 CA 策略见 `policy/extension.rs:85-147`，默认 EE 策略见 `policy/extension.rs:149-205`。

| 扩展 | EE 默认行为 | CA 默认行为 | 硬检查 / 可覆盖边界 |
|---|---|---|---|
| `basicConstraints` | 可选、关键级别不关心；内置回调拒绝 `cA=true`（`extension.rs:187-192`, `559-575`） | 必须存在且必须 critical；内容硬检查在 `permits_ca()` 中（`extension.rs:122-127`; `policy/mod.rs:462-486`） | CA 的存在性、`cA=true`、pathLen 不能被回调关闭；构造 verifier 时还要求 CA 策略中 BC 是 `Present`（`policy/mod.rs:296-303`）。EE 的 `cA=false` 仅由可替换回调负责 |
| `keyUsage` | 可选；若存在，内置回调拒绝 `keyCertSign`（`extension.rs:172-177`, `630-646`） | 必须存在，关键级别不关心；内置回调要求 `keyCertSign=true`（`extension.rs:111-116`, `702-716`） | **没有**独立于回调的 KU 硬检查。用 `None`/空回调覆盖后，CA 无 `keyCertSign` 或 EE 带 `keyCertSign` 都可能被接受 |
| `extendedKeyUsage` | 可选、必须 non-critical；若存在，必须含 `serverAuth`（server）或 `clientAuth`（client）（`extension.rs:197-201`, `604-628`） | 可选、non-critical；若存在，必须含策略 EKU 或 `anyExtendedKeyUsage`（`extension.rs:139-143`, `750-770`） | EKU OID 固定在 `PolicyDefinition` 中，无 Python builder 入口；但实际内容检查只在默认可替换回调中。扩展策略被覆盖后，`policy.extended_key_usage` 属性仍显示 server/clientAuth，却可能已无强制效果 |
| `subjectAltName` | 默认必须存在、关键级别不关心；内置回调执行“空 subject 时必须 critical；非空 subject 时必须 non-critical”的规则（`extension.rs:182-186`, `577-602`） | 可选、无内容回调 | Server 目标名称匹配是硬检查，且构造 server verifier 时要求 EE 策略的 SAN 为 `Present`（`policy/mod.rs:305-316`）。Client 无目标主体，默认策略仍要求 SAN，但可通过 `permit_all()` 放宽为可缺失 |
| `nameConstraints` | 默认 `require_not_present`（`extension.rs:193-194`） | 可选、关键级别不关心；默认回调要求 permitted/excluded 至少一个非空（`extension.rs:128-134`, `718-748`） | 只要 NC 存在，`lib.rs` 的 NC 引擎总会解析和执行；自定义回调不能关闭引擎。把 CA 策略改成 `require_not_present(NC)` 会使带 NC 的 CA 被拒绝，而不是“忽略 NC” |
| `authorityKeyIdentifier` | 默认必须存在且 non-critical，但无内容回调（`extension.rs:161-166`） | 可选、non-critical；若存在，默认回调要求含 `keyIdentifier`（`extension.rs:97-102`, `659-700`） | AKI/SKI 只影响候选排序，不强制匹配；覆盖回调只会丢失格式检查，不会把 AKI 变成链绑定条件 |
| `subjectKeyIdentifier` | 可选、无检查 | 可选；CABF 倾向要求但实现选择兼容旧 CA（`extension.rs:103-110`） | 仅参与候选排序 |
| AIA | 可选、non-critical，若存在则解析检查格式 | 同 EE | 不执行 AIA fetching、不自动下载证书/OCSP/CRL |
| 未知扩展 | 若 critical 且没有为其 OID 登记 validator，拒绝：`unaccounted-for critical extensions`（`extension.rs:297-310`） | 同左 | `permit_all()` **并不会**允许任意未知 critical 扩展；它只把八个内置 OID 设成 `MaybePresent/Agnostic/None`（`extension.rs:58-83`）。只有显式为该 OID 配置 validator 后才算“已交代” |

### 3.1 SAN 与身份匹配

Server 身份匹配只看 SAN 中的 DNS/IP，不使用 Subject CN（`policy/mod.rs:205-227`）：

- DNS 比较大小写不敏感；
- 只接受普通域名或最左侧单个 `*.` 通配标签；
- `*.example.com` 匹配 `foo.example.com`，不匹配 `example.com` 或 `foo.bar.example.com`；
- 非法 DNS pattern 返回不匹配，而不是放行；
- IP 按 4/16 字节地址精确比较。

源码中没有 public suffix list 检查；仓库测试清单明确跳过 `pedantic-public-suffix-wildcard`（`tests/x509/verification/test_limbo.py:24-28`）。因此 `*.co.uk` 这类通配证书若由 CA 合法签发，本验证器会按单层标签规则接受。

Client verifier 的 `PolicyDefinition.subject` 为 `None`（`policy/mod.rs:327-343`），所以**没有“期望客户端身份”参数，也没有账户授权判断**。成功后 `VerifiedClient.subjects` 返回 leaf SAN 供应用使用（`src/rust/src/x509/verify/mod.rs:357-376`）。应用必须自行把这些名称绑定到用户、设备或权限。

### 3.2 名称约束的已实现与未实现范围

已实现的匹配类型是 DNS、IP 和 RFC822（`lib.rs:176-226`）：

- DNS permitted 使用子树包含；通配 SAN 的 permitted 采用“必须允许通配展开后的全部名称”语义。
- DNS excluded 对通配 SAN 采用“子树有任何重叠即排除”的语义。
- IP 支持 IPv4/IPv6 CIDR 掩码和连续掩码校验。
- RFC822 支持精确邮箱、裸域名（仅该域）和 `.example.com` 形式（严格子域）。

明确缺口：

- `directoryName` 匹配未实现。若 critical NC 含 directoryName，直接硬失败（`lib.rs:430-457`；测试 `test_critical_dirname_constraint_rejected`）。
- 非 critical directoryName 约束在 leaf 含 directoryName SAN 时会因 unsupported 报错；若没有 directoryName SAN，则该约束被忽略（`lib.rs:227-240`；测试 `test_noncritical_dirname_constraint_with_dirname_san`、`test_noncritical_dirname_constraint_ignored`）。
- `NameChain::new()` 只读取 `SubjectAlternativeName`（`lib.rs:156-162`），没有从 Subject DN 的 CN、emailAddress 等属性构造待匹配名称。因此除上述 critical directoryName 兜底外，Subject DN 命名空间不会被完整约束。
- 其他 GeneralName 类型只有在“约束类型与 SAN 类型相同”时进入 unsupported 错误；类型不匹配时为 `Skipped`（`lib.rs:227-241`）。
- Limbo 清单也声明 `name-constraint-dn`、`has-policy-constraints`、`has-crl` 等特性不受支持（`tests/x509/verification/test_limbo.py:24-48`）。

---

## 4. 信任锚的准确责任边界

`Store` 在 Python 层要求至少一个证书（`src/rust/src/x509/verify/mod.rs:516-530`），Rust 层按 subject 建 HashMap（`trust_store.rs:16-27`）。

可以由源码证实的结论：

1. **Store 中每个证书都是平等、预先信任的锚。** Store API 没有名称范围、EKU 范围、指纹 pin、用途限制或“仅某 CA 可签发某主体”的字段。最小信任范围必须由调用方选择正确的证书集合来实现。
2. **命中 Store 的判定是解析后证书结构相等。** 仅 subject/issuer 名称相同不够；`Store::contains()` 还要求证书相等（`trust_store.rs:29-39`; `ops.rs:48-52`）。
3. **正常 CA 锚仍受有效期和扩展策略约束。** 它是子证书的候选签发者，因此先经过 `valid_issuer() -> permits_ca()`，包括 BC、CA 扩展策略、SPKI 算法/RSA 长度，并用其公钥验证子证书签名。
4. **锚自身签名不验证。** 代码只验证 `child` 被 `issuer` 签署；注释明确指出 root 自身的签名检查可豁免，因为非 root issuer 会在后续递归中作为 child 被检查（`policy/mod.rs:553-558`）。到达 `store.contains()` 后立即返回，不再为锚寻找 issuer。
5. **若初始 leaf 本身就是 Store 成员，则走 EE 路径后直接终止。** 这时不会调用 `permits_ca()`（`lib.rs:578-590` → `462-466`）。默认 EE 策略会通过回调拒绝 `cA=true`，但放宽 EE 策略后，一个 CA 证书若被显式放入 Store 并作为 leaf 传入，可按 EE 配置成功。测试 `TestClientVerifier.test_verify` 已展示 leaf 同时作为 Store 唯一成员时返回 `[leaf]`（`tests/x509/verification/test_verification.py:142-183`）。
6. **把中间证书加入 Store 会把它提升为信任锚。** 链到该证书即终止，不再验证其上级签发关系。这是 Store 的预期语义，也是配置审计重点。

---

## 5. 验证回调的能力与盲区

Python 侧通过 `require_present()`、`may_be_present()`、`require_not_present()` 配置扩展策略（`src/rust/src/x509/verify/extension_policy.rs:107-147`）。

### 5.1 回调能做什么

- 对已存在扩展执行任意 Python 校验；
- 对 `may_be_present()` OID 在扩展缺失时收到 `ext=None`，从而决定缺失是否可接受；
- 通过抛异常否决验证；
- 返回 `None` 表示无异议；返回其他值会触发 “Python validator must return None” 错误（`extension_policy.rs:223-241`；测试 `test_custom_cb_no_retval_enforced`）。
- 对无法解析为已知 Python 类型的扩展，以 `UnrecognizedExtension` 传入，而不是变成 `None`（`extension_policy.rs:193-221`；测试 `test_unparseable_extension_passed_as_unrecognized`）。

### 5.2 回调不能做什么

- 不能添加信任锚或改变 `Store`；
- 不能跳过签名验证、服务器 SAN 硬匹配、CA BC 硬检查或 NC 引擎；
- 不能查看完整最终链；参数只有当前 `Policy`、当前 `Certificate`、当前扩展；
- `Policy` Python 对象只暴露 depth、subject、time、EKU、RSA minimum 等属性，不暴露 Store（`src/rust/src/x509/verify/policy.rs:12-45`）；
- 不能“追加”到默认回调。对同一 OID 调用 builder 方法会替换 Rust 字段；重复配置同一 OID 还会报错（`policy/extension.rs:217-240`；测试 `test_builder_methods`）。

因此，“我传了回调”并不自动等于“保留了内置 WebPKI 检查”。如果你从 `webpki_defaults_ee()` 出发并对 `BasicConstraints` 调用 `.require_present(..., None)`，新 validator 只检查存在性和关键级别，旧的 `cA=true` 拒绝回调已被替换掉。若要保留语义，必须在自己的 Python 回调中重新实现这些内容检查。

---

## 6. 可导致“策略配置误接纳”的模式

### F1. 把 ClientVerifier 的链验证误当成身份授权【高】

危险形态：

```python
verifier = PolicyBuilder().store(store).build_client_verifier()
verified = verifier.verify(peer_cert, intermediates)
# 没有检查 verified.subjects，也没有把 SAN 绑定到账户/设备
allow_login()
```

源码证实 client policy 的 `subject=None`，没有目标名称可匹配（`policy/mod.rs:327-343`）。默认策略仍要求 SAN 存在、EKU 含 `clientAuth`（若 EKU 存在），但“由受信 CA 签发的某个客户端证书”不等于“该客户端有权访问此账户”。

**辨认/补偿：** 搜索 `build_client_verifier`；确认调用方在 `verify()` 后检查 `VerifiedClient.subjects` 或证书中的其他身份，并执行授权映射。

### F2. `ExtensionPolicy.permit_all()` 放宽 EE 角色和用途【高】

Client 场景可直接构造：

```python
PolicyBuilder().store(store).extension_policies(
    ca_policy=ExtensionPolicy.webpki_defaults_ca(),  # BC 仍必须 Present
    ee_policy=ExtensionPolicy.permit_all(),
).build_client_verifier()
```

仓库测试明确证实：无 SAN 证书在默认 client policy 下失败，但在 `ee_policy=permit_all()` 后成功，且 `verified_client.subjects is None`（`test_verification.py:763-796`）。

此配置还会移除 EE BC/EKU/KU 的内置内容回调，因此在证书仍满足硬性有效期、签名、未知 critical 兜底等条件时：

- 缺失/错误 EKU 可接受；
- KU 含 `keyCertSign` 可接受；
- `basicConstraints.cA=true` 不再由 EE 回调拒绝；
- SAN critical/subject-empty 规则不再检查。

Server 场景不能直接使用裸 `permit_all()`，因为构造时要求 SAN validator 为 `Present`。但以下配置可绕过 EE 的 BC/EKU/KU 内容检查，同时保留硬编码 SAN 名称匹配：

```python
ee_policy = (
    ExtensionPolicy.permit_all()
    .require_present(x509.SubjectAlternativeName, Criticality.AGNOSTIC, None)
)
PolicyBuilder().store(store).extension_policies(
    ca_policy=ExtensionPolicy.webpki_defaults_ca(),
    ee_policy=ee_policy,
).build_server_verifier(DNSName("target.example"))
```

此时目标 SAN 不匹配仍会被硬检查拒绝；但一个带匹配 SAN、`cA=true` 或用途异常的 leaf 可能通过 EE 扩展策略。

**辨认：** 搜索 `ExtensionPolicy.permit_all`；审查其是否同时用于 EE、是否补回 BC/KU/EKU 语义回调。

### F3. 用 `None`/空操作覆盖内置内容回调【高】

典型危险写法：

```python
ee_policy = ExtensionPolicy.webpki_defaults_ee().require_present(
    x509.BasicConstraints, Criticality.AGNOSTIC, None
)

ca_policy = ExtensionPolicy.webpki_defaults_ca().may_be_present(
    x509.KeyUsage, Criticality.AGNOSTIC, lambda policy, cert, ext: None
)
```

第一个配置只保留 BC 存在性/关键级别，不再执行 EE 的 `cA=false`。第二个配置整体替换 CA KU 回调，不再要求 `keyCertSign=true`；源码中没有其他位置补做该检查（全仓搜索 `key_cert_sign` 的策略判断只在 `policy/extension.rs:638` 和 `709`）。

**辨认：**

- 搜索 `require_present(`、`may_be_present(` 附近的 `None`、`lambda ...: None`、只记录日志不 raise 的回调；
- 对 `BasicConstraints`、`KeyUsage`、`ExtendedKeyUsage`、`AuthorityKeyIdentifier`、`NameConstraints` 逐一确认内容校验由谁负责；
- 不要把“criticality 从默认值改成 AGNOSTIC”理解为只改关键级别；只要调用 builder 覆盖同名 OID，旧回调也会被替换。

### F4. 登记了自定义 critical OID，却没有实际语义校验【中高】

未识别 critical 扩展默认失败（`extension.rs:305-310`）。但以下配置会把该 OID 变成“已交代且关键级别任意”：

```python
class MyPolicyExt(x509.ExtensionType):
    oid = x509.ObjectIdentifier("1.2.3.4.5")

ee_policy = ExtensionPolicy.permit_all().may_be_present(
    MyPolicyExt, Criticality.AGNOSTIC, None
)
```

这会允许该 critical 扩展存在而不检查其值。若传 Python 回调，绑定层会尝试把值解析为 Python 对象（无法识别时为 `UnrecognizedExtension`），但业务语义仍完全由回调负责；空回调等于不检查。

**辨认：** 所有 `may_be_present/require_present` 的自定义 OID 是否有非平凡回调；回调是否对非法值 raise。

### F5. 长生命周期 verifier 把验证时间冻结在构建时刻【中高】

未调用 `.time()` 时，时间在 `build_client_verifier()` / `build_server_verifier()` 中取当时 UTC（`src/rust/src/x509/verify/mod.rs:185-188`, `232-235`; `common.rs:613-623`），随后保存在不可变 `PolicyDefinition` 中。`verify()` 没有单独的时间参数。

因此：

```python
verifier = PolicyBuilder().store(store).build_server_verifier(name)
# 进程长期运行；证书在 verifier 构建后过期
verifier.verify(leaf, intermediates)  # 仍按构建时的旧时间判断
```

可能把构建时尚有效、验证时已过期的证书判定为有效。文档示例提醒 verifier 放置过久会有 expiration 问题，但代码层面的根因是策略时间在 build 时固定。

**辨认/补偿：** 搜索共享/缓存的 `ServerVerifier`、`ClientVerifier` 单例；每次验证附近用当前时间构建，或显式建立可接受的时间刷新机制。Store 可复用，时间策略不应无限期冻结。

### F6. Store 过宽或把 leaf/intermediate 直接信任【高】

以下写法会使对应证书成为无条件锚点：

```python
store = Store(load_pem_x509_certificates(bundle))   # bundle 是否可信、是否含多余证书？
store = Store([peer_cert])                          # leaf 被直接信任
store = Store([supplied_intermediate])              # 该 intermediate 被提升为锚
```

Store 没有用途或名称约束字段。若信任束可被输入影响、包含攻击者证书，或为了“修复链构建失败”而把对端提供的 intermediate 加入 Store，链认证就失去意义。

**辨认：** 审计所有 `Store(` 的证书来源；确保证书来自带外、只读、最小权限的信任束，而不是 TLS 对端输入、上传文件或临时调试代码。

### F7. 把验证成功误解为“未吊销”【高运营风险】

在 `src/rust/cryptography-x509-verification/src`、`src/rust/src/x509/verify` 和 `cryptography/x509/verification.py` 中搜索 `revoc/crl/ocsp` 无验证逻辑命中。Limbo 清单也跳过 `has-crl`（`test_limbo.py:46-47`）。

因此，未过期、链有效但已被 CA 吊销的证书仍可能通过此 API。仓库虽有 CRL/OCSP 构造和解析模块，但没有接入该 verifier。

**补偿：** 在链验证之外实施 CRL/OCSP 或其他吊销状态检查；本报告不能证明部署中不存在外部吊销层。

### F8. 依赖 DirectoryName/Subject DN 名称约束【中】

如果内部 PKI 用 directoryName NC 限制 Subject DN，默认策略并不提供完整 RFC 5280 DN 匹配：

- critical directoryName NC 当前硬失败，通常是 fail-closed；
- non-critical directoryName NC 在无 directoryName SAN 时被忽略；
- Subject DN 本身不会被转换为 NameChain 名称执行匹配。

源码注释直接说明了这一缺口（`lib.rs:430-440`），Limbo 跳过 `name-constraint-dn`（`test_limbo.py:29-30`）。

**辨认：** 检查 CA 证书的 NC 是否含 `directoryName`，以及策略是否依赖 CN/O/OU 命名空间做安全边界。若是，需要外部 DN 校验或更换/补充验证器。

### F9. 误以为 leaf 密钥强度和所有 CABF 订户要求都被强制【中】

RSA 2048 和 SPKI 算法白名单只在 `valid_issuer()` 中针对签发者执行（`policy/mod.rs:540-593`）。`permits_ee()` 没有对应的 leaf SPKI 算法或 RSA modulus 检查。Leaf 的签名算法会因它是 `valid_issuer()` 中的 `child` 而接受白名单检查，但 leaf 自身公钥类型/长度不会在本 API 中评级。

Limbo 清单明确跳过 `pedantic-webpki-subscriber-key`，注释说明大多数验证器不强制 CABF 对订户密钥的要求（`test_limbo.py:34-36`）。

**辨认/补偿：** 若安全基线要求 leaf 密钥最小强度或禁止 DSA/弱曲线，需要在回调或验证后检查 leaf 的 `public_key()`。实际 TLS/SSH 后端可能另有约束，但这不属于该链验证 API 的已证实行为。

### F10. 默认兼容性宽松项造成的“标准上不应接受”【低到中】

源码或项目测试清单明确承认以下宽松行为：

- EE EKU 缺失时按“任意 EKU”处理；只有 EKU 存在时才要求目标 EKU（`extension.rs:604-627`）。
- CA EKU 缺失也放行；存在时允许目标 EKU 或 `anyExtendedKeyUsage`（`extension.rs:750-769`）。
- EE EKU 内容检查使用 `.any(eku == policy_eku)`；因此同时含目标 EKU 和 `anyEKU` 时会通过，尽管上方注释写着“must not”显式 anyEKU（`extension.rs:612-624`）。这是注释与实现之间的差异，是否构成风险取决于适用的 CABF 版本。
- 序列号 `0` 实际可通过长度检查；Limbo 显式跳过 `rfc5280::serial::zero`（`policy/mod.rs:403-421`; `test_limbo.py:57-60`）。
- CA 缺失 AKI、intermediate 缺失 AKI、root AKI/SKI 不匹配等被接受（`extension.rs:664-678`; `test_limbo.py:61-79`）。AKI/SKI 仅用于候选排序。
- 自签发证书也无条件增加 depth；源码注释承认这不符合 RFC 5280 的 self-issued depth 处理，并有意让相关 Limbo 用例失败（`lib.rs:496-515`; `test_limbo.py:50-56`）。这主要可能导致**误拒绝**，但运维若因此调高 `max_chain_depth`，应理解实际计数语义。
- 文档称 self-issued intermediates 不计入 chain depth（`docs/x509/verification.rst:248-257`），与上述源码无条件 `checked_add(1)` 不一致；以源码和跳过测试为准。

---

## 7. 代码审查快速识别清单

可在使用该库的代码库中搜索以下信号：

```text
ExtensionPolicy.permit_all
.require_present(..., None)
.may_be_present(..., None)
lambda ...: None
Criticality.AGNOSTIC
build_client_verifier
PolicyBuilder()                         # 是否链式调用了 .time(...)
Store(                                  # 证书来源是否可信、是否包含对端输入
verify(                                 # verify 后是否做主体授权/吊销检查
```

对每个命中，依次询问：

1. 这是 Server 还是 Client 验证？若是 Client，`subjects` 如何映射到授权身份？
2. Store 是否只包含带外信任根？有没有把 leaf/intermediate/用户输入加入 Store？
3. EE 策略是否保留 `cA=false`、EKU、KU 检查？Server 是否仍有硬 SAN 匹配（不要试图用 client verifier 验证服务器）？
4. CA 策略是否保留 `keyCertSign` 检查？BC 是否仍为 `Present`？
5. 自定义回调是否真正解析并验证值，且失败时 raise？
6. critical 扩展是否都有对应语义 validator，而不是用 `AGNOSTIC + None` “登记放行”？
7. verifier 的 `validation_time` 是每次验证附近的当前时间，还是长期固定在构建时刻？
8. 吊销、DN 名称约束、公共后缀、leaf 密钥强度是否由外层补偿控制？

相对安全的基线是：

- Server 证书使用 `build_server_verifier(DNSName/IPAddress(...))`；
- Client 证书使用 `build_client_verifier()` 后显式授权 SAN；
- 不显式传 `extension_policies()`，或从 `webpki_defaults_ca()` / `webpki_defaults_ee()` 出发并只在能重实现语义时覆盖；
- Store 使用操作系统/certifi 等可信根束，不把对端提供的证书加入 Store；
- 每次验证使用接近当前的时间策略；
- 单独实施吊销检查和业务授权。

---

## 8. 证据缺口与未审计范围

以下事项不能从本次源码阅读中得出肯定结论：

1. **未执行 `nox -e local`、Rust 测试或动态 PoC。** 对“某配置会接受某类证书”的判断来自明确代码路径和仓库测试；除测试已直接证明者外，未实际构造证书运行。
2. **未审计底层密码学验证后端。** `PyCryptoOps::verify_signed_by()` 调用 `crate::x509::sign::verify_signature_with_signature_algorithm()`（`src/rust/src/x509/verify/mod.rs:42-52`）。算法白名单和调用关系已证实，但该函数及其链接的 OpenSSL/AWS-LC/BoringSSL/LibreSSL 实际行为、编译特性和后端策略未在本报告中验证。
3. **未执行 x509-limbo 外部套件。** 文中引用的 Limbo 特性/用例跳过集合是仓库源码中的项目自述，可证明维护者声明这些范围不受支持或有意偏离，但不等同于本次运行结果。
4. **CFFI/OpenSSL 低层验证路径未审计。** 本报告只确认 `x509.verification` 没有调用那些 `X509_verify_cert` 声明；若应用直接使用 pyOpenSSL 或自行调用 CFFI，应另行分析。
5. **部署侧补偿控制未知。** 调用方可能在 `verify()` 后做吊销、CT、账户绑定、DN 检查、leaf 密钥强度或额外 EKU 策略；这些无法从该仓库推断。
6. **扩展 ASN.1 parser 的全部解析健壮性未逐一审计。** 报告只覆盖验证策略如何调用解析结果；fuzzing/内存安全边界和所有扩展类型的解析差异不在结论范围内。

## 9. 关键源码索引

- 验证入口与链构建：`src/rust/cryptography-x509-verification/src/lib.rs`
- 策略、有效期、SAN 硬匹配、CA/EE 入口、签名与算法检查：`src/rust/cryptography-x509-verification/src/policy/mod.rs`
- 默认扩展策略、validator 替换语义、内置 BC/KU/EKU/NC 回调：`src/rust/cryptography-x509-verification/src/policy/extension.rs`
- Store 与信任锚相等性：`src/rust/cryptography-x509-verification/src/trust_store.rs`
- Python builder、时间默认值、Store/Verifier 绑定：`src/rust/src/x509/verify/mod.rs`
- Python 回调包装：`src/rust/src/x509/verify/extension_policy.rs`
- Python 公开导出：`src/cryptography/x509/verification.py`
- 策略测试：`tests/x509/verification/test_verification.py`
- Limbo 已知缺口/有意偏离：`tests/x509/verification/test_limbo.py`
