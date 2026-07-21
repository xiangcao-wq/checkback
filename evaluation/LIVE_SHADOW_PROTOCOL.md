# CheckBack 真实 Shadow 评测协议

状态：仅作为准备文件。当前不得启用公开 Shadow，不得调用真实模型，也不得重复发送此前提供的照片。

## 1. 每一轮必须单独、明确授权

授权单位是“评测执行次数”，不是照片对数量。同一照片对每重复运行一次，都重新计为 1 次评测执行，并可能产生最多 3 次模型调用。

开始前必须补全服务商协议链接、协议版本、删除方式和有效期。建议使用以下文本：

> 我同意将我明确提供的照片用于 CheckBack 的 [N] 次隔离 Shadow 评测执行。每次执行在满足复核条件时最多产生 3 次阿里云百炼/Qwen 调用，本轮总上限为 [3N] 次；同一照片对每重复执行一次，也计入 N 和 3N。照片会发送至阿里云百炼/Qwen，并可能由服务商按照 [服务协议链接及版本] 处理或留存。CheckBack 评测端不保留照片，但无法召回已经发送给服务商的数据。我可以随时要求停止，尚未发送的剩余调用将不再发送；已经发出的调用无法撤回。评测端仅保留匿名数字 ID、固定枚举和数值耗时，最长 [不超过30天]，可通过 [删除申请方式] 提前删除。授权有效至 [日期时间]，不得用于公开流量或其他用途。

此前“两张照片最多额外发送 5 次”的授权已经全部使用，不能沿用。

## 2. 照片、真值与拆分要求

- 优先使用作者本人拍摄、确认不含敏感信息的照片。
- 避免证件、密码、聊天、住址、屏幕内容、人脸和其他人的信息。
- 真值必须在查看 Flash/Plus 输出前锁定。
- Gate 和 holdout 由两人独立标注；分歧必须仲裁。
- Plus 只是对照，不能作为 ground truth。
- 同一场景重复拍摄必须共用匿名 `scene-0001` 类 ID，不能虚增独立场景数。
- 实体、区域和日期桶只使用 `item-0001`、`zone-0001`、`day-001` 一类匿名数字 ID；不得写物品名、位置原文或真实日期。`supported + elsewhere` 必须预先标注匿名 `expected_zone`，其他真值不得填写该字段。
- `smoke`、`gate`、`holdout` 必须分文件保存。调参过程中不得查看冻结 holdout 的结果。
- 收集前必须冻结 representative 与 challenge 两份采样计划并记录匿名 plan ID；每个 case 绑定对应 plan ID，同一 scene 不得跨 cohort；看到模型输出后不得改变 cohort、配比或权重。
- 每条真值记录来源、是否在输出前锁定、标注人数和仲裁状态；holdout 至少两人独立标注，模型输出不能作为真值来源。

## 3. 调用次数账本

每轮建立只追加的本地计数账本，只记录匿名执行 ID、调用序号、标准化结果码和数值耗时，不记录图片、提示词或模型原文。

转换后的每个评测 case 必须写入唯一 execution_id、该 suite 声明配置的 SHA-256，以及 Primary/Flash/Plus 各 1 次、重试 0 次、总调用 3 次的执行记录。Schema 会拒绝错配置、重复执行 ID 和超额记录，但这些字段仍是导入数据，不能代替原子预占账本和第二人外部审计。

每次发出请求前必须：

1. 检查剩余授权调用数大于 0；
2. 在账本中预占 1 次；
3. 请求结束后写入 `success`、`timeout`、`request_error` 或 `invalid_output`；
4. Qwen SDK 隐式重试必须保持为 0，不允许账本外自动重发；
5. 单次 Shadow 执行内禁止任何显式重试；Primary、Flash、Plus 各最多 1 次，失败直接记录标准化 outcome；
6. 如需重跑，必须创建新的 `execution_id`，重新计入 N，并获得该新执行自己的最多 3 个调用槽；
7. 每次预占前同时校验 `per_execution_calls < 3` 与 `total_calls < 3N`；任一条件不满足都不得发送；
8. 达到 N 次执行、单执行 3 次调用或本轮 3N 次总调用中的任一上限，立即停止。

## 4. 第一阶段：受控小样本

至少 60 次评测执行，只用于判断是否值得扩大 Shadow：

- 至少 20 个可观察的真实缺失样本；
- 至少 20 个没有缺失的困难负样本；
- 至少 20 个遮挡、裁切、视角变化、反光或模糊样本；
- 每类至少覆盖 5 个不同场景。

这一步即使全部通过，也只能进入扩大 Shadow，不能启用 Active。

## 5. 扩大 Shadow 的冻结 holdout 门槛

正式 verifier gate 只接受 holdout 数据：

- 至少 1,000 次 holdout trial，且不混入 smoke/gate；采样计划必须在收集前冻结，真值必须在输出前锁定并由至少两人独立标注/仲裁；
- representative 至少 700 次：至少 50 个独立场景，单一场景不超过 5%；至少 7 个完整匿名日期桶、21 个时间窗口，每个窗口至少 30 次；
- challenge 至少 300 次、50 个独立场景；单场景不得超过 challenge trial 或候选 item 的 5%；至少 125 个可观察缺失候选，覆盖至少 20 个场景；
- challenge 至少 150 个可观察非缺失困难负样本，覆盖至少 100 次 trial、20 个场景，其中 `same_place` 和 `elsewhere` 各至少 75 个；
- challenge 至少 150 个 `not_comparable` 候选，覆盖至少 100 次 trial、20 个场景；
- `desk`、`lab`、`shared_tools` 各至少 10 个独立场景；每类还必须分别包含至少 100 次 representative trial，以及 missing、hard-negative、not-comparable 各至少 5 个 challenge 场景；
- representative 至少 600 个模拟 Fast 接受 batch，按候选 item 加权的 Fast 接受率也不得低于 65%；模型快照、Primary/Fast/Plus 超时、零重试设置、完整 prompt/template/settings SHA-256 必须与 pinned config 完全一致；
- challenge confirmed-missing precision 不低于 99%，supported-missing recall 不低于 90%，decision coverage 不低于 95%，仅按 supported 项计算的 truth accuracy 不低于 99%；每个场景也分别要求 recall ≥90%、decision coverage ≥95%、truth accuracy ≥99%；
- challenge 按场景宏平均的 decision coverage ≥95%、truth accuracy ≥99%、missing recall ≥90%；任一 supported 场景的 coverage 不得低于 80%、truth accuracy 不得低于 90%，任一含真实缺失场景的 recall 不得低于 80%；
- 错误确认缺失、把真实缺失/移位清除为原位、把真实缺失报成在其他位置、把原位物品报成问题、移位区域指错、对不可比较样本强行下结论、相对 Plus 的真值回归均为 0；
- representative 按 case 与按候选 item 计算的 Fast 接受率均不低于 65%，回退率不高于 35%，终止型 unresolved case 不高于 1%；item decision coverage 不低于 95%，supported-missing recall 不低于 90%，truth accuracy 不低于 99%；Flash/Plus batch 有效率不低于 99%/99.5%；
- representative 模拟 Active 总体 p95、任一时间窗口最差 p95、每个场景 p95 均不高于 20 秒；representative 的每个场景、每个时间窗口还分别按 item 与 case-macro 检查 coverage、truth accuracy 和 missing recall 的宏平均与最差组 floor；
- 相对 Plus-only 的配对中位延迟至少改善 20%，p95 至少改善 15%。

这些指标仍不能证明端到端 Primary 召回率或 case-level unsafe clear。Active 前还必须建立完整 Primary + `normalizeCheckbackReport` 标注集。

## 6. 每次执行检查表

执行前：

- [ ] 本轮授权文本已补全并记录，且尚未过期；
- [ ] 服务商协议链接和版本已提供给参与者；
- [ ] N、3N、已使用次数和剩余额度已核对；
- [ ] 照片已做敏感内容检查；
- [ ] representative/challenge 采样计划已在收集前冻结，匿名 plan ID、cohort 与 split 已确定；
- [ ] 真值来源、输出前锁定状态、两名标注者和仲裁结果已记录；
- [ ] 使用隔离环境，公开站点仍保持 off；
- [ ] 模型快照、prompt 版本和 prompt SHA-256 与 pinned config 一致；隔离采集器还需记录实际 provider、endpoint profile、client version 和请求候选回执；
- [ ] Qwen SDK 隐式重试为 0，单次执行内禁止显式重试；重跑必须使用新的 `execution_id` 并重新计入 N；
- [ ] 账本同时硬校验单执行调用数不超过 3、本轮总调用数不超过 3N；
- [ ] 每个待导入 case 的唯一 execution_id、suite 配置 SHA-256、对应 plan ID 和 1/1/1/0/3 调用记录已与账本复核；
- [ ] 旧 API Key 已轮换。

执行中：

- [ ] 每次请求前预占调用额度；
- [ ] 不记录请求正文、Data URL、物品标签、evidence、prompt、原始位置或模型原文；
- [ ] 只记录匿名数字 ID、固定枚举和数值耗时；
- [ ] 429、5xx、超时和 schema 失败只记录标准化枚举；
- [ ] 收到停止要求后，不再发出任何剩余请求。

执行后：

- [ ] 删除本地、容器和临时目录中的照片副本；
- [ ] 校验执行次数和模型调用总数未超授权；
- [ ] 转换为 `checkback.shadow-eval.v1`；
- [ ] 普通检查运行 `npm run eval:shadow -- path\to\suite.json`；
- [ ] 冻结 holdout 运行 `npm run eval:shadow:gate -- path\to\holdout-suite.json`；
- [ ] 第二人复核指标、失败案例和 split 污染；
- [ ] 评测记录不超过 30 天，并支持提前删除。

## 7. 立即停止条件

出现任一情况，停止测试并保持 off：

- 任意错误确认缺失、错误 clear、原位物品误报、移位区域指错或对不可比较样本强行下结论；
- 未授权照片、调用超限、split 污染或隐私事件；
- 模型、prompt 或代码版本与记录不一致；
- `qwen_unresolved` 超过 2%；
- 全流程 p95 超过 30 秒，或任一冻结时间窗口的 p95 超过门槛；
- 429/5xx 持续异常；
- 无法证明临时照片已清理。

## 8. 公开 Shadow/Active 前仍需完成

- 更新隐私页，明确最多 3 次 Qwen 调用和服务商处理边界；
- 提供逐用户主动 opt-in，而不是全局环境变量覆盖所有用户；
- 实现受控 cohort/canary 和逐调用额度账本；
- 建立匿名聚合和 14–30 天删除策略；
- 完成端到端标注集和 case-level unsafe-clear 测试；
- 演练 `CHECKBACK_FAST_VERIFIER_MODE=off` 与 `CHECKBACK_ANALYSIS_ENABLED=false` 两个熔断开关；
- 由用户书面确认部署。
