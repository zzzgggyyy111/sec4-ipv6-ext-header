过滤规则只看第一个扩展头，后面串上七八个逐跳选项就把规则表绕过去了：必须遍历完整扩展头链；链长度必须有上限；只允许受支持的扩展类型；逐跳选项不得出现在中间节点之外；分片必须拒绝；批量校验各报文独立。不变量：任何未支持的扩展类型都导致拒绝；扩展链不会无限展开。

## 数据格式

扩展头链是映射的序列。每个映射包含 type 与 length 两个字段：type 是扩展类型名，length 是以八位组计的长度。策略是包含 max_headers 与 allowed_types 的映射。

受支持的扩展类型名为 hop_by_hop、routing、fragment、destination、authentication、mobility。

## 行为约定

parse_chain 返回完整的规范化链；check_count 检查链长度上限；check_type 检查单个扩展类型；check_hop_by_hop 检查逐跳选项是否只位于链首；check_fragment 检查分片；verify_chain 返回包含 ok、issues、count、types 的汇总；validate_chain 返回问题列表；header_batch 返回逐报文结果。

## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |

