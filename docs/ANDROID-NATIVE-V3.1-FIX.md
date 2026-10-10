# bxroot native-world-v3.1 修复说明

修复 DSHA proroot 配置下 native session 初始化返回 `ESTALE` 的问题。

原因是 DSHA 同时通过 `PROROOT_CFG_FD` 与环境 bind 列表携带 bind，配置解析会产生重复或重排记录；旧逻辑直接比较 bind 数量和索引顺序，误判为会话过期。

修复后按 `(host, guest, readonly)` 有效 bind 集合双向核对，仍严格校验 rootfs、路径和只读属性；只忽略重复和顺序差异。

## 验证

- Termux Android 核心矩阵：21/21 PASS。
- session fd、guest→host→guest、Node→Android→guest、cwd、只读 bind、PTY、Ctrl-C、clean env 均通过。
- 修复 runtime SHA-256：`39c1bccac3f443ee03113e199df3baf0e3ed5ea4172559fe5d69e2f9a356a05c`。
- entry SHA-256：`e57e890622fda68e98803b062e78ecb61bdb7336ad604b9d9ff2bc14d23be09e`。

该修复属于 bxroot 通用 runtime，不包含 DSHA APK 或 DSHA 二改版。
