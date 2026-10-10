# bxroot native-world-v3 Android arm64 发行说明

- 分支：`feat/native-world-v3`
- 提交：`0acd70ae39c6535e440df7143ef8e88c2299dbe4`
- 通用发行包：`bxroot-native-v3-android-arm64-release.zip`
- runtime SHA-256：`93bd717fa13bb5f9f0814cf41714df81071fc618a0bbb8f503b1e0f01d2a1fd1`
- native entry SHA-256：`e57e890622fda68e98803b062e78ecb61bdb7336ad604b9d9ff2bc14d23be09e`

## 验证

- Termux Android 核心矩阵：21/21 PASS。
- Termux Android 脚本诊断：7/7 PASS。
- Termux Android 压力测试：1120/1120 PASS。
- 16 并发 1000 次：1000/1000 PASS，最大单次 155ms。
- 压力测试前后 fd：4/4。
- proc-fd 回归：63/63 PASS。
- native-session：18 cases / 1454 checks PASS。
- warning gate：21 个编译单元零警告。
- 静态与 freestanding PIE helper：各 107 checks PASS。

## 边界

这是 bxroot 通用运行时发行说明。DSHA APK、DSHA 二改版、DSHA 私有适配和设备数据不属于本仓库发行内容；本项目不包含 DSHA APK 或其私有包名。Termux companion、Binder/RPC 和设备能力适配仍属于外部适配层。

匿名 bionic ELF 自动分流、相对 `posix_spawn` 配合 chdir actions 继续按第三版边界处理。
