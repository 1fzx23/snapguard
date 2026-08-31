# SnapGuard 🛡️

> 目录快照、变更检测与完整性守护 —— 另一个每两周小工具。

SnapGuard 为任意目录生成不可变快照（文件路径、大小、修改时间、SHA-256），并据此：

- **📸 快照**：一键记录目录当前状态。
- **🔍 对比**：`diff` 命令找出新增、删除、修改、重命名。
- **✅ 校验**：`verify` 重新计算哈希，检测文件损坏或被篡改。
- **👀 监控**：`watch` 实时监听目录变化（优先 OS 原生事件，回退到轮询）。
- **🧹 清理**：`prune` 保留最近 N 份快照，避免历史堆积。

适合用于：配置文件防漂移、部署前后比对、备份完整性校验、代码/资产变更审计。

---

## 安装

```bash
# 1. 克隆仓库
git clone https://github.com/1fzx23/snapguard.git
cd snapguard

# 2. 直接运行（纯标准库，无需依赖）
python snapguard.py --help

# 3. 或安装到 PATH（可选）
pip install -e .
```

> `watch` 命令默认使用轮询。如果希望使用原生文件系统事件，安装 `watchdog`：
> ```bash
> pip install watchdog
> ```

---

## 快速开始

```bash
# 在项目目录初始化 SnapGuard 仓库
snapguard init .

# 创建第一份快照
snapguard snap --label "v1.0-release"

# 修改一些文件后，对比当前状态
snapguard diff latest

# 校验所有文件哈希是否仍然一致
snapguard verify latest

# 查看当前与最新快照的摘要
snapguard status
```

---

## 命令详解

### `init [DIR]`

在当前目录（或指定目录）创建 `.snapguard/` 仓库，包含 `snapshots/` 和 `config.json`。

```bash
snapguard init .
```

### `snap --label <label> --exclude <pattern>`

创建新快照。支持多次 `--exclude` 排除文件或目录，pattern 为正则表达式。

```bash
snapguard snap --label "before-upgrade" --exclude "\\.log$" --exclude "node_modules"
```

### `list`

列出所有已存储快照。

```bash
snapguard list
```

### `diff <snapshot>`

将当前目录与指定快照比较，输出新增、删除、修改、重命名。`snapshot` 可填快照 ID 或 `latest`。

```bash
snapguard diff latest
snapguard diff 20260831-120000-000
```

### `verify <snapshot>`

重新计算每个文件的 SHA-256，与快照中的哈希比较。返回不匹配列表，空表示全部正常。

```bash
snapguard verify latest
```

### `watch --interval <seconds>`

实时监控目录变化。安装了 `watchdog` 时使用原生事件；否则每 2 秒轮询一次。

```bash
snapguard watch
snapguard watch --interval 5
```

### `prune --keep <N>`

只保留最近 N 份快照，删除旧的。

```bash
snapguard prune --keep 20
```

### `status`

显示最新快照的摘要与当前目录变化统计。

```bash
snapguard status
```

---

## 设计要点

- **零依赖核心**：快照、diff、verify、轮询监控均只使用 Python 标准库。
- **哈希去重重命名检测**：如果文件内容哈希不变但路径改变，会被标记为 `renamed` 而非先删后增。
- **自包含仓库**：`.snapguard/` 目录不会被纳入自己的快照，避免循环。
- **路径兼容**：快照内统一使用 POSIX 风格路径，跨平台可读。

---

## 示例输出

```text
$ snapguard diff latest
Diff against snapshot 20260831-181000-000 (before-upgrade)
Changes: +1 added, -1 removed, ~2 modified, →1 renamed
→ old/name.txt  →  new/name.txt  (a1b2c3d4e5f6)
+ added.txt  (1.2 KiB  f6e5d4c3b2a1)
- removed.txt  (3.4 KiB  e5d4c3b2a1f0)
~ config.json  (1.2 KiB → 1.3 KiB  a1b2 → c3d4)
```

---

## 项目信息

- 作者：[1fzx23](https://github.com/1fzx23)
- 难度：L4 / 专家
- 许可证：[MIT](./LICENSE)
- 演示页：https://1fzx23.github.io/snapguard/
