# BNDSForum

BNDSForum 是一套轻量级的博客与知识分享平台。它基于 Flask 3 构建，内置 Markdown 写作体验、层次化标签体系以及与 BNDS Online Judge (BNDSOJ) 的账号集成。

## 目录

- [功能亮点](#功能亮点)
- [技术栈](#技术栈)
- [目录结构](#目录结构)
- [环境要求](#环境要求)
- [快速开始](#快速开始)
- [配置与环境变量](#配置与环境变量)
- [数据存储与迁移](#数据存储与迁移)
- [认证与权限模型](#认证与权限模型)
- [内容创作体验](#内容创作体验)
- [标签体系与导航](#标签体系与导航)
- [管理后台能力](#管理后台能力)

## 功能亮点

- 支持 Markdown 写作、实时预览、代码高亮与 KaTeX 数学公式渲染。
- 与 BNDSOJ 共用账号体系；远程校验成功后自动同步真实姓名并更新本地缓存。
- 文章、评论均支持 Markdown；评论区具备轻量工具栏和实时校验。
- 采用 SQLite 存储，自动初始化数据库并兼容旧版 JSON 文件结构。
- 管理后台提供用户、常用标签、层次化标签树的图形化管理。
- 标签树页面自动汇总节点下文章数量、符合条件的用户以及是否已有相关作品。
- 全量静态资源本地化，无需依赖外部 CDN，可直接离线部署。

## 技术栈

- **后端**：Flask 3、Flask-Login
- **数据层**：SQLite 3 本地文件数据库，使用 WAL 模式与外键约束
- **认证集成**：`requests` 驱动的 BNDSOJ 登录流程封装
- **Markdown & 富文本**：markdown-it、mdit-py-plugins、CodeMirror、highlight.js、KaTeX
- **前端样式**：自定义响应式布局，支持深浅配色与移动端导航

## 目录结构

```
BNDSForum/
├── app/                 # Flask 应用主包
│   ├── __init__.py      # 应用工厂与全局上下文
│   ├── admin.py         # 管理后台蓝图
│   ├── auth.py          # 登录 / 登出 / 注册入口（注册已禁用）
│   ├── blog.py          # 文章、评论与用户主页
│   ├── datastore.py     # SQLite 数据访问层及业务逻辑
│   ├── oj_client.py     # BNDSOJ 登录校验客户端
│   ├── tag.py           # 标签树展示与统计
│   ├── static/          # 本地化静态资源与样式
│   └── templates/       # Jinja2 模板
├── data/                # 默认数据目录（forum.sqlite3）
├── run.py               # 入口脚本（开发服务器）
├── requirements.txt     # Python 依赖列表
└── COPYING              # GPL-3.0 许可文本
```

## 环境要求

- Python ≥ 3.8（建议 3.11+，与 Flask 3 官方支持保持一致）
- SQLite 3（随 Python 内置）
- 可选：访问 BNDSOJ 登录页的出站网络权限

## 快速开始

```bash
# 1. 创建并激活虚拟环境
python3 -m venv .venv
source .venv/bin/activate     # Windows: .venv\Scripts\activate

# 2. 安装依赖
pip install --upgrade pip
pip install -r requirements.txt

# 3. (可选) 配置环境变量
export SECRET_KEY="change-me"
export OJ_BASE_URL="https://onlinejudge.bnds.cn"

# 4. 启动开发服务器
python run.py                 # 监听 0.0.0.0:6001
```

首轮启动会自动在 `data/forum.sqlite3` 创建数据库，并初始化用户名为 `admin`、密码为 `admin123` 的管理员帐号。请立即登录后台修改密码。

浏览器访问 `http://localhost:6001` 即可进入首页。

## 配置与环境变量

| 变量名           | 默认值                     | 说明 |
| ---------------- | -------------------------- | ---- |
| `SECRET_KEY`     | `dev-secret-key`           | Flask 会话密钥，部署时必须修改 |
| `OJ_BASE_URL`    | `https://onlinejudge.bnds.cn` | BNDSOJ 入口地址 |
| `OJ_TIMEOUT`     | `10`（秒）                 | BNDSOJ 请求超时时间 |
| `OJ_VERIFY_SSL`  | `false`（任何非真值均视作否） | `true` 强制校验证书，`false` 关闭校验 |

> 提示：生产环境应显式设置 `SECRET_KEY`，并根据部署网络状况决定是否开启 `OJ_VERIFY_SSL`。

## 数据存储与迁移

- 默认数据位于 `data/forum.sqlite3`；可通过设置 `DATA_PATH`（修改 `app/__init__.py`）定制存储位置。
- `datastore.py` 会自动启用 SQLite `WAL` 模式、外键约束与适配的性能配置。
- 首次启动若检测到旧版 JSON 数据（`users.json`、`tags.json`、`tag_tree.json`、`posts.json` 或 `posts/*.json`），会执行一次性迁移；迁移完成后写入 `data/.sqlite_migrated` 哨兵文件防止重复导入。
- 所有写操作均在线程安全的 `RLock` 范围内完成，可安全用于 Flask 内置开发服务器与 Gunicorn 等 WSGI 容器。

## 认证与权限模型

1. **BNDSOJ 联合登录**：登录表单优先向 BNDSOJ 发起校验；成功后自动同步真实姓名并缓存密码哈希以支持离线登录。
2. **离线回退**：当 BNDSOJ 不可用或账号不存在时，退回本地 SQLite 校验。
3. **角色体系**：
   - `admin`：访问管理后台、调整用户角色与固定标签、维护标签树。
   - `user`：撰写文章、评论、查看标签树。
4. **注册入口**：面向普通用户注册已关闭，模板按钮用于管理员批量创建时保留。可在 `auth.register` 中重新开启。

## 内容创作体验

- **Markdown 编辑器**：基于 CodeMirror，提供常用语法快捷按钮、键盘列表缩进、实时预览面板。
- **KaTeX 数学公式**：在 Markdown 中使用 `$...$` 或 `$$...$$` 即可渲染；编辑器会自动转义大括号避免冲突。
- **Callout 块**：支持 `:::info` / `:::success` / `:::warning` / `:::error` 容器语法，预览和渲染均保持提示框样式。
- **语法高亮**：内置 highlight.js，无需额外配置即可对代码块进行高亮。
- **评论区**：表单采用紧凑模式，与文章编辑器共享渲染逻辑，提交前校验空内容并给出提示。

## 标签体系与导航

- **常用标签**：管理员维护的扁平标签列表，作者写作时可多选。
- **固定标签**：为用户全局配置的标签，系统会在该用户的所有文章中自动附加。
- **标签树**：任意层级的有向树结构，支持创建空占位节点。`/tags` 页面显示树状导航、每个节点下的文章与具备写作能力的用户列表；节点统计通过 `posts_with_tags` 与 `user_has_post_with_tags` 动态计算。
- **筛选与统计**：标签树节点页面展示匹配文章列表、具备标签覆盖能力的作者、是否已有作品等信息，方便分配写作任务。

## 管理后台能力

- 常用标签增删。
- 标签树节点增删改，含父节点选择与路径预览。
- 用户筛选（用户名、真实姓名、固定标签）与批量编辑（真实姓名、角色、固定标签）。
- 保护策略：强制至少保留一名管理员；普通用户无法访问后台路由。

## 性能测试脚本

仓库提供 `scripts/perf_test.py` 用于压力与性能测试，涵盖首页、标签树、文章详情、登录、写作、评论、后台等典型操作。脚本会在运行前自动备份 `data/forum.sqlite3`，测试结束（无论成功与否）都会恢复原始数据库，确保测试数据不污染现有环境。

执行示例：

```bash
python scripts/perf_test.py \
  --base-url http://localhost:6001 \
  --duration 60 \
  --concurrency 8
```

常用参数：

- `--base-url`：目标服务地址，默认为本地开发服务器。
- `--username` / `--password`：登录账号，默认使用内置管理员，可通过环境变量 `PERF_USERNAME` / `PERF_PASSWORD` 覆盖。
- `--duration`：压力测试持续时间（秒）。
- `--concurrency`：并发工作线程数量。
- `--timeout`：单次请求超时时间（秒）。
- `--seed-posts`：测试前额外创建的种子文章数量，保证读取与编辑操作有数据可用。
- `--seed`：随机种子，便于复现压测场景。

测试完成后会在终端输出各操作的吞吐（TPS）与时延（平均值、p95、max 等），可据此评估不同功能的性能表现。
