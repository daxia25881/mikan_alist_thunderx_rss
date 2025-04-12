# Mikan to Alist Uploader

Mikan to Alist Uploader 是一个自动化工具，用于监听 Mikan RSS 的更新，并将新发布的资源自动添加到 Alist 的离线下载队列中。

## 功能特点

- 支持监听多个 Mikan RSS 链接
- 自动为每个番剧创建独立的文件夹
- 自动将磁力链接添加到对应的番剧文件夹
- 自动跟踪已下载的项目，避免重复下载
- 按番剧分类存储下载记录
- 通过 Docker 快速部署
- 提供Web管理界面，可视化配置和监控

## Docker Compose 部署指南

### 前置条件

- 安装 Docker 和 Docker Compose
- 获取 Mikan 的 RSS 订阅链接
- 准备好 Alist 的账号、密码和基础 URL

### 部署步骤

1. 克隆或下载此仓库到本地

```bash
git clone https://github.com/yourusername/mikan_alist_uploader.git
cd mikan_alist_uploader
```

2. 配置环境变量

编辑 `.env` 文件，填写以下信息：

```
# Alist Configuration
ALIST_USERNAME=你的Alist用户名
ALIST_PASSWORD=你的Alist密码
ALIST_BASE_URL=你的Alist地址，例如http://localhost:5244
ALIST_OFFLINE_DOWNLOAD_DIR=/你的Alist下载目录

# Mikan RSS URLs (多个链接用逗号分隔)
MIKAN_RSS_URLS=https://mikanani.me/RSS/MyBangumi?token=你的token,https://mikanani.me/RSS/Bangumi?bangumiId=xxxx

# 或者使用单个RSS链接(上面的配置优先)
# MIKAN_RSS_URL=https://mikanani.me/RSS/MyBangumi?token=你的token

# 检查设置
CHECK_INTERVAL=10    # RSS 检查间隔（分钟）

# Web界面设置
WEB_PORT=8080        # Web界面端口

# 时区设置 (可选但推荐)
TZ=Asia/Shanghai
```

3. 创建 data 目录以存储持久化数据

```bash
mkdir -p data
```

4. 构建和启动容器

```bash
docker-compose up -d
```

5. 访问Web管理界面

在浏览器中访问 `http://你的服务器IP:8080`，可以看到Web管理界面。

6. 查看日志

```bash
docker-compose logs -f
```

### 更新应用

如需更新应用，请执行：

```bash
docker-compose down
git pull
docker-compose up -d --build
```

## 使用方法

部署完成后，应用会自动运行并定期检查您配置的 RSS 订阅。

### Web管理界面

通过Web管理界面，您可以：

1. 修改下载目录路径 - 更改Alist中接收下载文件的目录
2. 调整检查间隔 - 设置多久检查一次RSS更新
3. 管理RSS链接 - 添加、删除或修改监听的RSS链接
4. 查看番剧状态 - 查看已下载的番剧及集数
5. 手动触发检查 - 立即执行RSS检查而不等待计划任务

所有通过Web界面修改的配置会自动保存，并立即生效。

### 工作流程

1. 应用启动后，会轮询检查配置的所有 RSS 链接
2. 从 RSS 标题中提取番剧名称（例如 "Mikan Project - 乡下大叔成为剑圣" 提取为 "乡下大叔成为剑圣"）
3. 在 Alist 下载目录中创建以番剧名称命名的文件夹
4. 从 RSS 项目中提取磁力链接，添加到对应的番剧文件夹中
5. 将下载记录按番剧分类保存到 data/processed_mikan_hashes.json 文件中
6. 定期按配置的 CHECK_INTERVAL 间隔检查 RSS 更新

## 重要提示

- 确保您的 Alist 配置了正确的离线下载引擎（如 storage 或 aria2）
- 如果使用 aria2 作为下载引擎，请确保 aria2 已正确配置
- 建议在首次使用前，手动测试一次 Alist 的离线下载功能是否正常工作
- 多个磁力链接上传会间隔 3 秒，以避免 Alist API 限流
- 默认Web端口为8080，可以通过环境变量或配置文件修改 