# 🧠 LogMind

<div align="center">

**Lightweight Terminal Log Intelligent Analysis Engine**

**轻量级终端日志智能分析引擎**

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/Zero-Dependencies-orange)]()
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)]()

[English](#english) | [简体中文](#简体中文) | [繁體中文](#繁體中文)

</div>

---

<a name="english"></a>
## 🎉 English

### Overview

**LogMind** is a zero-dependency, high-performance CLI tool designed for real-time log monitoring, intelligent pattern recognition, and anomaly detection. It helps developers and system administrators quickly analyze log files, identify issues, and gain insights into system behavior.

### ✨ Core Features

- 📊 **Multi-format Support**: Parse various log formats (syslog, JSON, Apache/Nginx, application logs)
- 🔍 **Pattern Detection**: Automatically detect IP addresses, emails, URLs, UUIDs, exceptions, and more
- ⚠️ **Anomaly Detection**: Identify error bursts, repeated errors, and security concerns
- 📈 **Statistical Analysis**: Log level distribution, time range analysis, top errors
- 🎨 **Beautiful Output**: Colored terminal output with progress bars and tables
- 📤 **Export Options**: JSON, CSV, and formatted text reports
- 🔄 **Real-time Monitoring**: Follow mode for live log analysis (like `tail -f`)
- 📦 **Compressed Files**: Support for .gz, .zip, .tar.gz archives
- 🚀 **Zero Dependencies**: Pure Python standard library, no external packages required

### 🚀 Quick Start

#### Installation

```bash
# Clone the repository
git clone https://github.com/gitstq/LogMind.git
cd LogMind

# Make executable
chmod +x logmind.py

# Optional: Install system-wide
pip install -e .
```

#### Basic Usage

```bash
# Analyze a log file
python logmind.py analyze /var/log/syslog

# Create demo log for testing
python logmind.py demo --lines 1000 -o demo.log

# Analyze with JSON output
python logmind.py analyze app.log --format json --output report.json

# Real-time monitoring
python logmind.py analyze /var/log/app.log --follow

# Analyze multiple files
python logmind.py analyze *.log
```

### 📖 Detailed Usage

#### Command: `analyze`

Analyze log files with various options:

```bash
python logmind.py analyze [files...] [options]

Options:
  -f, --follow          Follow mode (real-time monitoring)
  -n, --lines N         Maximum lines to analyze
  -o, --output FILE     Output file
  --format {text,json,csv}  Output format (default: text)
  --pattern NAME:REGEX  Add custom pattern
  --no-color            Disable colored output
```

#### Examples

```bash
# Analyze with custom pattern
python logmind.py analyze app.log --pattern "request_id:[a-z0-9-]+"

# Export to CSV
python logmind.py analyze app.log --format csv --output report.csv

# Analyze compressed log
python logmind.py analyze app.log.gz

# Limit analysis to first 10000 lines
python logmind.py analyze huge.log --lines 10000
```

### 💡 Design Philosophy

LogMind was built with these principles:

1. **Zero Dependencies**: Works with Python standard library only
2. **Universal Compatibility**: Runs on any system with Python 3.8+
3. **Developer-Friendly**: Intuitive CLI with sensible defaults
4. **Extensible**: Easy to add custom patterns and detectors
5. **Performance**: Efficient streaming analysis for large files

### 📦 Architecture

```
LogMind
├── LogParser          # Multi-format timestamp & level parsing
├── PatternDetector    # Regex-based pattern matching
├── AnomalyDetector    # Statistical anomaly detection
├── LogAnalyzer        # Main analysis engine
└── OutputFormatter    # Text/JSON/CSV formatting
```

### 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

<a name="简体中文"></a>
## 🎉 简体中文

### 项目介绍

**LogMind** 是一个零依赖、高性能的命令行工具，专为实时日志监控、智能模式识别和异常检测而设计。它帮助开发人员和系统管理员快速分析日志文件、识别问题并深入了解系统行为。

### ✨ 核心特性

- 📊 **多格式支持**：解析各种日志格式（syslog、JSON、Apache/Nginx、应用程序日志）
- 🔍 **模式检测**：自动检测 IP 地址、邮箱、URL、UUID、异常等
- ⚠️ **异常检测**：识别错误爆发、重复错误和安全问题
- 📈 **统计分析**：日志级别分布、时间范围分析、热门错误
- 🎨 **美观输出**：彩色终端输出，带进度条和表格
- 📤 **导出选项**：JSON、CSV 和格式化文本报告
- 🔄 **实时监控**：跟随模式进行实时日志分析（类似 `tail -f`）
- 📦 **压缩文件**：支持 .gz、.zip、.tar.gz 归档文件
- 🚀 **零依赖**：纯 Python 标准库，无需外部包

### 🚀 快速开始

#### 安装

```bash
# 克隆仓库
git clone https://github.com/gitstq/LogMind.git
cd LogMind

# 添加执行权限
chmod +x logmind.py

# 可选：系统级安装
pip install -e .
```

#### 基本用法

```bash
# 分析日志文件
python logmind.py analyze /var/log/syslog

# 创建演示日志用于测试
python logmind.py demo --lines 1000 -o demo.log

# 以 JSON 格式输出分析结果
python logmind.py analyze app.log --format json --output report.json

# 实时监控
python logmind.py analyze /var/log/app.log --follow

# 分析多个文件
python logmind.py analyze *.log
```

### 📖 详细使用指南

#### 命令：`analyze`

使用各种选项分析日志文件：

```bash
python logmind.py analyze [文件...] [选项]

选项：
  -f, --follow          跟随模式（实时监控）
  -n, --lines N         最大分析行数
  -o, --output FILE     输出文件
  --format {text,json,csv}  输出格式（默认：text）
  --pattern NAME:REGEX  添加自定义模式
  --no-color            禁用彩色输出
```

#### 示例

```bash
# 使用自定义模式分析
python logmind.py analyze app.log --pattern "request_id:[a-z0-9-]+"

# 导出为 CSV
python logmind.py analyze app.log --format csv --output report.csv

# 分析压缩日志
python logmind.py analyze app.log.gz

# 限制分析前 10000 行
python logmind.py analyze huge.log --lines 10000
```

### 💡 设计思路

LogMind 遵循以下原则构建：

1. **零依赖**：仅使用 Python 标准库即可工作
2. **通用兼容**：在任何装有 Python 3.8+ 的系统上运行
3. **开发者友好**：直观的 CLI，具有合理的默认值
4. **可扩展**：易于添加自定义模式和检测器
5. **高性能**：针对大文件的高效流式分析

### 📦 架构

```
LogMind
├── LogParser          # 多格式时间戳和级别解析
├── PatternDetector    # 基于正则表达式的模式匹配
├── AnomalyDetector    # 统计异常检测
├── LogAnalyzer        # 主分析引擎
└── OutputFormatter    # 文本/JSON/CSV 格式化
```

### 🤝 贡献指南

欢迎贡献！请随时提交 Pull Request。

1. Fork 本仓库
2. 创建您的功能分支 (`git checkout -b feature/AmazingFeature`)
3. 提交您的更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 打开 Pull Request

### 📄 开源协议

本项目采用 MIT 协议开源 - 详情请参阅 [LICENSE](LICENSE) 文件。

---

<a name="繁體中文"></a>
## 🎉 繁體中文

### 專案介紹

**LogMind** 是一個零依賴、高效能的命令列工具，專為即時日誌監控、智慧模式識別和異常檢測而設計。它幫助開發人員和系統管理員快速分析日誌檔案、識別問題並深入了解系統行為。

### ✨ 核心特性

- 📊 **多格式支援**：解析各種日誌格式（syslog、JSON、Apache/Nginx、應用程式日誌）
- 🔍 **模式檢測**：自動檢測 IP 位址、電子郵件、URL、UUID、異常等
- ⚠️ **異常檢測**：識別錯誤爆發、重複錯誤和安全問題
- 📈 **統計分析**：日誌級別分佈、時間範圍分析、熱門錯誤
- 🎨 **美觀輸出**：彩色終端輸出，帶進度條和表格
- 📤 **匯出選項**：JSON、CSV 和格式化文字報告
- 🔄 **即時監控**：跟隨模式進行即時日誌分析（類似 `tail -f`）
- 📦 **壓縮檔案**：支援 .gz、.zip、.tar.gz 壓縮檔案
- 🚀 **零依賴**：純 Python 標準函式庫，無需外部套件

### 🚀 快速開始

#### 安裝

```bash
# 克隆儲存庫
git clone https://github.com/gitstq/LogMind.git
cd LogMind

# 新增執行權限
chmod +x logmind.py

# 可選：系統級安裝
pip install -e .
```

#### 基本用法

```bash
# 分析日誌檔案
python logmind.py analyze /var/log/syslog

# 建立示範日誌用於測試
python logmind.py demo --lines 1000 -o demo.log

# 以 JSON 格式輸出分析結果
python logmind.py analyze app.log --format json --output report.json

# 即時監控
python logmind.py analyze /var/log/app.log --follow

# 分析多個檔案
python logmind.py analyze *.log
```

### 📖 詳細使用指南

#### 指令：`analyze`

使用各種選項分析日誌檔案：

```bash
python logmind.py analyze [檔案...] [選項]

選項：
  -f, --follow          跟隨模式（即時監控）
  -n, --lines N         最大分析行數
  -o, --output FILE     輸出檔案
  --format {text,json,csv}  輸出格式（預設：text）
  --pattern NAME:REGEX  新增自訂模式
  --no-color            停用彩色輸出
```

#### 範例

```bash
# 使用自訂模式分析
python logmind.py analyze app.log --pattern "request_id:[a-z0-9-]+"

# 匯出為 CSV
python logmind.py analyze app.log --format csv --output report.csv

# 分析壓縮日誌
python logmind.py analyze app.log.gz

# 限制分析前 10000 行
python logmind.py analyze huge.log --lines 10000
```

### 💡 設計理念

LogMind 遵循以下原則建構：

1. **零依賴**：僅使用 Python 標準函式庫即可運作
2. **通用相容**：在任何裝有 Python 3.8+ 的系統上執行
3. **開發者友善**：直觀的 CLI，具有合理的預設值
4. **可擴充**：易於新增自訂模式和檢測器
5. **高效能**：針對大檔案的高效串流分析

### 📦 架構

```
LogMind
├── LogParser          # 多格式時間戳和級別解析
├── PatternDetector    # 基於正規表示式的模式匹配
├── AnomalyDetector    # 統計異常檢測
├── LogAnalyzer        # 主分析引擎
└── OutputFormatter    # 文字/JSON/CSV 格式化
```

### 🤝 貢獻指南

歡迎貢獻！請隨時提交 Pull Request。

1. Fork 本儲存庫
2. 建立您的功能分支 (`git checkout -b feature/AmazingFeature`)
3. 提交您的變更 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 開啟 Pull Request

### 📄 開源授權

本專案採用 MIT 授權開源 - 詳情請參閱 [LICENSE](LICENSE) 檔案。

---

<div align="center">

**Made with ❤️ by gitstq**

⭐ Star us on GitHub — it motivates us a lot!

</div>
