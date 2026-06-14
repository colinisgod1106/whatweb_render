# WhatWeb GUI

網站技術指紋識別工具，支援在 [Render](https://render.com) 上一鍵部署。

## 功能

- 🔍 偵測 50+ 技術特徵（CMS、Web Server、Framework、CDN、Analytics 等）
- 🔒 SSL 憑證資訊顯示
- 📊 HTTP 回應標頭完整列表
- ⚡ 最多 5 個 URL 同時並發掃描
- 🖥️ 深色主題 Terminal 風格 GUI

## 部署到 Render

### 方法一：使用 render.yaml（推薦）

1. Fork 或上傳本專案到 GitHub
2. 登入 [Render](https://render.com)
3. 點擊 **New → Blueprint**
4. 連接你的 GitHub repo
5. Render 會自動讀取 `render.yaml` 並部署

### 方法二：手動建立 Web Service

1. 登入 Render → **New → Web Service**
2. 連接 GitHub repo
3. 設定：
   - **Runtime**: Python 3
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn app:app --bind 0.0.0.0:$PORT --workers 2 --timeout 30`
4. 點擊 **Create Web Service**

## 本地執行

```bash
pip install -r requirements.txt
python app.py
# 開啟 http://localhost:5000
```

## 檔案結構

```
whatweb-gui/
├── app.py              # Flask 應用 + 指紋識別邏輯
├── templates/
│   └── index.html      # 前端 GUI
├── requirements.txt    # Python 依賴
├── render.yaml         # Render 部署設定
└── README.md
```
