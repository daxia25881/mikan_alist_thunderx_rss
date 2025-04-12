package main

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"
)

// --- Structs ---

// Config 定义 Alist/服务 配置结构体
type Config struct {
	Username           string   `json:"username"`
	Password           string   `json:"password"`
	BaseURL            string   `json:"base_url"`             // Alist 或类似服务的 API 基础 URL
	OfflineDownloadDir string   `json:"offline_download_dir"` // Alist 上的离线下载目标目录
	CheckInterval      int      `json:"check_interval"`       // RSS 检查间隔（分钟）
	RssURLs            []string `json:"rss_urls"`             // 多个Mikan RSS URL
	WebPort            int      `json:"web_port"`             // Web界面端口
}

// RSS represents the top-level structure of the Mikan RSS feed
type RSS struct {
	XMLName xml.Name `xml:"rss"`
	Channel Channel  `xml:"channel"`
}

// Channel contains the metadata and list of items
type Channel struct {
	XMLName xml.Name `xml:"channel"`
	Title   string   `xml:"title"`
	Link    string   `xml:"link"`
	Items   []Item   `xml:"item"`
}

// Item represents a single episode/entry in the feed
type Item struct {
	XMLName     xml.Name `xml:"item"`
	Title       string   `xml:"title"`
	Link        string   `xml:"link"` // Link to the episode page (contains hash)
	GUID        string   `xml:"guid"`
	PubDate     string   `xml:"pubDate"`
	Description string   `xml:"description"`
}

// ProcessedHashesMap 保存每个番剧已处理的哈希值
type ProcessedHashesMap map[string][]string

// --- Global Variables ---
var config Config                // Holds Alist configuration
var globalToken string           // Cache for Alist API token
var configMutex sync.RWMutex     // 用于保护配置的读写锁
var isConfigChanged bool = false // 配置是否已更改
var mikanRssURL string           // Holds the Mikan RSS URL

// --- Constants ---
const (
	processedHashesFile  = "data/processed_mikan_hashes.json" // 用JSON格式保存已处理的哈希值
	userAgent            = "GoMikanAlistUploader/1.3"         // HTTP User-Agent for requests
	configFileName       = "data/alist_config.json"           // Fallback Alist config file name
	defaultCheckInterval = 30                                 // 默认检查间隔（分钟）
	uploadInterval       = 3 * time.Second                    // 多个磁力链接上传间隔时间
	defaultWebPort       = 8085                               // 默认Web界面端口
)

// Common public trackers (for magnet link generation)
var trackers = []string{
	"udp://tracker.opentrackr.org:1337/announce",
	"udp://tracker.openbittorrent.com:6969/announce",
	"udp://tracker.dler.org:6969/announce",
	"udp://open.demonii.com:1337/announce",
	"udp://tracker.coppersurfer.tk:6969/announce",
	"udp://tracker.leechers-paradise.org:6969/announce",
	// Add more trackers if needed
}

// --- Configuration Loading ---

// loadConfig loads Alist configuration.
// It prioritizes environment variables (ALIST_USERNAME, ALIST_PASSWORD, ALIST_BASE_URL, ALIST_OFFLINE_DOWNLOAD_DIR).
// If any of these are missing, it attempts to load from `alist_config.json`.
func loadConfig() error {
	configMutex.Lock()
	defer configMutex.Unlock()

	log.Println("加载 Alist 配置...")
	config.Username = os.Getenv("ALIST_USERNAME")
	config.Password = os.Getenv("ALIST_PASSWORD")
	config.BaseURL = strings.TrimRight(os.Getenv("ALIST_BASE_URL"), "/") // Ensure no trailing slash
	config.OfflineDownloadDir = os.Getenv("ALIST_OFFLINE_DOWNLOAD_DIR")

	// 加载RSS URLs
	if rssURLsEnv := os.Getenv("MIKAN_RSS_URLS"); rssURLsEnv != "" {
		// 以逗号分隔多个URL
		config.RssURLs = strings.Split(rssURLsEnv, ",")
		// 清理空格
		for i, url := range config.RssURLs {
			config.RssURLs[i] = strings.TrimSpace(url)
		}
		log.Printf("从环境变量加载了 %d 个RSS链接", len(config.RssURLs))
	} else if singleRssURL := os.Getenv("MIKAN_RSS_URL"); singleRssURL != "" {
		// 兼容单个RSS链接的旧配置
		config.RssURLs = []string{singleRssURL}
		log.Println("从环境变量加载了单个RSS链接")
	}

	// 获取间隔配置
	if interval := os.Getenv("CHECK_INTERVAL"); interval != "" {
		if i, err := strconv.Atoi(interval); err == nil && i > 0 {
			config.CheckInterval = i
		}
	}

	// 获取Web端口
	if webPort := os.Getenv("WEB_PORT"); webPort != "" {
		if p, err := strconv.Atoi(webPort); err == nil && p > 0 {
			config.WebPort = p
		}
	}

	// 设置默认值
	if config.CheckInterval <= 0 {
		config.CheckInterval = defaultCheckInterval
	}

	// 设置默认Web端口
	if config.WebPort <= 0 {
		config.WebPort = defaultWebPort
	}

	// Check if loaded from environment variables
	loadedFromEnv := config.Username != "" && config.Password != "" && config.BaseURL != "" && config.OfflineDownloadDir != ""

	if !loadedFromEnv || len(config.RssURLs) == 0 {
		log.Printf("环境变量未完全设置，尝试从 %s 加载...", configFileName)
		file, err := os.Open(configFileName)
		if err != nil {
			// If file doesn't exist and env vars were also missing, it's a fatal error
			if os.IsNotExist(err) {
				// 如果文件不存在但环境变量存在，尝试创建配置文件
				if loadedFromEnv {
					// 保存现有配置到文件
					if saveErr := saveConfig(); saveErr != nil {
						log.Printf("警告: 创建初始配置文件失败: %v", saveErr)
					}
				} else {
					return fmt.Errorf("错误: Alist 配置未通过环境变量完全设置，且配置文件 %s 未找到", configFileName)
				}
			} else {
				// Other error opening file
				return fmt.Errorf("打开配置文件 %s 时出错: %w", configFileName, err)
			}
		} else {
			// 文件存在，读取配置
			defer file.Close()

			decoder := json.NewDecoder(file)
			// Decode into a temporary struct to avoid overwriting partially loaded env vars
			var fileConfig Config
			err = decoder.Decode(&fileConfig)
			if err != nil {
				return fmt.Errorf("解析配置文件 %s 时出错: %w", configFileName, err)
			}

			// Fill missing values from the file config
			if config.Username == "" {
				config.Username = fileConfig.Username
			}
			if config.Password == "" {
				config.Password = fileConfig.Password
			}
			if config.BaseURL == "" {
				config.BaseURL = strings.TrimRight(fileConfig.BaseURL, "/")
			}
			if config.OfflineDownloadDir == "" {
				config.OfflineDownloadDir = fileConfig.OfflineDownloadDir
			}
			if len(config.RssURLs) == 0 && len(fileConfig.RssURLs) > 0 {
				config.RssURLs = fileConfig.RssURLs
			}
			if config.CheckInterval <= 0 && fileConfig.CheckInterval > 0 {
				config.CheckInterval = fileConfig.CheckInterval
			}
			if config.WebPort <= 0 && fileConfig.WebPort > 0 {
				config.WebPort = fileConfig.WebPort
			}
			log.Printf("从 %s 加载了部分或全部配置。", configFileName)
		}
	} else {
		log.Println("从环境变量加载了 Alist 配置。")
	}

	// Final validation
	if config.Username == "" || config.Password == "" || config.BaseURL == "" || config.OfflineDownloadDir == "" {
		return fmt.Errorf("错误: Alist 配置不完整 (需要 username, password, base_url, offline_download_dir)，请检查环境变量或 %s 文件", configFileName)
	}

	if len(config.RssURLs) == 0 {
		return fmt.Errorf("错误: 未配置任何Mikan RSS链接，请通过MIKAN_RSS_URLS或MIKAN_RSS_URL环境变量配置")
	}

	log.Printf("已配置: %d 个RSS链接, RSS检查间隔=%d分钟, Web端口=%d",
		len(config.RssURLs), config.CheckInterval, config.WebPort)
	return nil
}

// saveConfig 保存配置到json文件
func saveConfig() error {
	configMutex.RLock()
	defer configMutex.RUnlock()

	// 创建目录
	dir := path.Dir(configFileName)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("创建配置目录失败: %w", err)
	}

	// 打开文件
	file, err := os.OpenFile(configFileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("创建配置文件失败: %w", err)
	}
	defer file.Close()

	// 使用JSON编码
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ") // 美化输出
	if err = encoder.Encode(config); err != nil {
		return fmt.Errorf("编码配置失败: %w", err)
	}

	log.Printf("配置已保存到 %s", configFileName)
	isConfigChanged = false
	return nil
}

// updateConfig 更新配置并保存
func updateConfig(offlineDir string, checkInterval int, rssURLs []string) error {
	configMutex.Lock()

	// 标记配置是否有变化
	changed := false

	// 更新下载目录
	if offlineDir != "" && offlineDir != config.OfflineDownloadDir {
		config.OfflineDownloadDir = offlineDir
		changed = true
	}

	// 更新检查间隔
	if checkInterval > 0 && checkInterval != config.CheckInterval {
		config.CheckInterval = checkInterval
		changed = true
	}

	// 更新RSS URLs
	if rssURLs != nil && len(rssURLs) > 0 {
		// 清理空值
		cleanURLs := make([]string, 0, len(rssURLs))
		for _, url := range rssURLs {
			if trimmedURL := strings.TrimSpace(url); trimmedURL != "" {
				cleanURLs = append(cleanURLs, trimmedURL)
			}
		}

		// 检查是否有变化
		if !stringSlicesEqual(cleanURLs, config.RssURLs) {
			config.RssURLs = cleanURLs
			changed = true
		}
	}

	configMutex.Unlock()

	// 如果有变化，保存配置
	if changed {
		isConfigChanged = true
		return saveConfig()
	}

	return nil
}

// stringSlicesEqual 比较两个字符串切片是否相等
func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}

	for i, v := range a {
		if v != b[i] {
			return false
		}
	}

	return true
}

// --- Alist API Interaction Functions ---

// getToken retrieves the Alist API token, using a cache if available.
// Handles login if the token is not cached or seems invalid.
func getToken() (string, error) {
	if globalToken != "" {
		// Simple cache check. A more robust solution might verify the token first.
		// log.Println("使用缓存的 Alist token")
		return globalToken, nil
	}

	apiURL := config.BaseURL + "/api/auth/login"
	log.Println("正在登录 Alist 获取 token...")

	loginInfo := map[string]string{
		"username": config.Username,
		"password": config.Password,
	}
	payloadBytes, err := json.Marshal(loginInfo)
	if err != nil {
		log.Printf("Alist 登录信息 JSON 编码失败: %v", err)
		return "", fmt.Errorf("无法编码登录信息: %w", err)
	}

	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequest("POST", apiURL, strings.NewReader(string(payloadBytes)))
	if err != nil {
		log.Printf("创建 Alist 登录请求失败: %v", err)
		return "", fmt.Errorf("无法创建登录请求: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("登录 Alist 时网络错误: %v", err)
		return "", fmt.Errorf("登录 Alist 时出错: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("读取 Alist 登录响应体失败: %v", err)
		return "", fmt.Errorf("无法读取登录响应: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		log.Printf("Alist 登录失败，状态码: %d, 响应: %s", resp.StatusCode, string(body))
		return "", fmt.Errorf("Alist 登录失败，状态码: %d", resp.StatusCode)
	}

	var result map[string]interface{}
	err = json.Unmarshal(body, &result)
	if err != nil {
		log.Printf("解析 Alist 登录响应 JSON 失败: %v, 响应: %s", err, string(body))
		return "", fmt.Errorf("无法解析登录响应 JSON: %w", err)
	}

	// Check response structure and code
	codeFloat, _ := result["code"].(float64)
	code := int(codeFloat)
	if code != 200 {
		message := "未知错误"
		if msg, ok := result["message"].(string); ok {
			message = msg
		}
		log.Printf("Alist 登录 API 返回错误: %s (code: %d)", message, code)
		return "", fmt.Errorf("Alist 登录 API 返回失败: %s", message)
	}

	data, ok := result["data"].(map[string]interface{})
	if !ok {
		log.Printf("Alist 登录响应格式错误: 未找到 'data' 字段。响应: %s", string(body))
		return "", fmt.Errorf("Alist 登录响应格式错误: 'data'")
	}

	token, ok := data["token"].(string)
	if !ok || token == "" {
		log.Printf("Alist 登录响应格式错误: 未在 'data' 中找到有效的 'token'。响应: %s", string(body))
		return "", fmt.Errorf("Alist 登录响应格式错误: 'token'")
	}

	log.Println("Alist 登录成功，已获取并缓存 token。")
	globalToken = token // Cache the token
	return token, nil
}

// addMagnet adds the given magnet link to the Alist offline download queue.
func addMagnet(magnet string, targetFolder string) (bool, error) {
	token, err := getToken()
	if err != nil {
		// Error already logged in getToken
		return false, fmt.Errorf("无法获取 Alist token: %w", err)
	}

	// 构建完整路径
	downloadPath := config.OfflineDownloadDir
	if targetFolder != "" {
		downloadPath = path.Join(config.OfflineDownloadDir, targetFolder)
	}

	apiURL := config.BaseURL + "/api/fs/add_offline_download"
	log.Printf("正在添加离线下载任务到 Alist 目录: %s", downloadPath)
	// log.Printf("Magnet: %s", magnet) // Uncomment for debugging

	postData := map[string]interface{}{
		"path": downloadPath,
		"urls": []string{magnet},
		// Use storage as download tool instead of aria2
		"tool":          "storage",
		"delete_policy": "delete_on_upload_succeed",
	}
	payloadBytes, err := json.Marshal(postData)
	if err != nil {
		log.Printf("离线下载任务数据 JSON 编码失败: %v", err)
		return false, fmt.Errorf("无法编码离线下载数据: %w", err)
	}

	client := &http.Client{Timeout: 25 * time.Second} // Give more time for this request
	req, err := http.NewRequest("POST", apiURL, strings.NewReader(string(payloadBytes)))
	if err != nil {
		log.Printf("创建 Alist 添加离线下载请求失败: %v", err)
		return false, fmt.Errorf("无法创建添加下载请求: %w", err)
	}
	req.Header.Set("Authorization", token) // Set Authorization header
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("添加 Alist 离线下载任务时网络错误: %v", err)
		// Clear token cache on network errors too, maybe token related?
		globalToken = ""
		return false, fmt.Errorf("添加 Alist 离线任务时出错: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("读取 Alist 添加离线下载响应体失败: %v", err)
		return false, fmt.Errorf("无法读取添加下载响应: %w", err)
	}

	// Check for specific error codes like 401 Unauthorized
	if resp.StatusCode == http.StatusUnauthorized {
		log.Println("Alist 返回 401 Unauthorized，Token 可能已过期或无效，清除缓存。")
		globalToken = "" // Clear cached token
		return false, fmt.Errorf("Alist 认证失败 (401)")
	}

	if resp.StatusCode != http.StatusOK {
		log.Printf("添加 Alist 离线下载任务 API 失败，状态码: %d, 响应: %s", resp.StatusCode, string(body))
		return false, fmt.Errorf("添加 Alist 离线任务 API 请求失败，状态码: %d", resp.StatusCode)
	}

	var result map[string]interface{}
	err = json.Unmarshal(body, &result)
	if err != nil {
		log.Printf("解析 Alist 添加离线下载响应 JSON 失败: %v, 响应: %s", err, string(body))
		return false, fmt.Errorf("无法解析添加下载响应 JSON: %w", err)
	}

	codeFloat, _ := result["code"].(float64)
	code := int(codeFloat)
	if code == 200 {
		log.Println("Alist 离线下载任务添加请求成功!")
		return true, nil
	}

	// Handle API level errors (code != 200)
	message := "未知 API 错误"
	if msg, ok := result["message"].(string); ok {
		message = msg
	}
	log.Printf("添加 Alist 离线下载任务 API 返回错误: %s (code: %d)", message, code)
	return false, fmt.Errorf("添加 Alist 离线任务 API 返回失败: %s", message)
}

// listDownloadDir lists the contents of the Alist offline download directory and forces a refresh.
// Returns the number of items found in the directory.
func listDownloadDir() (int, error) {
	token, err := getToken()
	if err != nil {
		return 0, fmt.Errorf("无法获取 Alist token: %w", err)
	}

	apiURL := config.BaseURL + "/api/fs/list"
	log.Printf("正在获取并刷新 Alist 目录内容: %s", config.OfflineDownloadDir)

	postData := map[string]interface{}{
		"path":     config.OfflineDownloadDir,
		"password": "", // Provide password if the directory is protected
		"page":     1,
		"per_page": 0,    // 0 means get all items (check Alist docs if this behavior changes)
		"refresh":  true, // Force refresh
	}
	payloadBytes, err := json.Marshal(postData)
	if err != nil {
		log.Printf("Alist 目录列表数据 JSON 编码失败: %v", err)
		return 0, fmt.Errorf("无法编码目录列表数据: %w", err)
	}

	client := &http.Client{Timeout: 45 * time.Second} // Refresh might take longer
	req, err := http.NewRequest("POST", apiURL, strings.NewReader(string(payloadBytes)))
	if err != nil {
		log.Printf("创建 Alist 目录列表请求失败: %v", err)
		return 0, fmt.Errorf("无法创建目录列表请求: %w", err)
	}
	req.Header.Set("Authorization", token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("获取 Alist 目录列表时网络错误: %v", err)
		if resp != nil && resp.StatusCode == http.StatusUnauthorized { // Check resp != nil
			log.Println("Alist 返回 401 Unauthorized，清除 token 缓存。")
			globalToken = ""
		}
		return 0, fmt.Errorf("获取 Alist 目录列表时出错: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("读取 Alist 目录列表响应体失败: %v", err)
		return 0, fmt.Errorf("无法读取目录列表响应: %w", err)
	}

	if resp.StatusCode == http.StatusUnauthorized {
		log.Println("Alist 返回 401 Unauthorized，清除 token 缓存。")
		globalToken = ""
		return 0, fmt.Errorf("Alist 认证失败 (401)")
	}

	if resp.StatusCode != http.StatusOK {
		log.Printf("获取 Alist 目录列表 API 失败，状态码: %d, 响应: %s", resp.StatusCode, string(body))
		return 0, fmt.Errorf("获取 Alist 目录列表 API 请求失败，状态码: %d", resp.StatusCode)
	}

	var result map[string]interface{}
	err = json.Unmarshal(body, &result)
	if err != nil {
		log.Printf("解析 Alist 目录列表响应 JSON 失败: %v, 响应: %s", err, string(body))
		return 0, fmt.Errorf("无法解析目录列表响应 JSON: %w", err)
	}

	codeFloat, _ := result["code"].(float64)
	code := int(codeFloat)
	if code != 200 {
		message := "未知 API 错误"
		if msg, ok := result["message"].(string); ok {
			message = msg
		}
		log.Printf("Alist 目录列表 API 返回错误: %s (code: %d)", message, code)
		return 0, fmt.Errorf("Alist 目录列表 API 返回错误: %s", message)
	}

	data, ok := result["data"].(map[string]interface{})
	if !ok {
		log.Printf("无法解析 Alist 目录列表响应中的 'data' 字段。响应: %s", string(body))
		return 0, fmt.Errorf("无法解析目录列表响应 'data'")
	}

	content, ok := data["content"].([]interface{})
	if !ok {
		// It's possible 'content' is null or not an array if the directory is empty or inaccessible
		log.Printf("Alist 目录 %s 内容为空或无法解析 ('content' 字段非数组或不存在)。", config.OfflineDownloadDir)
		return 0, nil // Empty directory is not an error
	}

	fileCount := len(content)
	log.Printf("Alist 目录 %s 刷新成功，当前包含 %d 个项目。", config.OfflineDownloadDir, fileCount)
	// Optional: Log file names for debugging
	// for i, item := range content {
	//     if fileInfo, ok := item.(map[string]interface{}); ok {
	//         if name, ok := fileInfo["name"].(string); ok {
	//             log.Printf("  - Item %d: %s", i+1, name)
	//         }
	//     }
	// }

	return fileCount, nil
}

// --- Mikan RSS & Persistence Functions ---

// fetchAndParseRSS fetches the Mikan RSS feed from the given URL and parses it.
func fetchAndParseRSS(rssFeedURL string) (*RSS, error) {
	log.Printf("正在从 %s 获取 Mikan RSS Feed...", rssFeedURL)
	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest("GET", rssFeedURL, nil)
	if err != nil {
		return nil, fmt.Errorf("创建 Mikan RSS 请求失败: %w", err)
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/xml, application/rss+xml;q=0.9, */*;q=0.8") // Standard Accept header

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("获取 Mikan RSS feed 失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body) // Read body for debugging
		log.Printf("Mikan RSS 请求失败，状态码: %d, 响应: %s", resp.StatusCode, string(bodyBytes))
		return nil, fmt.Errorf("获取 Mikan RSS feed 失败: status code %d", resp.StatusCode)
	}

	var feed RSS
	// Use a Decoder for potentially better handling of XML intricacies
	decoder := xml.NewDecoder(resp.Body)
	// Optional: Handle potential character encoding issues if Mikan RSS uses non-UTF8 encodings
	// decoder.CharsetReader = func(charset string, input io.Reader) (io.Reader, error) { ... }
	if err := decoder.Decode(&feed); err != nil {
		// Attempt to read body again if decoding failed, for debugging
		// Note: resp.Body might be partially consumed by the decoder already
		// resp.Body.Seek(0, io.SeekStart) // This won't work on network streams
		log.Printf("解析 Mikan RSS XML 失败: %v", err)
		// Consider logging the raw body if parsing fails consistently
		return nil, fmt.Errorf("解析 Mikan RSS XML 失败: %w", err)
	}

	log.Printf("成功获取并解析 Mikan RSS Feed: %s", feed.Channel.Title)
	return &feed, nil
}

// createMagnetLink constructs a magnet link from a torrent hash and title.
func createMagnetLink(hash, title string) string {
	// Ensure hash is uppercase (common practice for magnet links)
	upperHash := strings.ToUpper(hash)
	magnet := fmt.Sprintf("magnet:?xt=urn:btih:%s", upperHash)

	// Add Display Name (dn), URL-encoded
	if title != "" {
		// Basic cleanup for title before encoding
		cleanTitle := strings.ReplaceAll(title, "[", " ")
		cleanTitle = strings.ReplaceAll(cleanTitle, "]", " ")
		cleanTitle = strings.ReplaceAll(cleanTitle, "【", " ")
		cleanTitle = strings.ReplaceAll(cleanTitle, "】", " ")
		cleanTitle = strings.ReplaceAll(cleanTitle, "/", "_") // Replace slashes
		cleanTitle = strings.ReplaceAll(cleanTitle, "\\", "_")
		cleanTitle = strings.Join(strings.Fields(cleanTitle), " ") // Consolidate whitespace
		magnet += "&dn=" + url.QueryEscape(cleanTitle)
	}

	// Add trackers (tr), URL-encoded
	for _, tr := range trackers {
		magnet += "&tr=" + url.QueryEscape(tr)
	}

	return magnet
}

// loadProcessedHashes reads the processed hashes from the specified file.
// Returns a map where keys are the anime titles and values are arrays of processed hashes.
func loadProcessedHashes(filename string) (ProcessedHashesMap, error) {
	processedMap := make(ProcessedHashesMap)
	log.Printf("正在加载已处理的 Hashes 文件: %s", filename)

	file, err := os.Open(filename)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("文件 '%s' 不存在，将创建新的哈希记录。", filename)
			return processedMap, nil // Return empty map, not an error
		}
		// Other error opening file
		return nil, fmt.Errorf("打开文件 %s 时出错: %w", filename, err)
	}
	defer file.Close()

	// 使用JSON解码
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&processedMap)
	if err != nil {
		// 如果文件存在但格式不正确，记录警告但返回空Map
		log.Printf("警告: 解析哈希记录文件 %s 失败: %v，将使用新的空记录", filename, err)
		return make(ProcessedHashesMap), nil
	}

	// 计算总哈希数
	totalHashes := 0
	for _, hashes := range processedMap {
		totalHashes += len(hashes)
	}

	log.Printf("从 %s 成功加载了 %d 个番剧的总计 %d 个哈希值。",
		filename, len(processedMap), totalHashes)
	return processedMap, nil
}

// saveProcessedHashes saves the provided map of hashes to the specified file.
// It uses a temporary file and rename strategy for atomic-like saving.
func saveProcessedHashes(filename string, hashesMap ProcessedHashesMap) error {
	// 计算总哈希数
	totalHashes := 0
	for _, hashes := range hashesMap {
		totalHashes += len(hashes)
	}

	log.Printf("正在保存 %d 个番剧的总计 %d 个哈希值到文件: %s",
		len(hashesMap), totalHashes, filename)

	tempFilename := filename + ".tmp"
	file, err := os.OpenFile(tempFilename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("创建临时文件 %s 失败: %w", tempFilename, err)
	}

	// 确保清理临时文件
	defer func() {
		if err := file.Close(); err != nil {
			log.Printf("关闭临时文件 %s 时发生错误 (可能已在错误处理中关闭): %v", tempFilename, err)
		}

		// 如果临时文件还存在（重命名失败），则清理
		if _, statErr := os.Stat(tempFilename); statErr == nil {
			if removeErr := os.Remove(tempFilename); removeErr != nil {
				log.Printf("警告: 清理临时文件 %s 失败: %v", tempFilename, removeErr)
			}
		}
	}()

	// 使用JSON编码
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ") // 美化输出
	if err = encoder.Encode(hashesMap); err != nil {
		return fmt.Errorf("JSON编码哈希映射到临时文件 %s 时出错: %w", tempFilename, err)
	}

	// 关闭文件
	if err = file.Close(); err != nil {
		return fmt.Errorf("关闭临时文件 %s 时出错: %w", tempFilename, err)
	}

	// 重命名临时文件为目标文件
	if err = os.Rename(tempFilename, filename); err != nil {
		return fmt.Errorf("重命名临时文件 %s 到 %s 时出错: %w", tempFilename, filename, err)
	}

	log.Printf("成功保存哈希值映射到 %s。", filename)
	return nil
}

// monitorDownload 监控 Alist 下载目录中的文件数变化来判断下载是否完成
func monitorDownload(initialCount int) {
	log.Printf("开始监控下载目录 (初始文件数: %d)...", initialCount)

	lastCount := initialCount
	checkCount := 0
	maxChecks := 10 // 最多检查10次

	for checkCount < maxChecks {
		// 等待3秒
		time.Sleep(3 * time.Second)
		checkCount++

		// 获取当前目录文件数
		currentCount, err := listDownloadDir()
		if err != nil {
			log.Printf("监控时获取目录内容错误: %v, 将继续监控", err)
			continue
		}

		// 计算变化量
		change := currentCount - lastCount
		log.Printf("监控: 检查 %d/%d, 当前文件数=%d, 上次文件数=%d, 变化=%d",
			checkCount, maxChecks, currentCount, lastCount, change)

		// 如果文件数增加，认为有新下载完成
		if change > 0 {
			log.Printf("检测到新文件下载完成 (增加了 %d 个文件)", change)
		}

		// 更新上次的文件数
		lastCount = currentCount
	}

	log.Printf("文件监控结束，已完成 %d 次检查", maxChecks)
}

// checkAllRSS 轮询检查所有RSS链接
func checkAllRSS() (bool, error) {
	log.Println("开始轮询检查所有RSS链接...")

	// 1. 加载已处理哈希记录
	processedHashes, err := loadProcessedHashes(processedHashesFile)
	if err != nil {
		return false, fmt.Errorf("加载已处理哈希记录文件失败: %w", err)
	}

	// 追踪是否有任何新项目
	anyNewItems := false

	// 2. 遍历所有RSS链接
	for _, rssURL := range config.RssURLs {
		// 处理一个RSS链接
		hasNewItems, err := processSingleRSS(rssURL, processedHashes)
		if err != nil {
			log.Printf("处理RSS链接 %s 时出错: %v", rssURL, err)
			continue // 继续处理下一个RSS
		}

		if hasNewItems {
			anyNewItems = true
		}
	}

	// 3. 保存更新后的哈希记录
	if anyNewItems {
		err = saveProcessedHashes(processedHashesFile, processedHashes)
		if err != nil {
			log.Printf("警告: 保存处理哈希记录失败: %v", err)
		}
	}

	return anyNewItems, nil
}

// processSingleRSS 处理单个RSS链接的内容
func processSingleRSS(rssURL string, processedHashes ProcessedHashesMap) (bool, error) {
	log.Printf("处理RSS链接: %s", rssURL)

	// 1. 获取并解析RSS
	feed, err := fetchAndParseRSS(rssURL)
	if err != nil {
		return false, fmt.Errorf("获取或解析RSS失败: %w", err)
	}

	if feed == nil || len(feed.Channel.Items) == 0 {
		log.Printf("RSS feed为空或不包含任何项目: %s", rssURL)
		return false, nil
	}

	// 2. 从Channel Title解析番剧名称
	animeTitle := extractAnimeTitle(feed.Channel.Title)
	if animeTitle == "" {
		log.Printf("无法从RSS标题提取番剧名称: %s", feed.Channel.Title)
		animeTitle = "未知番剧_" + time.Now().Format("20060102")
	}

	log.Printf("处理番剧: %s", animeTitle)

	// 3. 确保已处理哈希表中有该番剧的条目
	if _, exists := processedHashes[animeTitle]; !exists {
		processedHashes[animeTitle] = []string{}
	}

	// 4. 创建番剧文件夹
	folderCreated, err := createAnimeFolder(animeTitle)
	if err != nil || !folderCreated {
		log.Printf("创建番剧文件夹失败: %v", err)
		// 继续处理，尝试直接上传到根目录
	}

	// 5. 获取文件夹中当前文件数，用于后续监控
	initialCount, err := getAnimeFolderFileCount(animeTitle)
	if err != nil {
		log.Printf("获取番剧文件夹初始文件数失败: %v", err)
		initialCount = 0
	}

	// 6. 处理所有未处理的项目
	hasNewItems := false
	var newItems []Item

	for _, item := range feed.Channel.Items {
		// 提取哈希
		itemHash := path.Base(item.Link)
		if len(itemHash) != 40 {
			log.Printf("警告: 从链接 '%s' 提取的哈希 '%s' 格式无效 (长度不为40)，跳过此项目",
				item.Link, itemHash)
			continue
		}

		// 检查是否已处理
		isProcessed := false
		for _, hash := range processedHashes[animeTitle] {
			if hash == itemHash {
				isProcessed = true
				break
			}
		}

		if isProcessed {
			log.Printf("哈希 %s 已处理，跳过此项目: %s", itemHash, item.Title)
			continue
		}

		// 收集新项目
		newItems = append(newItems, item)
		hasNewItems = true
	}

	// 7. 处理所有新项目
	if len(newItems) > 0 {
		log.Printf("发现 %d 个新项目，开始处理...", len(newItems))

		// 按照时间间隔上传所有新项目
		for i, item := range newItems {
			itemHash := path.Base(item.Link)
			log.Printf("处理新项目 %d/%d: %s", i+1, len(newItems), item.Title)

			// 生成磁力链接
			magnetLink := createMagnetLink(itemHash, item.Title)

			// 添加磁力链接到Alist指定文件夹
			success, addErr := addMagnet(magnetLink, animeTitle)
			if !success {
				log.Printf("添加项目到Alist失败: %v", addErr)
				continue // 继续处理下一个
			}

			log.Printf("成功将磁力链接添加到Alist (哈希: %s)", itemHash)

			// 将哈希添加到已处理列表
			processedHashes[animeTitle] = append(processedHashes[animeTitle], itemHash)

			// 如果还有更多项目要处理，等待uploadInterval时间
			if i < len(newItems)-1 {
				log.Printf("等待 %s 后继续上传下一个项目...", uploadInterval)
				time.Sleep(uploadInterval)
			}
		}

		// 8. 监控下载
		if initialCount >= 0 {
			go monitorDownloadFolder(animeTitle, initialCount)
		}
	} else {
		log.Printf("番剧 %s 没有新项目需要处理", animeTitle)
	}

	return hasNewItems, nil
}

// extractAnimeTitle 从RSS标题中提取番剧名称
func extractAnimeTitle(channelTitle string) string {
	// 从 "Mikan Project - 番剧名称" 格式中提取番剧名称
	if strings.HasPrefix(channelTitle, "Mikan Project - ") {
		return strings.TrimPrefix(channelTitle, "Mikan Project - ")
	}
	return channelTitle
}

// getAnimeFolderFileCount 获取番剧文件夹中的文件数
func getAnimeFolderFileCount(animeTitle string) (int, error) {
	if animeTitle == "" {
		return listDownloadDir()
	}

	folderPath := path.Join(config.OfflineDownloadDir, animeTitle)
	token, err := getToken()
	if err != nil {
		return -1, fmt.Errorf("获取 Alist token 失败: %w", err)
	}

	apiURL := config.BaseURL + "/api/fs/list"
	log.Printf("正在获取并刷新文件夹内容: %s", folderPath)

	postData := map[string]interface{}{
		"path":     folderPath,
		"password": "",
		"page":     1,
		"per_page": 0,
		"refresh":  true,
	}

	payloadBytes, err := json.Marshal(postData)
	if err != nil {
		log.Printf("目录列表数据 JSON 编码失败: %v", err)
		return -1, fmt.Errorf("编码目录列表数据失败: %w", err)
	}

	client := &http.Client{Timeout: 45 * time.Second}
	req, err := http.NewRequest("POST", apiURL, strings.NewReader(string(payloadBytes)))
	if err != nil {
		log.Printf("创建目录列表请求失败: %v", err)
		return -1, fmt.Errorf("创建目录列表请求失败: %w", err)
	}

	req.Header.Set("Authorization", token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("获取目录列表时网络错误: %v", err)
		return -1, fmt.Errorf("获取目录列表失败: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("读取目录列表响应失败: %v", err)
		return -1, fmt.Errorf("读取目录列表响应失败: %w", err)
	}

	if resp.StatusCode == http.StatusUnauthorized {
		log.Println("Alist 返回 401 Unauthorized，清除 token 缓存")
		globalToken = ""
		return -1, fmt.Errorf("Alist 认证失败 (401)")
	}

	if resp.StatusCode != http.StatusOK {
		log.Printf("获取目录列表 API 失败，状态码: %d, 响应: %s", resp.StatusCode, string(body))
		return -1, fmt.Errorf("获取目录列表 API 失败，状态码: %d", resp.StatusCode)
	}

	var result map[string]interface{}
	err = json.Unmarshal(body, &result)
	if err != nil {
		log.Printf("解析目录列表响应 JSON 失败: %v, 响应: %s", err, string(body))
		return -1, fmt.Errorf("解析目录列表响应失败: %w", err)
	}

	codeFloat, _ := result["code"].(float64)
	code := int(codeFloat)
	if code != 200 {
		message := "未知 API 错误"
		if msg, ok := result["message"].(string); ok {
			message = msg
		}
		log.Printf("目录列表 API 返回错误: %s (code: %d)", message, code)
		return -1, fmt.Errorf("目录列表 API 返回错误: %s", message)
	}

	data, ok := result["data"].(map[string]interface{})
	if !ok {
		log.Printf("无法解析目录列表响应中的 'data' 字段")
		return -1, fmt.Errorf("无法解析目录列表响应中的 'data' 字段")
	}

	content, ok := data["content"].([]interface{})
	if !ok {
		// 如果目录为空，返回0
		return 0, nil
	}

	fileCount := len(content)
	log.Printf("文件夹 %s 刷新成功，当前包含 %d 个项目", folderPath, fileCount)
	return fileCount, nil
}

// monitorDownloadFolder 监控特定文件夹的下载变化
func monitorDownloadFolder(animeTitle string, initialCount int) {
	folderPath := animeTitle
	if animeTitle == "" {
		folderPath = config.OfflineDownloadDir
	} else {
		folderPath = path.Join(config.OfflineDownloadDir, animeTitle)
	}

	log.Printf("开始监控下载文件夹 %s (初始文件数: %d)...", folderPath, initialCount)

	lastCount := initialCount
	checkCount := 0
	maxChecks := 10 // 最多检查10次

	for checkCount < maxChecks {
		// 等待3秒
		time.Sleep(3 * time.Second)
		checkCount++

		// 获取当前文件数
		currentCount, err := getAnimeFolderFileCount(animeTitle)
		if err != nil {
			log.Printf("监控时获取文件夹 %s 内容错误: %v, 将继续监控", folderPath, err)
			continue
		}

		// 计算变化量
		change := currentCount - lastCount
		log.Printf("监控 %s: 检查 %d/%d, 当前文件数=%d, 上次文件数=%d, 变化=%d",
			folderPath, checkCount, maxChecks, currentCount, lastCount, change)

		// 如果文件数增加，认为有新下载完成
		if change > 0 {
			log.Printf("检测到文件夹 %s 中新文件下载完成 (增加了 %d 个文件)", folderPath, change)
		}

		// 更新上次文件数
		lastCount = currentCount
	}

	log.Printf("文件夹 %s 监控结束，已完成 %d 次检查", folderPath, maxChecks)
}

// createAnimeFolder 在Alist中创建番剧文件夹
func createAnimeFolder(animeTitle string) (bool, error) {
	// 获取token
	token, err := getToken()
	if err != nil {
		return false, fmt.Errorf("获取 Alist token 失败: %w", err)
	}

	// 构建完整路径
	folderPath := path.Join(config.OfflineDownloadDir, animeTitle)

	// 先检查文件夹是否已存在
	exists, err := checkFolderExists(folderPath)
	if err != nil {
		log.Printf("检查文件夹 %s 是否存在时出错: %v", folderPath, err)
	}

	if exists {
		log.Printf("文件夹 %s 已存在，无需创建", folderPath)
		return true, nil
	}

	log.Printf("正在创建番剧文件夹: %s", folderPath)

	// 准备请求
	apiURL := config.BaseURL + "/api/fs/mkdir"
	postData := map[string]string{
		"path": folderPath,
	}

	payloadBytes, err := json.Marshal(postData)
	if err != nil {
		log.Printf("创建文件夹数据 JSON 编码失败: %v", err)
		return false, fmt.Errorf("编码创建文件夹数据失败: %w", err)
	}

	// 发送请求
	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequest("POST", apiURL, strings.NewReader(string(payloadBytes)))
	if err != nil {
		log.Printf("创建文件夹请求失败: %v", err)
		return false, fmt.Errorf("创建文件夹请求失败: %w", err)
	}

	req.Header.Set("Authorization", token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)

	// 发送请求
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("创建文件夹时网络错误: %v", err)
		// 清除token缓存
		globalToken = ""
		return false, fmt.Errorf("创建文件夹网络错误: %w", err)
	}
	defer resp.Body.Close()

	// 读取响应
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("读取创建文件夹响应失败: %v", err)
		return false, fmt.Errorf("读取创建文件夹响应失败: %w", err)
	}

	// 检查认证错误
	if resp.StatusCode == http.StatusUnauthorized {
		log.Println("Alist 返回 401 Unauthorized，Token 可能已过期，清除缓存")
		globalToken = ""
		return false, fmt.Errorf("Alist 认证失败 (401)")
	}

	// 检查其他HTTP错误
	if resp.StatusCode != http.StatusOK {
		log.Printf("创建文件夹 API 失败，状态码: %d, 响应: %s", resp.StatusCode, string(body))
		return false, fmt.Errorf("创建文件夹 API 失败，状态码: %d", resp.StatusCode)
	}

	// 解析响应
	var result map[string]interface{}
	err = json.Unmarshal(body, &result)
	if err != nil {
		log.Printf("解析创建文件夹响应 JSON 失败: %v, 响应: %s", err, string(body))
		return false, fmt.Errorf("解析创建文件夹响应失败: %w", err)
	}

	// 检查API错误
	codeFloat, _ := result["code"].(float64)
	code := int(codeFloat)
	if code == 200 {
		log.Printf("成功创建番剧文件夹: %s", folderPath)
		return true, nil
	}

	// 处理API错误
	message := "未知API错误"
	if msg, ok := result["message"].(string); ok {
		message = msg
	}

	// 如果错误是因为文件夹已存在，也视为成功
	if strings.Contains(strings.ToLower(message), "already exists") ||
		strings.Contains(strings.ToLower(message), "已存在") {
		log.Printf("文件夹 %s 已存在，无需创建", folderPath)
		return true, nil
	}

	log.Printf("创建文件夹 API 返回错误: %s (code: %d)", message, code)
	return false, fmt.Errorf("创建文件夹 API 返回错误: %s", message)
}

// checkFolderExists 检查Alist中文件夹是否存在
func checkFolderExists(folderPath string) (bool, error) {
	// 尝试获取目录列表来检查文件夹是否存在
	token, err := getToken()
	if err != nil {
		return false, fmt.Errorf("获取 Alist token 失败: %w", err)
	}

	// 先检查父目录是否存在该文件夹
	parentDir := path.Dir(folderPath)
	folderName := path.Base(folderPath)

	apiURL := config.BaseURL + "/api/fs/list"

	postData := map[string]interface{}{
		"path":     parentDir,
		"password": "",
		"page":     1,
		"per_page": 0,    // 获取所有项目
		"refresh":  true, // 强制刷新
	}

	payloadBytes, err := json.Marshal(postData)
	if err != nil {
		log.Printf("目录列表数据 JSON 编码失败: %v", err)
		return false, fmt.Errorf("编码目录列表数据失败: %w", err)
	}

	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequest("POST", apiURL, strings.NewReader(string(payloadBytes)))
	if err != nil {
		log.Printf("创建目录列表请求失败: %v", err)
		return false, fmt.Errorf("创建目录列表请求失败: %w", err)
	}

	req.Header.Set("Authorization", token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("获取目录列表时网络错误: %v", err)
		return false, fmt.Errorf("获取目录列表网络错误: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("读取目录列表响应失败: %v", err)
		return false, fmt.Errorf("读取目录列表响应失败: %w", err)
	}

	if resp.StatusCode == http.StatusUnauthorized {
		log.Println("Alist 返回 401 Unauthorized，清除 token 缓存")
		globalToken = ""
		return false, fmt.Errorf("Alist 认证失败 (401)")
	}

	if resp.StatusCode != http.StatusOK {
		log.Printf("获取目录列表 API 失败，状态码: %d, 响应: %s", resp.StatusCode, string(body))
		return false, fmt.Errorf("获取目录列表 API 失败，状态码: %d", resp.StatusCode)
	}

	var result map[string]interface{}
	err = json.Unmarshal(body, &result)
	if err != nil {
		log.Printf("解析目录列表响应 JSON 失败: %v, 响应: %s", err, string(body))
		return false, fmt.Errorf("解析目录列表响应失败: %w", err)
	}

	codeFloat, _ := result["code"].(float64)
	code := int(codeFloat)
	if code != 200 {
		message := "未知 API 错误"
		if msg, ok := result["message"].(string); ok {
			message = msg
		}
		log.Printf("目录列表 API 返回错误: %s (code: %d)", message, code)
		return false, fmt.Errorf("目录列表 API 返回错误: %s", message)
	}

	data, ok := result["data"].(map[string]interface{})
	if !ok {
		log.Printf("无法解析目录列表响应中的 'data' 字段")
		return false, fmt.Errorf("无法解析目录列表响应中的 'data' 字段")
	}

	content, ok := data["content"].([]interface{})
	if !ok {
		// 如果目录为空，则文件夹不存在
		return false, nil
	}

	// 检查文件夹是否存在
	for _, item := range content {
		if fileInfo, ok := item.(map[string]interface{}); ok {
			if name, ok := fileInfo["name"].(string); ok && name == folderName {
				// 检查这是否是一个文件夹
				if typeStr, ok := fileInfo["type"].(float64); ok && typeStr == 1 {
					// 是文件夹类型
					return true, nil
				}
			}
		}
	}

	return false, nil
}

// --- Web Interface Templates ---

// 首页模板
const indexTemplate = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Mikan RSS 管理器</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        h1, h2, h3 {
            color: #2c3e50;
        }
        .container {
            background: #f9f9f9;
            border-radius: 5px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .form-group {
            margin-bottom: 15px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
        }
        input[type="text"], 
        input[type="number"] {
            width: 100%;
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 4px;
            box-sizing: border-box;
        }
        .rss-list {
            margin-top: 10px;
        }
        .rss-item {
            display: flex;
            margin-bottom: 10px;
        }
        .rss-item input {
            flex-grow: 1;
            margin-right: 10px;
        }
        .btn {
            padding: 8px 12px;
            background: #3498db;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
        }
        .btn:hover {
            background: #2980b9;
        }
        .btn-danger {
            background: #e74c3c;
        }
        .btn-danger:hover {
            background: #c0392b;
        }
        .btn-add {
            margin-top: 10px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        th, td {
            text-align: left;
            padding: 12px;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #f2f2f2;
        }
        tr:hover {
            background-color: #f5f5f5;
        }
        .status {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 14px;
        }
        .status-success {
            background-color: #2ecc71;
            color: white;
        }
        .status-warning {
            background-color: #f39c12;
            color: white;
        }
        .status-error {
            background-color: #e74c3c;
            color: white;
        }
        .anime-table {
            margin-top: 30px;
        }
        .message {
            padding: 10px;
            margin-bottom: 20px;
            border-radius: 4px;
        }
        .message-success {
            background-color: #d4edda;
            border-color: #c3e6cb;
            color: #155724;
        }
        .message-error {
            background-color: #f8d7da;
            border-color: #f5c6cb;
            color: #721c24;
        }
    </style>
</head>
<body>
    <h1>Mikan RSS 管理器</h1>
    
    {{if .Message}}
    <div class="message {{if .IsError}}message-error{{else}}message-success{{end}}">
        {{.Message}}
    </div>
    {{end}}
    
    <div class="container">
        <h2>配置设置</h2>
        <form action="/save-config" method="POST">
            <div class="form-group">
                <label for="offlineDir">下载目录:</label>
                <input type="text" id="offlineDir" name="offlineDir" value="{{.Config.OfflineDownloadDir}}" required>
            </div>
            
            <div class="form-group">
                <label for="checkInterval">检查间隔 (分钟):</label>
                <input type="number" id="checkInterval" name="checkInterval" value="{{.Config.CheckInterval}}" min="1" required>
            </div>
            
            <div class="form-group">
                <label>RSS 链接:</label>
                <div class="rss-list" id="rssContainer">
                    {{range $index, $url := .Config.RssURLs}}
                    <div class="rss-item">
                        <input type="text" name="rssURLs[]" value="{{$url}}" placeholder="https://mikanani.me/RSS/..." required>
                        <button type="button" class="btn btn-danger" onclick="removeRssField(this)">删除</button>
                    </div>
                    {{end}}
                </div>
                <button type="button" class="btn btn-add" onclick="addRssField()">添加 RSS 链接</button>
            </div>
            
            <div class="form-group">
                <button type="submit" class="btn">保存配置</button>
                <button type="button" class="btn" onclick="location.href='/check-now'">立即检查</button>
            </div>
        </form>
    </div>
    
    <div class="container">
        <h2>番剧状态</h2>
        <table class="anime-table">
            <thead>
                <tr>
                    <th>番剧名称</th>
                    <th>已处理集数</th>
                    <th>最后更新</th>
                </tr>
            </thead>
            <tbody>
                {{range $name, $episodes := .ProcessedItems}}
                <tr>
                    <td>{{$name}}</td>
                    <td>{{len $episodes}}</td>
                    <td>{{index $episodes 0}}</td>
                </tr>
                {{else}}
                <tr>
                    <td colspan="3">暂无数据</td>
                </tr>
                {{end}}
            </tbody>
        </table>
    </div>
    
    <script>
        function addRssField() {
            const container = document.getElementById('rssContainer');
            const newItem = document.createElement('div');
            newItem.className = 'rss-item';
            newItem.innerHTML = '<input type="text" name="rssURLs[]" placeholder="https://mikanani.me/RSS/..." required><button type="button" class="btn btn-danger" onclick="removeRssField(this)">删除</button>';
            container.appendChild(newItem);
        }
        
        function removeRssField(button) {
            const item = button.parentElement;
            item.parentElement.removeChild(item);
        }
        
        // 至少需要一个RSS链接
        document.querySelector('form').addEventListener('submit', function(e) {
            const rssInputs = document.querySelectorAll('input[name="rssURLs[]"]');
            if (rssInputs.length === 0) {
                e.preventDefault();
                alert('请至少添加一个RSS链接');
            }
        });
    </script>
</body>
</html>
`

// --- Web Server Handlers ---

// 首页数据
type IndexData struct {
	Config         Config
	ProcessedItems ProcessedHashesMap
	Message        string
	IsError        bool
}

// 启动Web服务器
func startWebServer() {
	port := config.WebPort
	log.Printf("启动Web管理界面，监听端口 %d...", port)

	// 注册路由
	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/save-config", handleSaveConfig)
	http.HandleFunc("/check-now", handleCheckNow)

	// 启动服务器
	go func() {
		err := http.ListenAndServe(fmt.Sprintf(":%d", port), nil)
		if err != nil {
			log.Fatalf("启动Web服务器失败: %v", err)
		}
	}()
}

// 首页处理
func handleIndex(w http.ResponseWriter, r *http.Request) {
	// 创建模板
	tmpl, err := template.New("index").Parse(indexTemplate)
	if err != nil {
		http.Error(w, "模板加载失败", http.StatusInternalServerError)
		log.Printf("模板加载失败: %v", err)
		return
	}

	// 获取已处理的集数
	processedItems, err := loadProcessedHashes(processedHashesFile)
	if err != nil {
		processedItems = make(ProcessedHashesMap)
		log.Printf("加载处理记录失败: %v", err)
	}

	// 获取消息参数
	message := r.URL.Query().Get("message")
	isError := r.URL.Query().Get("error") == "true"

	// 准备数据
	configMutex.RLock()
	data := IndexData{
		Config:         config,
		ProcessedItems: processedItems,
		Message:        message,
		IsError:        isError,
	}
	configMutex.RUnlock()

	// 渲染模板
	err = tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, "模板渲染失败", http.StatusInternalServerError)
		log.Printf("模板渲染失败: %v", err)
	}
}

// 保存配置处理
func handleSaveConfig(w http.ResponseWriter, r *http.Request) {
	// 仅接受POST请求
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/?message=请使用POST请求提交表单&error=true", http.StatusSeeOther)
		return
	}

	// 解析表单
	err := r.ParseForm()
	if err != nil {
		http.Redirect(w, r, "/?message=表单解析失败&error=true", http.StatusSeeOther)
		return
	}

	// 获取下载目录
	offlineDir := r.FormValue("offlineDir")
	if offlineDir == "" {
		http.Redirect(w, r, "/?message=下载目录不能为空&error=true", http.StatusSeeOther)
		return
	}

	// 获取检查间隔
	checkIntervalStr := r.FormValue("checkInterval")
	checkInterval, err := strconv.Atoi(checkIntervalStr)
	if err != nil || checkInterval <= 0 {
		http.Redirect(w, r, "/?message=检查间隔必须是正整数&error=true", http.StatusSeeOther)
		return
	}

	// 获取RSS链接
	rssURLs := r.Form["rssURLs[]"]
	if len(rssURLs) == 0 {
		http.Redirect(w, r, "/?message=至少需要一个RSS链接&error=true", http.StatusSeeOther)
		return
	}

	// 更新配置
	err = updateConfig(offlineDir, checkInterval, rssURLs)
	if err != nil {
		http.Redirect(w, r, fmt.Sprintf("/?message=保存配置失败: %s&error=true", err.Error()), http.StatusSeeOther)
		return
	}

	// 重定向回首页
	http.Redirect(w, r, "/?message=配置已成功保存", http.StatusSeeOther)
}

// 立即检查处理
func handleCheckNow(w http.ResponseWriter, r *http.Request) {
	// 执行RSS检查
	go func() {
		newItemFound, err := checkAllRSS()
		if err != nil {
			log.Printf("手动执行RSS检查失败: %v", err)
		} else if newItemFound {
			log.Printf("手动检查发现新项目，已添加到下载队列")
		} else {
			log.Printf("手动检查未发现新项目")
		}
	}()

	// 重定向回首页
	http.Redirect(w, r, "/?message=已开始执行RSS检查，请稍后刷新查看结果", http.StatusSeeOther)
}

// --- Main Execution ---

func main() {
	log.Println("--- Mikan RSS to Alist Uploader v1.4 ---")
	log.Println("服务启动，将以后台模式持续运行...")

	// 1. 加载 Alist 配置
	err := loadConfig()
	if err != nil {
		log.Fatalf("初始化失败: Alist 配置错误: %v", err)
	}

	// 检查是否有RSS链接配置
	if len(config.RssURLs) == 0 {
		log.Fatalf("错误: 未配置RSS链接，请配置MIKAN_RSS_URLS或MIKAN_RSS_URL环境变量")
	}
	log.Printf("已配置 %d 个RSS链接", len(config.RssURLs))

	// 初始化下载目录
	_, err = listDownloadDir()
	if err != nil {
		log.Printf("警告: 初始化时获取下载目录内容失败: %v", err)
	}

	// 启动Web服务器
	startWebServer()

	// 立即执行一次检查，看是否有新项目
	newItemFound, checkErr := checkAllRSS()
	if checkErr != nil {
		log.Printf("首次 RSS 检查错误: %v", checkErr)
	} else if newItemFound {
		log.Printf("首次检查发现新项目，已添加到下载队列")
	} else {
		log.Printf("首次检查未发现新项目")
	}

	// 主循环：定期检查 RSS
	ticker := time.NewTicker(time.Duration(config.CheckInterval) * time.Minute)
	defer ticker.Stop()

	log.Printf("进入主循环，每 %d 分钟检查一次 RSS Feed", config.CheckInterval)

	// 如果配置更新，应用新的检查间隔
	go func() {
		for {
			time.Sleep(30 * time.Second) // 每30秒检查一次配置更改

			if isConfigChanged {
				log.Println("检测到配置更改，更新检查间隔...")
				configMutex.RLock()
				newInterval := config.CheckInterval
				configMutex.RUnlock()

				// 重新设置ticker
				ticker.Reset(time.Duration(newInterval) * time.Minute)
				log.Printf("检查间隔已更新为 %d 分钟", newInterval)

				isConfigChanged = false
			}
		}
	}()

	for range ticker.C {
		startTime := time.Now()
		log.Printf("定时 RSS 检查开始...")

		newItemFound, checkErr := checkAllRSS()
		if checkErr != nil {
			log.Printf("RSS 检查错误: %v", checkErr)
		} else if newItemFound {
			log.Printf("检查发现新项目，已添加到下载队列")
		} else {
			log.Printf("检查未发现新项目")
		}

		log.Printf("RSS 检查完成 (耗时: %s)，等待下一个检查周期", time.Since(startTime))
	}
}
