package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os/exec"
	"regexp"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

//go:embed index.html
var content embed.FS

type WireguardManager struct {
	client *wgctrl.Client
}

func NewWireguardManager() (*WireguardManager, error) {
	client, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("无法创建 WireGuard 客户端: %v", err)
	}
	return &WireguardManager{client: client}, nil
}

func (wg *WireguardManager) Close() {
	wg.client.Close()
}

// 创建新的 WireGuard 接口
func (wg *WireguardManager) CreateInterface(name string, port int, privateKey string) error {
	key, err := wgtypes.ParseKey(privateKey)
	if err != nil {
		return fmt.Errorf("私钥格式错误: %v", err)
	}

	config := wgtypes.Config{
		PrivateKey: &key,
		ListenPort: &port,
	}

	err = wg.client.ConfigureDevice(name, config)
	if err != nil {
		return fmt.Errorf("配置接口失败: %v", err)
	}
	return nil
}

// 添加对等点
func (wg *WireguardManager) AddPeer(interfaceName string, publicKey string, allowedIPs []string, endpoint string) error {
	key, err := wgtypes.ParseKey(publicKey)
	if err != nil {
		return fmt.Errorf("公钥格式错误: %v", err)
	}

	// 解析 endpoint
	endpointAddr, err := net.ResolveUDPAddr("udp", endpoint)
	if err != nil {
		return fmt.Errorf("endpoint 格式错误: %v", err)
	}

	// 解析 allowedIPs
	var cidrs []net.IPNet
	for _, ip := range allowedIPs {
		_, cidr, err := net.ParseCIDR(ip)
		if err != nil {
			return fmt.Errorf("IP 格式错误: %v", err)
		}
		cidrs = append(cidrs, *cidr)
	}

	peer := wgtypes.PeerConfig{
		PublicKey:         key,
		AllowedIPs:        cidrs,
		Endpoint:          endpointAddr,
		ReplaceAllowedIPs: true,
	}

	config := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peer},
	}

	err = wg.client.ConfigureDevice(interfaceName, config)
	if err != nil {
		return fmt.Errorf("添加对等点失败: %v", err)
	}
	return nil
}

// WireguardStatus 表示 WireGuard 状态的结构体
type WireguardStatus struct {
	Name       string       `json:"name"`
	PublicKey  string       `json:"public_key"`
	ListenPort int          `json:"listen_port"`
	Peers      []PeerStatus `json:"peers"`
}

// PeerStatus 表示对等点状态的���构体
type PeerStatus struct {
	PublicKey         string   `json:"public_key"`
	Endpoint          string   `json:"endpoint"`
	LastHandshakeTime string   `json:"last_handshake_time"`
	TransmitBytes     int64    `json:"transmit_bytes"`
	ReceiveBytes      int64    `json:"receive_bytes"`
	AllowedIPs        []string `json:"allowed_ips"`
}

// GetInterfaceStatusJSON 返回接口状态的 JSON 格式
func (wg *WireguardManager) GetInterfaceStatusJSON(name string) (*WireguardStatus, error) {
	device, err := wg.client.Device(name)
	if err != nil {
		return nil, fmt.Errorf("获取接口状态失败: %v", err)
	}

	status := &WireguardStatus{
		Name:       device.Name,
		PublicKey:  device.PublicKey.String(),
		ListenPort: device.ListenPort,
		Peers:      make([]PeerStatus, 0),
	}

	for _, peer := range device.Peers {
		peerStatus := PeerStatus{
			PublicKey:         peer.PublicKey.String(),
			LastHandshakeTime: peer.LastHandshakeTime.String(),
			TransmitBytes:     peer.TransmitBytes,
			ReceiveBytes:      peer.ReceiveBytes,
			AllowedIPs:        make([]string, 0),
		}
		if peer.Endpoint != nil {
			peerStatus.Endpoint = peer.Endpoint.String()
		}
		for _, ip := range peer.AllowedIPs {
			peerStatus.AllowedIPs = append(peerStatus.AllowedIPs, ip.String())
		}
		status.Peers = append(status.Peers, peerStatus)
	}

	return status, nil
}

// GetAllInterfaces 获取所有 WireGuard 接口
func (wg *WireguardManager) GetAllInterfaces() ([]string, error) {
	devices, err := wg.client.Devices()
	if err != nil {
		return nil, fmt.Errorf("获取接口列表失败: %v", err)
	}
	interfaces := make([]string, len(devices))
	for i, device := range devices {
		interfaces[i] = device.Name
	}
	return interfaces, nil
}

// Bird2Manager 用于管理 Bird2 相关操作
type Bird2Manager struct {
	birdCmd string
}

// NewBird2Manager 创建新的 Bird2 管理器
func NewBird2Manager() *Bird2Manager {
	return &Bird2Manager{
		birdCmd: "birdc",
	}
}

// ExecuteCommand 执行 Bird2 命令
func (b *Bird2Manager) ExecuteCommand(cmd string) (string, error) {
	// 构建完整命令
	fullCmd := exec.Command(b.birdCmd, cmd)
	output, err := fullCmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("执行命令失败: %v", err)
	}
	return string(output), nil
}

// HTTPServer 处理 HTTP 请求的结构体
type HTTPServer struct {
	wg   *WireguardManager
	bird *Bird2Manager
}

// NewHTTPServer 创建新的 HTTP 服务器
func NewHTTPServer(wg *WireguardManager, bird *Bird2Manager) *HTTPServer {
	return &HTTPServer{wg: wg, bird: bird}
}

// handleStatus 处理状态请求
func (s *HTTPServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "只支持 GET 请求", http.StatusMethodNotAllowed)
		return
	}

	interfaceName := r.URL.Query().Get("interface")
	if interfaceName == "" {
		interfaceName = "wg0" // 默认接口名
	}

	status, err := s.wg.GetInterfaceStatusJSON(interfaceName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

// handleIndex 处理根路径请求
func (s *HTTPServer) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	data, err := content.ReadFile("index.html")
	if err != nil {
		http.Error(w, "无法读取页面", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(data)
}

// handleInterfaces 处理获取接口列表的请求
func (s *HTTPServer) handleInterfaces(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "只支持 GET 请求", http.StatusMethodNotAllowed)
		return
	}

	interfaces, err := s.wg.GetAllInterfaces()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(interfaces)
}

// BirdProtocol 表示 Bird 协议的结构
type BirdProtocol struct {
	Name       string `json:"name"`
	Protocol   string `json:"protocol"`
	State      string `json:"state"`
	Since      string `json:"since"`
	Info       string `json:"info"`
	StateClass string `json:"state_class"` // 用于前端显示不同状态的样式
}

// BirdRoute 表示路由条目的结构
type BirdRoute struct {
	Network  string        `json:"network"`
	Protocol string        `json:"protocol"`
	Since    string        `json:"since"`
	Primary  bool          `json:"primary"`
	Metric   string        `json:"metric"`
	ASPath   string        `json:"as_path"`
	NextHops []BirdNextHop `json:"next_hops"`
}

// BirdNextHop 表示下一跳信息
type BirdNextHop struct {
	Via       string `json:"via"`
	Interface string `json:"interface"`
	From      string `json:"from,omitempty"`
}

// BirdStatus 表示 Bird 状态的结构
type BirdStatus struct {
	RouterID    string `json:"router_id"`
	ServerTime  string `json:"server_time"`
	LastReboot  string `json:"last_reboot"`
	LastReconf  string `json:"last_reconf"`
	Version     string `json:"version"`
	MemoryUsage string `json:"memory_usage"`
}

// BirdMemory 表示内存使用情况的结构
type BirdMemory struct {
	Categories []BirdMemoryCategory `json:"categories"`
	Total      BirdMemoryUsage      `json:"total"`
}

// BirdMemoryCategory 表示内存使用类别
type BirdMemoryCategory struct {
	Name  string          `json:"name"`
	Usage BirdMemoryUsage `json:"usage"`
}

// BirdMemoryUsage 表示内存使用量
type BirdMemoryUsage struct {
	Effective string `json:"effective"`
	Overhead  string `json:"overhead"`
}

// parseBirdOutput 解析 Bird 命令输出
func parseBirdOutput(cmd, output string) (interface{}, error) {
	switch cmd {
	case "show protocols":
		return parseBirdProtocols(output)
	case "show route":
		return parseBirdRoutes(output)
	case "show status":
		return parseBirdStatus(output)
	case "show memory":
		return parseBirdMemory(output)
	default:
		return map[string]string{"raw": output}, nil
	}
}

// parseBirdProtocols 解析协议信息
func parseBirdProtocols(output string) ([]BirdProtocol, error) {
	lines := strings.Split(output, "\n")
	protocols := make([]BirdProtocol, 0)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "BIRD") || strings.HasPrefix(line, "Name") || strings.HasPrefix(line, "name") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		// 跳过 device1 记录
		if fields[0] == "device1" {
			continue
		}

		protocol := BirdProtocol{
			Name:     fields[0],
			Protocol: fields[1],
			State:    fields[3],
			Since:    fields[4],
		}

		// 添加额外信息
		if len(fields) > 5 {
			protocol.Info = strings.Join(fields[5:], " ")
		}

		// 设置状态样式类
		switch strings.ToLower(protocol.State) {
		case "up":
			protocol.StateClass = "success"
		case "down":
			protocol.StateClass = "error"
		case "start":
			protocol.StateClass = "warning"
		default:
			protocol.StateClass = "info"
		}

		protocols = append(protocols, protocol)
	}

	return protocols, nil
}

// parseBirdRoutes 解析路由信息
func parseBirdRoutes(output string) ([]BirdRoute, error) {
	lines := strings.Split(output, "\n")
	routes := make([]BirdRoute, 0)
	var currentRoute *BirdRoute

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "BIRD") || strings.HasPrefix(line, "Table") {
			continue
		}

		// 检查是否是新路由条目
		if !strings.HasPrefix(line, " ") && strings.Contains(line, "/") {
			if currentRoute != nil {
				routes = append(routes, *currentRoute)
			}
			currentRoute = &BirdRoute{NextHops: make([]BirdNextHop, 0)}

			// 解析网络地址
			parts := strings.Fields(line)
			currentRoute.Network = parts[0]

			// 解析协议信息
			if idx := strings.Index(line, "["); idx > 0 {
				protocolInfo := line[idx:]
				// 提取协议名称和时间
				if protoMatch := regexp.MustCompile(`\[(.*?)\s+(.*?)\]`).FindStringSubmatch(protocolInfo); len(protoMatch) > 2 {
					currentRoute.Protocol = protoMatch[1]
					currentRoute.Since = protoMatch[2]
				}
				// 检查是否是主路由
				currentRoute.Primary = strings.Contains(protocolInfo, "*")
				// 提取度量值
				if metricMatch := regexp.MustCompile(`\((\d+)\)`).FindStringSubmatch(protocolInfo); len(metricMatch) > 1 {
					currentRoute.Metric = metricMatch[1]
				}
				// 提取 AS 路径
				if asMatch := regexp.MustCompile(`\[(AS[^\]]+)\]`).FindStringSubmatch(protocolInfo); len(asMatch) > 1 {
					currentRoute.ASPath = asMatch[1]
				}
			}
		} else if strings.Contains(line, "via") && currentRoute != nil {
			// 解析下一跳信息
			nextHop := BirdNextHop{}
			parts := strings.Fields(line)
			for i, part := range parts {
				switch part {
				case "via":
					if i+1 < len(parts) {
						nextHop.Via = parts[i+1]
					}
				case "on":
					if i+1 < len(parts) {
						nextHop.Interface = parts[i+1]
					}
				case "from":
					if i+1 < len(parts) {
						nextHop.From = parts[i+1]
					}
				}
			}
			currentRoute.NextHops = append(currentRoute.NextHops, nextHop)
		}
	}

	// 添加最后一个路由
	if currentRoute != nil {
		routes = append(routes, *currentRoute)
	}

	return routes, nil
}

// parseBirdStatus 解析状态信息
func parseBirdStatus(output string) (*BirdStatus, error) {
	lines := strings.Split(output, "\n")
	status := &BirdStatus{}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		switch {
		case strings.HasPrefix(line, "BIRD"):
			status.Version = strings.TrimSpace(strings.TrimPrefix(line, "BIRD"))
		case strings.HasPrefix(line, "Router ID"):
			status.RouterID = strings.TrimSpace(strings.TrimPrefix(line, "Router ID is"))
		case strings.HasPrefix(line, "Current server time"):
			status.ServerTime = strings.TrimSpace(strings.TrimPrefix(line, "Current server time is"))
		case strings.HasPrefix(line, "Last reboot"):
			status.LastReboot = strings.TrimSpace(strings.TrimPrefix(line, "Last reboot on"))
		case strings.HasPrefix(line, "Last reconfiguration"):
			status.LastReconf = strings.TrimSpace(strings.TrimPrefix(line, "Last reconfiguration on"))
		}
	}

	return status, nil
}

// parseBirdMemory 解析内存信息
func parseBirdMemory(output string) (*BirdMemory, error) {
	lines := strings.Split(output, "\n")
	memory := &BirdMemory{
		Categories: make([]BirdMemoryCategory, 0),
	}

	var inTable bool
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "BIRD") || strings.Contains(line, "BIRD memory usage") {
			continue
		}

		if strings.Contains(line, "Effective") {
			inTable = true
			continue
		}

		if !inTable {
			continue
		}

		// 使用正则表达式提取数值和单位
		re := regexp.MustCompile(`^([\w\s]+):\s+(\d+\.?\d*)\s*([kMGT]?B)\s+(\d+\.?\d*)\s*([kMGT]?B)`)
		matches := re.FindStringSubmatch(line)

		if len(matches) == 6 {
			name := strings.TrimSpace(strings.TrimSuffix(matches[1], ":"))
			effective := matches[2] + " " + matches[3]
			overhead := matches[4] + " " + matches[5]

			if strings.HasPrefix(line, "Total") {
				memory.Total = BirdMemoryUsage{
					Effective: effective,
					Overhead:  overhead,
				}
			} else {
				category := BirdMemoryCategory{
					Name: name,
					Usage: BirdMemoryUsage{
						Effective: effective,
						Overhead:  overhead,
					},
				}
				memory.Categories = append(memory.Categories, category)
			}
		}
	}

	return memory, nil
}

// handleBirdCommand 处理 Bird2 命令请求
func (s *HTTPServer) handleBirdCommand(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "只支持 POST 请求", http.StatusMethodNotAllowed)
		return
	}

	var request struct {
		Command string `json:"command"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "无效的请求格式", http.StatusBadRequest)
		return
	}

	// 验证命令
	allowedCommands := map[string]bool{
		"show protocols": true,
		"show route":     true,
		"show status":    true,
		"show memory":    true,
	}

	cmd := strings.TrimSpace(request.Command)
	if !allowedCommands[cmd] {
		http.Error(w, "不支持的命令", http.StatusBadRequest)
		return
	}

	output, err := s.bird.ExecuteCommand(cmd)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 解析输出
	parsedOutput, err := parseBirdOutput(cmd, output)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response := struct {
		Command string      `json:"command"`
		Data    interface{} `json:"data"`
		Raw     string      `json:"raw"`
	}{
		Command: cmd,
		Data:    parsedOutput,
		Raw:     output,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleBird 处理 Bird2 页面请求
func (s *HTTPServer) handleBird(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "bird.html")
}

func main() {
	wg, err := NewWireguardManager()
	if err != nil {
		log.Fatal(err)
	}
	defer wg.Close()

	// 创建 Bird2 管理器
	bird := NewBird2Manager()

	// 创建 HTTP 服务器
	server := NewHTTPServer(wg, bird)

	// 设置路由
	mux := http.NewServeMux()
	mux.HandleFunc("/", server.handleIndex)
	mux.HandleFunc("/status", server.handleStatus)
	mux.HandleFunc("/interfaces", server.handleInterfaces)
	mux.HandleFunc("/bird/command", server.handleBirdCommand)

	// 启动 HTTP 服务器
	log.Println("HTTP 服务器启动在 :8080 端口")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
