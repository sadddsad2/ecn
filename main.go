// 在 queryHTTPSRecordDoH 函数中修改 HTTP 客户端配置
func queryHTTPSRecordDoH(domain, dohURL string) (string, error) {
	query := buildDNSQuery(domain, typeHTTPS)
	
	// 构建DoH请求
	req, err := http.NewRequest("POST", dohURL, bytes.NewReader(query))
	if err != nil {
		return "", fmt.Errorf("创建DoH请求失败: %w", err)
	}
	
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	
	// 解析URL以获取主机名
	u, err := url.Parse(dohURL)
	if err != nil {
		return "", fmt.Errorf("解析DoH URL失败: %w", err)
	}
	
	// 检查主机名是否为IP地址
	host := u.Hostname()
	isIP := net.ParseIP(host) != nil
	
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	
	// 如果是IP地址，需要特殊处理
	if isIP {
		tlsConfig.InsecureSkipVerify = false
		tlsConfig.VerifyConnection = func(cs tls.ConnectionState) error {
			// 验证证书链
			opts := x509.VerifyOptions{
				DNSName:       "",  // 不验证DNS名称
				Intermediates: x509.NewCertPool(),
			}
			
			for _, cert := range cs.PeerCertificates[1:] {
				opts.Intermediates.AddCert(cert)
			}
			
			// 检查证书的IP SAN是否包含目标IP
			cert := cs.PeerCertificates[0]
			for _, ip := range cert.IPAddresses {
				if ip.String() == host {
					_, err := cert.Verify(opts)
					return err
				}
			}
			
			return fmt.Errorf("证书不包含目标IP: %s", host)
		}
	}
	
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}
	
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("DoH请求失败: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("DoH响应错误: %d", resp.StatusCode)
	}
	
	response, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("读取DoH响应失败: %w", err)
	}
	
	return parseDNSResponse(response)
}
