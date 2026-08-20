package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type CliConfig struct {
	ServerURL string `json:"server_url"`
	APIKey    string `json:"api_key"`
}

const configFileName = ".ssl-cli.json"

func getConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, configFileName), nil
}

func loadConfig() (*CliConfig, error) {
	path, err := getConfigPath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &CliConfig{}, nil
		}
		return nil, err
	}
	var config CliConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}
	return &config, nil
}

func saveConfig(config *CliConfig) error {
	path, err := getConfigPath()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func main() {
	if len(os.Args) < 2 {
		printGeneralHelp()
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "config":
		handleConfigCommand()
	case "issue":
		handleIssueCommand()
	case "download":
		handleDownloadCommand()
	case "install":
		handleInstallCommand()
	default:
		fmt.Printf("Unknown command: %s\n", command)
		printGeneralHelp()
		os.Exit(1)
	}
}

func printGeneralHelp() {
	fmt.Println("ssl-cli - Command-line interface for SSL Provider")
	fmt.Println("\nUsage:")
	fmt.Println("  ssl-cli <command> [arguments]")
	fmt.Println("\nCommands:")
	fmt.Println("  config      Configure CLI server URL and API credentials")
	fmt.Println("  issue       Issue and sign a new SSL certificate")
	fmt.Println("  download    Retrieve existing certificate files by certificate ID")
	fmt.Println("  install     Install certificate files and run reload command")
	fmt.Println("\nUse 'ssl-cli <command> --help' for command-specific flags.")
}

func handleConfigCommand() {
	configCmd := flag.NewFlagSet("config", flag.ExitOnError)
	action := ""
	if len(os.Args) > 2 {
		action = os.Args[2]
	}

	if action != "set" && action != "show" {
		fmt.Println("Usage: ssl-cli config [set|show] [flags]")
		fmt.Println("\nActions:")
		fmt.Println("  set         Save new configuration values")
		fmt.Println("  show        Display current configuration values")
		return
	}

	cfg, err := loadConfig()
	if err != nil {
		fmt.Printf("Error loading config: %v\n", err)
		os.Exit(1)
	}

	if action == "show" {
		fmt.Printf("Server URL: %s\n", cfg.ServerURL)
		if cfg.APIKey != "" {
			fmt.Println("API Key:    configured (hidden)")
		} else {
			fmt.Println("API Key:    not set")
		}
		return
	}

	// config set flags
	serverURL := configCmd.String("server", "", "SSL Provider server address (e.g. http://localhost:8080)")
	apiKey := configCmd.String("api-key", "", "API key token generated in console")

	// Parse flags omitting first 3 elements (ssl-cli config set)
	configCmd.Parse(os.Args[3:])

	if *serverURL == "" && *apiKey == "" {
		fmt.Println("Please provide --server or --api-key flags to update config.")
		os.Exit(1)
	}

	if *serverURL != "" {
		cfg.ServerURL = strings.TrimSuffix(*serverURL, "/")
	}
	if *apiKey != "" {
		cfg.APIKey = *apiKey
	}

	if err := saveConfig(cfg); err != nil {
		fmt.Printf("Failed to save config: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Configuration updated successfully.")
}

type IssueRequest struct {
	CommonName   string   `json:"common_name"`
	SANs         []string `json:"sans"`
	ValidityDays int      `json:"validity_days"`
	KeyType      string   `json:"key_type"`
	CSR          string   `json:"csr"`
}

type CertificateResponse struct {
	ID           uint      `json:"id"`
	CommonName   string    `json:"common_name"`
	SANs         []string  `json:"sans"`
	CertPEM      string    `json:"cert_pem"`
	KeyPEM       string    `json:"key_pem,omitempty"`
	CaPEM        string    `json:"ca_pem"`
	SerialNumber string    `json:"serial_number"`
}

func handleIssueCommand() {
	issueCmd := flag.NewFlagSet("issue", flag.ExitOnError)
	cn := issueCmd.String("common-name", "", "Certificate Common Name (CN)")
	sansRaw := issueCmd.String("sans", "", "Comma-separated Subject Alternative Names (SANs)")
	days := issueCmd.Int("days", 365, "Validity duration in days")
	keyType := issueCmd.String("key-type", "ecdsa", "Key Spec (ecdsa, rsa2048, rsa4096)")
	csrPath := issueCmd.String("csr", "", "Path to custom Certificate Signing Request file (CSR)")
	outCert := issueCmd.String("out-cert", "", "Output path for the signed certificate (default <cn>.crt)")
	outKey := issueCmd.String("out-key", "", "Output path for the private key (default <cn>.key, server-generation only)")
	outCa := issueCmd.String("out-ca", "", "Output path for the CA certificate (default ca.crt)")
	outNginx := issueCmd.String("out-nginx", "", "Output path for the Nginx combined certificate chain (default <cn>_nginx.crt)")

	issueCmd.Parse(os.Args[2:])

	cfg, err := loadConfig()
	if err != nil || cfg.ServerURL == "" || cfg.APIKey == "" {
		fmt.Println("CLI is not configured. Run 'ssl-cli config set --server <url> --api-key <key>' first.")
		os.Exit(1)
	}

	var request IssueRequest
	request.ValidityDays = *days
	request.KeyType = *keyType

	if *csrPath != "" {
		csrBytes, err := os.ReadFile(*csrPath)
		if err != nil {
			fmt.Printf("Failed to read CSR file: %v\n", err)
			os.Exit(1)
		}
		request.CSR = string(csrBytes)
	} else {
		if *cn == "" {
			fmt.Println("--common-name is required unless --csr is provided")
			os.Exit(1)
		}
		request.CommonName = *cn
		if *sansRaw != "" {
			parts := strings.Split(*sansRaw, ",")
			for _, p := range parts {
				trimmed := strings.TrimSpace(p)
				if trimmed != "" {
					request.SANs = append(request.SANs, trimmed)
				}
			}
		}
	}

	payload, err := json.Marshal(request)
	if err != nil {
		fmt.Printf("JSON marshalling error: %v\n", err)
		os.Exit(1)
	}

	reqURL := fmt.Sprintf("%s/api/v1/certificates", cfg.ServerURL)
	req, err := http.NewRequest("POST", reqURL, bytes.NewBuffer(payload))
	if err != nil {
		fmt.Printf("HTTP request build failed: %v\n", err)
		os.Exit(1)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", cfg.APIKey)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("API request execution failed: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		fmt.Printf("Server returned error (HTTP %d): %s\n", resp.StatusCode, string(bodyBytes))
		os.Exit(1)
	}

	var result CertificateResponse
	if err := json.Unmarshal(bodyBytes, &result); err != nil {
		fmt.Printf("Failed to parse response JSON: %v\n", err)
		os.Exit(1)
	}

	// File naming resolution
	certName := *outCert
	if certName == "" {
		certName = strings.ReplaceAll(strings.ToLower(result.CommonName), " ", "_") + ".crt"
	}
	caName := *outCa
	if caName == "" {
		caName = "ca.crt"
	}

	if err := os.WriteFile(certName, []byte(result.CertPEM), 0644); err != nil {
		fmt.Printf("Failed to save certificate file: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Saved certificate to: %s\n", certName)

	if err := os.WriteFile(caName, []byte(result.CaPEM), 0644); err != nil {
		fmt.Printf("Failed to save CA certificate file: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Saved CA certificate to: %s\n", caName)

	// Save Nginx combined certificate chain
	nginxName := *outNginx
	if nginxName == "" {
		nginxName = strings.ReplaceAll(strings.ToLower(result.CommonName), " ", "_") + "_nginx.crt"
	}
	nginxPEM := result.CertPEM + "\n" + result.CaPEM
	if err := os.WriteFile(nginxName, []byte(nginxPEM), 0644); err != nil {
		fmt.Printf("Failed to save Nginx bundle certificate file: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Saved Nginx bundle (full chain) certificate to: %s\n", nginxName)

	// Save key if returned (server keygen mode)
	if result.KeyPEM != "" {
		keyName := *outKey
		if keyName == "" {
			keyName = strings.ReplaceAll(strings.ToLower(result.CommonName), " ", "_") + ".key"
		}
		if err := os.WriteFile(keyName, []byte(result.KeyPEM), 0600); err != nil {
			fmt.Printf("Failed to save private key file: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Saved private key to: %s\n", keyName)
	}

	fmt.Println("Certificate signed successfully!")
}

func handleDownloadCommand() {
	downCmd := flag.NewFlagSet("download", flag.ExitOnError)
	certID := downCmd.Int("cert-id", 0, "ID of the certificate to download")
	outCert := downCmd.String("out-cert", "", "Output path for the certificate")
	outKey := downCmd.String("out-key", "", "Output path for the private key (if stored)")
	outCa := downCmd.String("out-ca", "", "Output path for the CA certificate")
	outNginx := downCmd.String("out-nginx", "", "Output path for the Nginx combined certificate chain")

	downCmd.Parse(os.Args[2:])

	if *certID == 0 {
		fmt.Println("--cert-id is required")
		os.Exit(1)
	}

	cfg, err := loadConfig()
	if err != nil || cfg.ServerURL == "" || cfg.APIKey == "" {
		fmt.Println("CLI is not configured. Run 'ssl-cli config set --server <url> --api-key <key>' first.")
		os.Exit(1)
	}

	reqURL := fmt.Sprintf("%s/api/v1/certificates/%d/download", cfg.ServerURL, *certID)
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		fmt.Printf("HTTP request setup failed: %v\n", err)
		os.Exit(1)
	}
	req.Header.Set("X-API-Key", cfg.APIKey)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("API request execution failed: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		fmt.Printf("Server returned error (HTTP %d): %s\n", resp.StatusCode, string(bodyBytes))
		os.Exit(1)
	}

	var result CertificateResponse
	if err := json.Unmarshal(bodyBytes, &result); err != nil {
		fmt.Printf("Failed to parse response JSON: %v\n", err)
		os.Exit(1)
	}

	// File writing
	cName := *outCert
	if cName == "" {
		cName = strings.ReplaceAll(strings.ToLower(result.CommonName), " ", "_") + ".crt"
	}
	if err := os.WriteFile(cName, []byte(result.CertPEM), 0644); err != nil {
		fmt.Printf("Failed to write certificate file: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Downloaded certificate to: %s\n", cName)

	caName := *outCa
	if caName == "" {
		caName = "ca.crt"
	}
	if err := os.WriteFile(caName, []byte(result.CaPEM), 0644); err != nil {
		fmt.Printf("Failed to write CA certificate file: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Downloaded CA certificate to: %s\n", caName)

	// Save Nginx combined certificate chain
	nginxName := *outNginx
	if nginxName == "" {
		nginxName = strings.ReplaceAll(strings.ToLower(result.CommonName), " ", "_") + "_nginx.crt"
	}
	nginxPEM := result.CertPEM + "\n" + result.CaPEM
	if err := os.WriteFile(nginxName, []byte(nginxPEM), 0644); err != nil {
		fmt.Printf("Failed to write Nginx bundle certificate file: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Downloaded Nginx bundle (full chain) certificate to: %s\n", nginxName)

	if result.KeyPEM != "" {
		kName := *outKey
		if kName == "" {
			kName = strings.ReplaceAll(strings.ToLower(result.CommonName), " ", "_") + ".key"
		}
		if err := os.WriteFile(kName, []byte(result.KeyPEM), 0600); err != nil {
			fmt.Printf("Failed to write private key file: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Downloaded private key to: %s\n", kName)
	}

	fmt.Println("Download finished.")
}

func handleInstallCommand() {
	instCmd := flag.NewFlagSet("install", flag.ExitOnError)
	cert := instCmd.String("cert", "", "Source path of the signed certificate file (.crt)")
	key := instCmd.String("key", "", "Source path of the private key file (.key)")
	destCert := instCmd.String("dest-cert", "", "Destination path to copy certificate file to")
	destKey := instCmd.String("dest-key", "", "Destination path to copy private key file to")
	reloadCmd := instCmd.String("reload-cmd", "", "Optional custom command to execute (e.g. 'systemctl reload nginx')")

	instCmd.Parse(os.Args[2:])

	if *cert == "" || *destCert == "" {
		fmt.Println("--cert and --dest-cert are required parameters")
		os.Exit(1)
	}

	// Copy Certificate
	if err := copyFile(*cert, *destCert); err != nil {
		fmt.Printf("Failed to copy certificate to destination: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Successfully installed certificate to: %s\n", *destCert)

	// Copy Key (if specified)
	if *key != "" && *destKey != "" {
		if err := copyFile(*key, *destKey); err != nil {
			fmt.Printf("Failed to copy key to destination: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Successfully installed private key to: %s\n", *destKey)
	}

	// Reload command
	if *reloadCmd != "" {
		fmt.Printf("Executing custom reload command: %s\n", *reloadCmd)
		cmd := exec.Command("sh", "-c", *reloadCmd)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Printf("Custom command returned error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Custom reload command executed successfully.")
	}

	fmt.Println("Installation sequence completed.")
}

func copyFile(src, dest string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}

	// Create directory hierarchy if not existing
	destDir := filepath.Dir(dest)
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return err
	}

	// Ensure destination file is written with strict user-read permissions
	return os.WriteFile(dest, data, 0600)
}
