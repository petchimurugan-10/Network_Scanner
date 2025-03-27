#ifndef EOS_FINGERPRINT_HPP
#define EOS_FINGERPRINT_HPP

#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <functional>

struct ScanResult {
    bool packet_received;
    bool rst_received;
    bool syn_ack_received;
    bool ack_received;
    int response_time_ms;
    int ttl;
    int window_size;
    std::vector<uint8_t> tcp_options;
    uint16_t mss_value;
    uint8_t window_scale;
    bool sack_permitted;
    uint8_t options_length;
    std::string timestamp;
};

struct OSSignature {
    std::string name;
    std::string version;
    bool fin_rst;
    bool null_rst;
    bool xmas_rst;
    bool ack_rst;
    bool syn_urg_rst;
    int typical_ttl;
    std::vector<int> common_ttls;
    int window_size;
    std::vector<int> window_sizes;
    bool uses_window_scaling;
    bool uses_sack;
    int typical_mss;
    std::vector<int> mss_values;
    uint8_t typical_option_layout;
    bool timestamp_supported;
    int confidence_weight;
    std::string description;
};

class EnhancedOSFingerprintScanner {
public:
    // Constructors and destructor
    EnhancedOSFingerprintScanner(const std::string& target, int timeout_ms = 2000);
    ~EnhancedOSFingerprintScanner();

    // Core functionality
    void performFingerprinting(int port, bool verbose);
    void analyzeResults(const std::vector<ScanResult>& results, bool verbose);
    void matchOSSignature(int ttl, int window_size, int mss, bool fin_rst, bool null_rst, 
                          bool xmas_rst, bool ack_rst, bool window_scaling, bool sack_support, 
                          bool timestamp_support, uint8_t option_layout, bool verbose);
    ScanResult sendTcpProbe(const std::string& target_ip, uint16_t port, bool fin, bool syn, 
                            bool rst, bool psh, bool ack, bool urg, bool ece, bool cwr, 
                            int probe_type, int timeout_ms);

    // Port scanning
    void scanPorts(const std::vector<int>& ports, bool verbose);
    bool quickScan(int port);
    std::vector<int> getOpenPorts() const;

    // Network scanning
    static std::vector<std::pair<std::string, std::pair<std::string, double>>> 
        scanNetwork(const std::string& network_cidr, const std::vector<int>& ports, bool verbose);
    static void asyncScanNetwork(const std::string& network_cidr, const std::vector<int>& ports,
                                 std::function<void(const std::string&, const std::pair<std::string, double>&)> callback,
                                 bool verbose);

    // Utility functions
    int createRawSocket();
    std::vector<uint8_t> craftTcpPacket(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, 
                                        uint16_t dst_port, uint32_t seq_num, uint32_t ack_num, 
                                        bool fin, bool syn, bool rst, bool psh, bool ack, bool urg, 
                                        bool ece, bool cwr, uint16_t window, const std::vector<uint8_t>& options);
    std::vector<uint8_t> prepareTcpOptions(int probe_type);
    void parseTcpOptions(const std::vector<uint8_t>& options, std::map<int, std::vector<uint8_t>>& parsed_options);
    std::string ipToString(uint32_t ip);

    // Results and reporting
    std::pair<std::string, double> getBestOSMatch() const;
    std::vector<std::pair<std::string, double>> getAllOSMatches() const;
    std::string generateReport(bool include_detailed_matches) const;
    void exportToCSV(const std::string& filename);
    bool isScanComplete() const;

    // Detection features
    bool isFirewalled() const;
    bool isLikelyHoneypot() const;

    // Configuration
    void setTimeout(int timeout_ms);
    void setTargetIP(const std::string& ip);

private:
    std::string target_ip;
    int timeout;
    uint16_t source_port;
    bool m_scan_complete;
    std::vector<std::pair<std::string, double>> os_matches;
    std::vector<int> open_ports;
    static std::mutex csvMutex;
};

#endif // EOS_FINGERPRINT_HPP#ifndef OS_FINGERPRINT_HPP
#define OS_FINGERPRINT_HPP

#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <functional>

struct ScanResult {
    bool packet_received;
    bool rst_received;
    bool syn_ack_received;
    bool ack_received;
    int response_time_ms;
    int ttl;
    int window_size;
    std::vector<uint8_t> tcp_options;
    uint16_t mss_value;
    uint8_t window_scale;
    bool sack_permitted;
    uint8_t options_length;
    std::string timestamp;
};

struct OSSignature {
    std::string name;
    std::string version;
    bool fin_rst;
    bool null_rst;
    bool xmas_rst;
    bool ack_rst;
    bool syn_urg_rst;
    int typical_ttl;
    std::vector<int> common_ttls;
    int window_size;
    std::vector<int> window_sizes;
    bool uses_window_scaling;
    bool uses_sack;
    int typical_mss;
    std::vector<int> mss_values;
    uint8_t typical_option_layout;
    bool timestamp_supported;
    int confidence_weight;
    std::string description;
};

// Struct to match the main program's expectation
struct OSFingerprint {
    std::string os_name;
    double confidence;
};

class EnhancedOSFingerprintScanner {
public:
    // Constructors and destructor
    EnhancedOSFingerprintScanner(const std::string& target, int timeout_ms = 2000);
    ~EnhancedOSFingerprintScanner();

    // Core functionality
    void performFingerprinting(int port, bool verbose);
    void analyzeResults(const std::vector<ScanResult>& results, bool verbose);
    void matchOSSignature(int ttl, int window_size, int mss, bool fin_rst, bool null_rst, 
                          bool xmas_rst, bool ack_rst, bool window_scaling, bool sack_support, 
                          bool timestamp_support, uint8_t option_layout, bool verbose);
    ScanResult sendTcpProbe(const std::string& target_ip, uint16_t port, bool fin, bool syn, 
                            bool rst, bool psh, bool ack, bool urg, bool ece, bool cwr, 
                            int probe_type, int timeout_ms);

    // Port scanning
    void scanPorts(const std::vector<int>& ports, bool verbose);
    bool quickScan(int port);
    std::vector<int> getOpenPorts() const;

    // Network scanning
    static std::vector<std::pair<std::string, std::pair<std::string, double>>> 
        scanNetwork(const std::string& network_cidr, const std::vector<int>& ports, bool verbose);
    static void asyncScanNetwork(const std::string& network_cidr, const std::vector<int>& ports,
                                 std::function<void(const std::string&, const std::pair<std::string, double>&)> callback,
                                 bool verbose);

    // Utility functions
    int createRawSocket();
    std::vector<uint8_t> craftTcpPacket(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, 
                                        uint16_t dst_port, uint32_t seq_num, uint32_t ack_num, 
                                        bool fin, bool syn, bool rst, bool psh, bool ack, bool urg, 
                                        bool ece, bool cwr, uint16_t window, const std::vector<uint8_t>& options);
    std::vector<uint8_t> prepareTcpOptions(int probe_type);
    void parseTcpOptions(const std::vector<uint8_t>& options, std::map<int, std::vector<uint8_t>>& parsed_options);
    std::string ipToString(uint32_t ip);

    // Results and reporting
    std::pair<std::string, double> getBestOSMatch() const;
    std::vector<std::pair<std::string, double>> getAllOSMatches() const;
    std::string generateReport(bool include_detailed_matches) const;
    void exportToCSV(const std::string& filename);
    bool isScanComplete() const;

    // Detection features
    bool isFirewalled() const;
    bool isLikelyHoneypot() const;

    // Configuration
    void setTimeout(int timeout_ms);
    void setTargetIP(const std::string& ip);

    // Function to return OSFingerprint struct for main program compatibility
    OSFingerprint detectOS(const std::string& ip, const std::vector<int>& ports);

private:
    std::string target_ip;
    int timeout;
    uint16_t source_port;
    bool m_scan_complete;
    std::vector<std::pair<std::string, double>> os_matches;
    std::vector<int> open_ports;
    static std::mutex csvMutex;
};

#endif // OS_FINGERPRINT_HPP