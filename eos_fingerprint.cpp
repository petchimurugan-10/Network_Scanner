#include "eos_fingerprint.hpp"
#include <iostream>
#include <fstream>
#include <chrono>
#include <cstring>
#include <map>
#include <set>
#include <vector>
#include <algorithm>
#include <random>
#include <mutex>
#include <future>
#include <memory>
#include <thread>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <errno.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>

// Constants for timeouts and retries
constexpr int DEFAULT_TIMEOUT_MS = 2000;
constexpr int MAX_RETRIES = 3;
constexpr int MIN_PORT = 1;
constexpr int MAX_PORT = 65535;
constexpr int DEFAULT_PORT = 80;

std::mutex EnhancedOSFingerprintScanner::csvMutex;

// Custom TCP header structure to handle options
struct tcp_header {
    uint16_t source;
    uint16_t dest;
    uint32_t seq;
    uint32_t ack_seq;
    uint16_t res1:4, doff:4, fin:1, syn:1, rst:1, psh:1, ack:1, urg:1, ece:1, cwr:1;
    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr;
    // Options can follow
};

// Comprehensive OS signature database with detailed fingerprints
std::vector<OSSignature> enhanced_signatures = {
    // Windows Systems
    {"Windows", "11", true, true, true, false, true, 128, {128, 64}, 64240, {64240, 65535, 8192}, true, true, 1460, {1460, 1440}, 1, true, 10, "Modern Windows with default network settings"},
    {"Windows", "10", true, true, true, false, true, 128, {128, 64}, 65535, {64240, 65535, 8192}, true, true, 1460, {1460, 1440}, 1, true, 10, "Windows 10 with various patch levels"},
    {"Windows", "Server 2022", true, true, true, false, true, 128, {128, 64}, 64240, {64240, 8192, 16384}, true, true, 1460, {1460, 1440}, 1, true, 10, "Windows Server 2022 with default network settings"},
    {"Windows", "Server 2019", true, true, true, false, true, 128, {128, 64}, 64240, {64240, 8192, 16384}, true, true, 1460, {1460, 1440}, 1, true, 10, "Windows Server 2019 with default network settings"},
    {"Windows", "Server 2016", true, true, true, false, true, 128, {128, 64}, 8192, {8192, 16384, 64240}, true, true, 1460, {1460, 1440}, 1, true, 10, "Windows Server 2016 with default network settings"},
    {"Windows", "7/8/8.1", true, true, true, false, true, 128, {128, 64}, 8192, {8192, 64240, 65535}, true, true, 1460, {1460, 1440}, 1, true, 8, "Older Windows desktop systems"},
    {"Windows", "XP/2003", true, true, true, false, true, 128, {128, 32}, 65535, {65535, 16384, 8192}, false, false, 1460, {1460, 1440}, 0, false, 6, "Legacy Windows systems"},
    
    // Linux Systems
    {"Linux", "Kernel 5.x-6.x", false, false, false, false, false, 64, {64, 128}, 65535, {65535, 29200, 14600}, true, true, 1460, {1460, 1440, 1400}, 2, true, 10, "Modern Linux kernel with default settings"},
    {"Linux", "Kernel 4.x", false, false, false, false, false, 64, {64, 128}, 29200, {29200, 14600, 5840}, true, true, 1460, {1460, 1440, 1400}, 2, true, 10, "Linux kernel 4.x series"},
    {"Ubuntu", "22.04/23.10/24.04", false, false, false, false, false, 64, {64}, 64240, {64240, 29200, 5840}, true, true, 1460, {1460, 1440}, 2, true, 10, "Ubuntu Linux with default network settings"},
    {"Ubuntu", "18.04/20.04", false, false, false, false, false, 64, {64}, 29200, {29200, 5840}, true, true, 1460, {1460, 1440}, 2, true, 9, "Ubuntu Linux LTS releases"},
    {"Debian", "11/12", false, false, false, false, false, 64, {64}, 29200, {29200, 5840}, true, true, 1460, {1460, 1440}, 2, true, 9, "Debian stable releases"},
    {"CentOS/RHEL", "7/8/9", false, false, false, false, false, 64, {64}, 14600, {14600, 29200, 5840}, true, true, 1460, {1460, 1440}, 2, true, 9, "RedHat-based distributions"},
    {"Fedora", "37-40", false, false, false, false, false, 64, {64}, 14600, {14600, 29200}, true, true, 1460, {1460}, 2, true, 9, "Fedora Linux"},
    {"Alpine", "3.x", false, false, false, false, false, 64, {64}, 5840, {5840, 29200}, true, true, 1460, {1460, 1440}, 2, true, 8, "Alpine Linux minimal distribution"},
    
    // macOS Systems
    {"macOS", "14 Sequoia", false, false, false, false, false, 64, {64}, 65535, {65535, 8192}, true, true, 1460, {1460, 1440}, 3, true, 10, "macOS latest version"},
    {"macOS", "13 Ventura", false, false, false, false, false, 64, {64}, 65535, {65535, 8192}, true, true, 1460, {1460, 1440}, 3, true, 10, "macOS Ventura"},
    {"macOS", "12 Monterey", false, false, false, false, false, 64, {64}, 65535, {65535, 8192}, true, true, 1460, {1460, 1440}, 3, true, 9, "macOS Monterey"},
    {"macOS", "11 Big Sur", false, false, false, false, false, 64, {64}, 65535, {65535, 8192}, true, true, 1460, {1460, 1440}, 3, true, 9, "macOS Big Sur"},
    {"macOS", "10.15 Catalina", false, false, false, false, false, 64, {64}, 65535, {65535, 8192}, true, true, 1460, {1460, 1440}, 3, true, 8, "macOS Catalina"},
    {"macOS", "10.14 and earlier", false, false, false, false, false, 64, {64}, 65535, {65535, 8192}, true, true, 1460, {1460, 1440}, 3, true, 7, "Older macOS versions"},
    
    // Network Devices
    {"Cisco", "IOS XE", true, true, true, true, true, 255, {255, 64}, 4128, {4128, 8192}, false, false, 1460, {1460, 536}, 0, false, 10, "Cisco IOS XE devices"},
    {"Cisco", "IOS", true, true, true, true, true, 255, {255, 64}, 4128, {4128, 8192}, false, false, 1460, {1460, 536}, 0, false, 9, "Cisco IOS classic devices"},
    {"Juniper", "Junos", false, false, false, false, false, 255, {255, 64}, 16384, {16384, 8192}, true, true, 1460, {1460, 1440}, 2, true, 10, "Juniper devices with Junos OS"},
    {"Fortigate", "FortiOS", true, true, true, false, true, 64, {64, 255}, 8192, {8192, 16384}, true, false, 1460, {1460, 1440}, 1, false, 10, "Fortinet Fortigate firewalls"},
    {"Palo Alto", "PAN-OS", false, false, false, false, false, 64, {64, 255}, 16384, {16384, 32768}, true, true, 1460, {1460, 1440}, 2, true, 10, "Palo Alto Networks devices"},
    {"F5", "BIG-IP", false, false, false, false, false, 64, {64, 255}, 8192, {8192, 16384}, true, true, 1460, {1460}, 2, true, 10, "F5 BIG-IP load balancers"},
    
    // IoT and Embedded
    {"Android", "Various", false, false, false, false, false, 64, {64}, 14600, {14600, 5840}, true, true, 1460, {1460, 1400}, 2, true, 8, "Android-based devices"},
    {"IoT", "Generic Linux", false, false, false, false, false, 64, {64}, 5840, {5840, 14600}, false, false, 1460, {1460, 1400, 536}, 0, false, 7, "Generic IoT devices using embedded Linux"},
    {"Embedded", "VxWorks", true, false, true, false, false, 255, {255, 64}, 8192, {8192, 4096}, false, false, 1460, {1460, 536}, 0, false, 8, "VxWorks-based embedded devices"},
    {"Embedded", "RTOS", true, true, true, false, false, 64, {64, 255}, 4096, {4096, 2048}, false, false, 536, {536, 1460}, 0, false, 7, "Generic RTOS-based embedded systems"},
    
    // Other Systems
    {"BSD", "FreeBSD 13/14", false, false, false, false, false, 64, {64}, 65535, {65535, 16384}, true, true, 1460, {1460, 1440}, 2, true, 10, "FreeBSD modern versions"},
    {"BSD", "OpenBSD 7.x", false, false, false, false, false, 64, {64}, 16384, {16384, 65535}, true, true, 1460, {1460, 1440}, 2, true, 10, "OpenBSD modern versions"},
    {"BSD", "NetBSD", false, false, false, false, false, 64, {64}, 32768, {32768, 16384}, true, true, 1460, {1460, 1440}, 2, true, 9, "NetBSD systems"},
    {"IBM", "AIX", false, false, false, false, false, 255, {255}, 16384, {16384, 32768}, true, true, 1460, {1460, 1440}, 1, true, 9, "IBM AIX systems"},
    {"Oracle", "Solaris", false, false, false, false, false, 255, {255, 64}, 8192, {8192, 32768}, true, true, 1460, {1460, 1440}, 2, true, 9, "Oracle Solaris systems"}
};

// Enhanced checksum calculation with handling for odd-length data
uint16_t compute_tcp_checksum(uint32_t src_addr, uint32_t dst_addr, uint8_t* tcp_segment, size_t length) {
    struct pseudo_header {
        uint32_t source_address;
        uint32_t dest_address;
        uint8_t placeholder;
        uint8_t protocol;
        uint16_t tcp_length;
    } psh;
    
    psh.source_address = src_addr;
    psh.dest_address = dst_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(length);

    size_t total_len = sizeof(pseudo_header) + length;
    bool odd_length = (total_len % 2 != 0);
    size_t padded_len = total_len + (odd_length ? 1 : 0);
    
    std::unique_ptr<uint8_t[]> extended_header(new uint8_t[padded_len]());
    memcpy(extended_header.get(), &psh, sizeof(pseudo_header));
    memcpy(extended_header.get() + sizeof(pseudo_header), tcp_segment, length);
    
    uint32_t sum = 0;
    uint16_t* ptr = reinterpret_cast<uint16_t*>(extended_header.get());
    for (size_t i = 0; i < padded_len / 2; i++) {
        sum += ntohs(ptr[i]);
    }
    
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return (uint16_t)(~sum);
}

// Create a raw socket and set it up
int EnhancedOSFingerprintScanner::createRawSocket() {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock == -1) {
        std::cerr << "Error creating raw socket: " << strerror(errno) << std::endl;
        return -1;
    }

    int on = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
        std::cerr << "Error setting IP_HDRINCL: " << strerror(errno) << std::endl;
        close(sock);
        return -1;
    }

    int flags = fcntl(sock, F_GETFL, 0);
    if (flags == -1) {
        std::cerr << "Error getting socket flags: " << strerror(errno) << std::endl;
        close(sock);
        return -1;
    }

    if (fcntl(sock, F_SETFL, flags | O_NONBLOCK) == -1) {
        std::cerr << "Error setting non-blocking mode: " << strerror(errno) << std::endl;
        close(sock);
        return -1;
    }

    return sock;
}

// Craft a TCP packet with custom flags and options
std::vector<uint8_t> EnhancedOSFingerprintScanner::craftTcpPacket(
    uint32_t src_ip, uint32_t dst_ip, 
    uint16_t src_port, uint16_t dst_port,
    uint32_t seq_num, uint32_t ack_num,
    bool fin, bool syn, bool rst, bool psh, bool ack, bool urg, bool ece, bool cwr,
    uint16_t window, const std::vector<uint8_t>& options) {
    
    size_t ip_header_len = sizeof(struct iphdr);
    size_t tcp_header_len = sizeof(struct tcp_header);
    size_t options_len = options.size();
    size_t total_len = ip_header_len + tcp_header_len + options_len;
    
    std::vector<uint8_t> packet(total_len, 0);
    
    struct iphdr* ip_header = reinterpret_cast<struct iphdr*>(packet.data());
    ip_header->version = 4;
    ip_header->ihl = 5;
    ip_header->tos = 0;
    ip_header->tot_len = htons(total_len);
    ip_header->id = htons(rand() % 65535);
    ip_header->frag_off = 0;
    ip_header->ttl = 64;
    ip_header->protocol = IPPROTO_TCP;
    ip_header->check = 0;
    ip_header->saddr = src_ip;
    ip_header->daddr = dst_ip;
    
    ip_header->check = 0;
    uint16_t* ptr = reinterpret_cast<uint16_t*>(ip_header);
    uint32_t sum = 0;
    for (int i = 0; i < ip_header->ihl * 2; i++) {
        sum += ntohs(ptr[i]);
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    ip_header->check = htons(~sum & 0xFFFF);
    
    struct tcp_header* tcp = reinterpret_cast<struct tcp_header*>(packet.data() + ip_header_len);
    tcp->source = htons(src_port);
    tcp->dest = htons(dst_port);
    tcp->seq = htonl(seq_num);
    tcp->ack_seq = htonl(ack_num);
    tcp->doff = (tcp_header_len + options_len) / 4;
    tcp->res1 = 0;
    tcp->fin = fin ? 1 : 0;
    tcp->syn = syn ? 1 : 0;
    tcp->rst = rst ? 1 : 0;
    tcp->psh = psh ? 1 : 0;
    tcp->ack = ack ? 1 : 0;
    tcp->urg = urg ? 1 : 0;
    tcp->ece = ece ? 1 : 0;
    tcp->cwr = cwr ? 1 : 0;
    tcp->window = htons(window);
    tcp->check = 0;
    tcp->urg_ptr = 0;
    
    if (options_len > 0) {
        memcpy(packet.data() + ip_header_len + tcp_header_len, options.data(), options_len);
    }
    
    tcp->check = 0;
    tcp->check = htons(compute_tcp_checksum(
        ip_header->saddr, ip_header->daddr,
        packet.data() + ip_header_len,
        tcp_header_len + options_len));
    
    return packet;
}

// Prepare TCP options based on probe type
std::vector<uint8_t> EnhancedOSFingerprintScanner::prepareTcpOptions(int probe_type) {
    std::vector<uint8_t> options;
    
    switch (probe_type) {
        case 1: { // Windows-style options
            options.push_back(2);  options.push_back(4);  options.push_back(5);  options.push_back(180);
            options.push_back(1);
            options.push_back(3);  options.push_back(3);  options.push_back(8);
            options.push_back(1);  options.push_back(1);
            options.push_back(4);  options.push_back(2);
            break;
        }
        case 2: { // Linux-style options
            options.push_back(2);  options.push_back(4);  options.push_back(5);  options.push_back(180);
            options.push_back(4);  options.push_back(2);
            options.push_back(8);  options.push_back(10);
            uint32_t ts = static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());
            options.push_back((ts >> 24) & 0xFF); options.push_back((ts >> 16) & 0xFF);
            options.push_back((ts >> 8) & 0xFF);  options.push_back(ts & 0xFF);
            options.push_back(0); options.push_back(0); options.push_back(0); options.push_back(0);
            options.push_back(3); options.push_back(3); options.push_back(7);
            break;
        }
        case 3: { // macOS-style options
            options.push_back(2);  options.push_back(4);  options.push_back(5);  options.push_back(180);
            options.push_back(1);
            options.push_back(3);  options.push_back(3);  options.push_back(6);
            options.push_back(1);  options.push_back(1);
            options.push_back(8);  options.push_back(10);
            uint32_t ts = static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());
            options.push_back((ts >> 24) & 0xFF); options.push_back((ts >> 16) & 0xFF);
            options.push_back((ts >> 8) & 0xFF);  options.push_back(ts & 0xFF);
            options.push_back(0); options.push_back(0); options.push_back(0); options.push_back(0);
            options.push_back(4);  options.push_back(2);
            break;
        }
        case 0: // No options (basic TCP)
        default: {
            break;
        }
    }
    
    while (options.size() % 4 != 0) {
        options.push_back(0);
    }
    
    return options;
}

// Send a TCP probe and analyze the response
ScanResult EnhancedOSFingerprintScanner::sendTcpProbe(
    const std::string& target_ip, uint16_t port, 
    bool fin, bool syn, bool rst, bool psh, bool ack, bool urg, bool ece, bool cwr,
    int probe_type, int timeout_ms) {
    
    ScanResult result = {};
    result.packet_received = false;
    result.rst_received = false;
    result.syn_ack_received = false;
    result.ack_received = false;
    result.response_time_ms = -1;
    result.ttl = -1;
    result.window_size = -1;
    result.mss_value = 0;
    result.window_scale = 0;
    result.sack_permitted = false;
    result.options_length = 0;
    
    int sock = createRawSocket();
    if (sock < 0) {
        return result;
    }
    
    struct sockaddr_in src_addr, dst_addr;
    memset(&src_addr, 0, sizeof(src_addr));
    memset(&dst_addr, 0, sizeof(dst_addr));
    
    src_addr.sin_family = AF_INET;
    src_addr.sin_port = htons(rand() % 65000 + 1024);
    src_addr.sin_addr.s_addr = inet_addr("192.168.1.1");
    
    dst_addr.sin_family = AF_INET;
    dst_addr.sin_port = htons(port);
    dst_addr.sin_addr.s_addr = inet_addr(target_ip.c_str());
    
    std::vector<uint8_t> options = prepareTcpOptions(probe_type);
    uint32_t seq_num = rand() % 0xFFFFFFFF;
    
    std::vector<uint8_t> packet = craftTcpPacket(
        src_addr.sin_addr.s_addr, dst_addr.sin_addr.s_addr,
        ntohs(src_addr.sin_port), port,
        seq_num, 0,
        fin, syn, rst, psh, ack, urg, ece, cwr,
        65535, options
    );
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    if (sendto(sock, packet.data(), packet.size(), 0, 
               (struct sockaddr*)&dst_addr, sizeof(dst_addr)) < 0) {
        std::cerr << "Failed to send packet: " << strerror(errno) << std::endl;
        close(sock);
        return result;
    }
    
    char buffer[4096];
    struct pollfd fds[1];
    fds[0].fd = sock;
    fds[0].events = POLLIN;
    
    int poll_result = poll(fds, 1, timeout_ms);
    if (poll_result <= 0) {
        close(sock);
        return result;
    }
    
    struct sockaddr_in recv_addr;
    socklen_t recv_addr_len = sizeof(recv_addr);
    
    ssize_t recv_len = recvfrom(sock, buffer, sizeof(buffer), 0, 
                              (struct sockaddr*)&recv_addr, &recv_addr_len);
    
    result.response_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::high_resolution_clock::now() - start_time).count();
    
    if (recv_len > 0) {
        result.packet_received = true;
        
        struct iphdr* ip_header = (struct iphdr*)buffer;
        int ip_header_len = ip_header->ihl * 4;
        result.ttl = ip_header->ttl;
        
        struct tcp_header* tcp = (struct tcp_header*)(buffer + ip_header_len);
        
        result.rst_received = tcp->rst;
        result.syn_ack_received = (tcp->syn && tcp->ack);
        result.ack_received = tcp->ack;
        result.window_size = ntohs(tcp->window);
        
        int tcp_header_len = tcp->doff * 4;
        
        if (tcp_header_len > sizeof(struct tcp_header)) {
            uint8_t* options_start = (uint8_t*)(buffer + ip_header_len + sizeof(struct tcp_header));
            int options_len = tcp_header_len - sizeof(struct tcp_header);
            result.options_length = options_len;
            result.tcp_options.assign(options_start, options_start + options_len);
            
            for (int i = 0; i < options_len; ) {
                uint8_t kind = options_start[i];
                if (kind == 0) break;
                else if (kind == 1) { i++; continue; }
                
                if (i + 1 >= options_len) break;
                uint8_t len = options_start[i + 1];
                if (i + len > options_len || len < 2) break;
                
                switch (kind) {
                    case 2: if (len == 4) result.mss_value = (options_start[i + 2] << 8) | options_start[i + 3]; break;
                    case 3: if (len == 3) result.window_scale = options_start[i + 2]; break;
                    case 4: if (len == 2) result.sack_permitted = true; break;
                }
                i += len;
            }
        }
        
        auto now = std::chrono::system_clock::now();
        auto now_time_t = std::chrono::system_clock::to_time_t(now);
        std::stringstream ss;
        ss << std::put_time(std::localtime(&now_time_t), "%Y-%m-%d %H:%M:%S");
        result.timestamp = ss.str();
    }
    
    close(sock);
    return result;
}

// Constructor
EnhancedOSFingerprintScanner::EnhancedOSFingerprintScanner(const std::string& target, int timeout_ms)
    : target_ip(target), timeout(timeout_ms), m_scan_complete(false) {
    if (timeout <= 0) timeout = DEFAULT_TIMEOUT_MS;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(1024, 65000);
    source_port = dis(gen);
}

// Destructor
EnhancedOSFingerprintScanner::~EnhancedOSFingerprintScanner() {}

// Perform OS fingerprinting
void EnhancedOSFingerprintScanner::performFingerprinting(int port, bool verbose) {
    std::vector<ScanResult> results;
    
    if (port <= 0 || port > MAX_PORT) port = DEFAULT_PORT;
    
    if (verbose) {
        std::cout << "Starting OS fingerprint scan on " << target_ip << ":" << port << std::endl;
    }
    
    results.push_back(sendTcpProbe(target_ip, port, false, true, false, false, false, false, false, false, 1, timeout));
    results.push_back(sendTcpProbe(target_ip, port, false, true, false, false, false, false, false, false, 2, timeout));
    results.push_back(sendTcpProbe(target_ip, port, false, true, false, false, false, false, false, false, 3, timeout));
    results.push_back(sendTcpProbe(target_ip, port, true, false, false, false, false, false, false, false, 0, timeout));
    results.push_back(sendTcpProbe(target_ip, port, true, true, false, false, false, false, false, false, 0, timeout));
    results.push_back(sendTcpProbe(target_ip, port, false, false, false, false, false, false, false, false, 0, timeout));
    results.push_back(sendTcpProbe(target_ip, port, true, false, false, true, false, true, false, false, 0, timeout));
    results.push_back(sendTcpProbe(target_ip, port, false, false, false, false, true, false, false, false, 0, timeout));
    results.push_back(sendTcpProbe(target_ip, port, false, true, false, false, false, true, false, false, 0, timeout));
    results.push_back(sendTcpProbe(target_ip, port, false, true, false, false, false, false, true, true, 0, timeout));
    
    analyzeResults(results, verbose);
    m_scan_complete = true;
}

// Analyze probe results
void EnhancedOSFingerprintScanner::analyzeResults(const std::vector<ScanResult>& results, bool verbose) {
    if (results.empty()) return;

    int syn_responses = 0, fin_responses = 0, null_responses = 0, xmas_responses = 0, ack_responses = 0;
    int typical_ttl = -1, typical_window = -1, typical_mss = -1;
    bool window_scaling = false, sack_support = false, timestamp_support = false;
    uint8_t option_layout = 0;
    
    for (const auto& result : results) {
        if (!result.packet_received) continue;
        
        if (result.syn_ack_received) syn_responses++;
        if (result.rst_received) {
            if (results[3].rst_received) fin_responses++;
            if (results[5].rst_received) null_responses++;
            if (results[6].rst_received) xmas_responses++;
            if (results[7].rst_received) ack_responses++;
        }
        
        if (result.syn_ack_received) {
            typical_ttl = result.ttl;
            typical_window = result.window_size;
            typical_mss = result.mss_value;
        }
        
        if (result.options_length > 0) {
            window_scaling = window_scaling || (result.window_scale > 0);
            sack_support = sack_support || result.sack_permitted;
            for (size_t i = 0; i < result.tcp_options.size(); i++) {
                if (result.tcp_options[i] == 8) {
                    timestamp_support = true;
                    break;
                }
            }
            
            if (result.options_length > 10) {
                if (result.tcp_options[0] == 2 && result.tcp_options[4] == 1) option_layout = 1;
                else if (result.tcp_options[0] == 2 && result.tcp_options[4] == 4) option_layout = 2;
                else if (result.tcp_options.size() >= 12 && result.tcp_options[0] == 2 && 
                         result.tcp_options[4] == 1 && result.tcp_options[6] == 8) option_layout = 3;
            }
        }
    }
    
    matchOSSignature(typical_ttl, typical_window, typical_mss, fin_responses > 0, null_responses > 0,
                     xmas_responses > 0, ack_responses > 0, window_scaling, sack_support,
                     timestamp_support, option_layout, verbose);
}

// Match fingerprint against OS signatures
void EnhancedOSFingerprintScanner::matchOSSignature(
    int ttl, int window_size, int mss,
    bool fin_rst, bool null_rst, bool xmas_rst,
    bool ack_rst, bool window_scaling, bool sack_support,
    bool timestamp_support, uint8_t option_layout,
    bool verbose) {
    
    if (verbose) {
        std::cout << "Fingerprint data: TTL=" << ttl << ", Window=" << window_size << ", MSS=" << mss << std::endl;
    }
    
    std::vector<std::pair<std::string, double>> matches;
    
    for (const auto& sig : enhanced_signatures) {
        double score = 0.0;
        int max_score = sig.confidence_weight * 10;
        
        if (ttl == sig.typical_ttl) score += sig.confidence_weight * 2;
        else for (int sig_ttl : sig.common_ttls) if (ttl == sig_ttl) { score += sig.confidence_weight * 1.5; break; }
        
        if (window_size == sig.window_size) score += sig.confidence_weight * 1.5;
        else for (int sig_window : sig.window_sizes) if (window_size == sig_window) { score += sig.confidence_weight * 1; break; }
        
        if (mss == sig.typical_mss) score += sig.confidence_weight * 1.5;
        else for (int sig_mss : sig.mss_values) if (mss == sig_mss) { score += sig.confidence_weight * 1; break; }
        
        if (fin_rst == sig.fin_rst) score += sig.confidence_weight * 0.5;
        if (null_rst == sig.null_rst) score += sig.confidence_weight * 0.5;
        if (xmas_rst == sig.xmas_rst) score += sig.confidence_weight * 0.5;
        if (ack_rst == sig.ack_rst) score += sig.confidence_weight * 0.5;
        
        if (window_scaling == sig.uses_window_scaling) score += sig.confidence_weight * 0.5;
        if (sack_support == sig.uses_sack) score += sig.confidence_weight * 0.5;
        if (timestamp_support == sig.timestamp_supported) score += sig.confidence_weight * 0.5;
        
        if (option_layout == sig.typical_option_layout) score += sig.confidence_weight * 1.0;
        
        double percentage_match = (score / max_score) * 100.0;
        
        if (percentage_match >= 50.0) {
            matches.push_back(std::make_pair(sig.name + " " + sig.version, percentage_match));
        }
    }
    
    std::sort(matches.begin(), matches.end(), 
              [](const auto& a, const auto& b) { return a.second > b.second; });
    
    os_matches = matches.empty() ? std::vector<std::pair<std::string, double>>{{"Unknown", 0.0}} : matches;
    
    if (verbose && !matches.empty()) {
        std::cout << "Best match: " << os_matches[0].first << " (" << os_matches[0].second << "%)" << std::endl;
    }
}

// Scan ports
void EnhancedOSFingerprintScanner::scanPorts(const std::vector<int>& ports, bool verbose) {
    open_ports.clear();
    
    if (verbose) std::cout << "Scanning " << ports.size() << " ports on " << target_ip << std::endl;
    
    std::vector<std::future<std::pair<int, bool>>> futures;
    
    for (int port : ports) {
        futures.push_back(std::async(std::launch::async, [this, port]() {
            ScanResult result = sendTcpProbe(target_ip, port, false, true, false, false, false, false, false, false, 0, timeout);
            return std::make_pair(port, result.syn_ack_received);
        }));
    }
    
    for (auto& future : futures) {
        auto result = future.get();
        if (result.second) open_ports.push_back(result.first);
    }
}

// Quick scan of a single port
bool EnhancedOSFingerprintScanner::quickScan(int port) {
    if (port <= 0 || port > MAX_PORT) port = DEFAULT_PORT;
    ScanResult result = sendTcpProbe(target_ip, port, false, true, false, false, false, false, false, false, 0, timeout);
    return result.syn_ack_received;
}

// Getters
std::pair<std::string, double> EnhancedOSFingerprintScanner::getBestOSMatch() const {
    return os_matches.empty() ? std::make_pair("Unknown", 0.0) : os_matches[0];
}

std::vector<std::pair<std::string, double>> EnhancedOSFingerprintScanner::getAllOSMatches() const {
    return os_matches;
}

std::vector<int> EnhancedOSFingerprintScanner::getOpenPorts() const {
    return open_ports;
}

std::string EnhancedOSFingerprintScanner::ipToString(uint32_t ip) {
    struct in_addr addr;
    addr.s_addr = ip;
    return std::string(inet_ntoa(addr));
}

bool EnhancedOSFingerprintScanner::isScanComplete() const {
    return m_scan_complete;
}

// Export to CSV
void EnhancedOSFingerprintScanner::exportToCSV(const std::string& filename) {
    std::lock_guard<std::mutex> lock(csvMutex);
    
    bool file_exists = (access(filename.c_str(), F_OK) != -1);
    std::ofstream outfile(file_exists ? filename : filename, file_exists ? std::ios::app : std::ios::out);
    
    if (!file_exists) outfile << "Timestamp,IP,BestOSMatch,Confidence,OpenPorts\n";
    
    auto now = std::chrono::system_clock::now();
    auto now_time_t = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&now_time_t), "%Y-%m-%d %H:%M:%S");
    
    auto best_match = getBestOSMatch();
    std::string ports_str;
    for (size_t i = 0; i < open_ports.size(); ++i) {
        ports_str += std::to_string(open_ports[i]) + (i < open_ports.size() - 1 ? "," : "");
    }
    
    outfile << ss.str() << "," << target_ip << ",\"" << best_match.first << "\"," 
            << best_match.second << ",\"" << ports_str << "\"" << std::endl;
}

// Network scanning
std::vector<std::pair<std::string, std::pair<std::string, double>>> 
EnhancedOSFingerprintScanner::scanNetwork(const std::string& network_cidr, const std::vector<int>& ports, bool verbose) {
    std::vector<std::pair<std::string, std::pair<std::string, double>>> results;
    
    size_t slash_pos = network_cidr.find('/');
    if (slash_pos == std::string::npos) return results;
    
    std::string network = network_cidr.substr(0, slash_pos);
    int prefix_len = std::stoi(network_cidr.substr(slash_pos + 1));
    
    struct in_addr addr;
    inet_pton(AF_INET, network.c_str(), &addr);
    uint32_t network_addr = ntohl(addr.s_addr);
    uint32_t mask = (0xFFFFFFFF << (32 - prefix_len));
    uint32_t start_addr = (network_addr & mask) + 1;
    uint32_t end_addr = (start_addr | ~mask) - 1;
    
    std::vector<std::future<std::pair<std::string, std::pair<std::string, double>>>> futures;
    
    for (uint32_t ip = start_addr; ip <= end_addr; ip++) {
        futures.push_back(std::async(std::launch::async, [ip, ports, verbose]() {
            struct in_addr addr;
            addr.s_addr = htonl(ip);
            std::string ip_str = inet_ntoa(addr);
            
            EnhancedOSFingerprintScanner scanner(ip_str);
            scanner.scanPorts(ports, verbose);
            if (!scanner.getOpenPorts().empty()) {
                scanner.performFingerprinting(scanner.getOpenPorts()[0], verbose);
                return std::make_pair(ip_str, scanner.getBestOSMatch());
            }
            return std::make_pair(ip_str, std::make_pair("No open ports", 0.0));
        }));
    }
    
    for (auto& future : futures) results.push_back(future.get());
    return results;
}

void EnhancedOSFingerprintScanner::asyncScanNetwork(
    const std::string& network_cidr, const std::vector<int>& ports,
    std::function<void(const std::string&, const std::pair<std::string, double>&)> callback,
    bool verbose) {
    
    size_t slash_pos = network_cidr.find('/');
    if (slash_pos == std::string::npos) return;
    
    std::string network = network_cidr.substr(0, slash_pos);
    int prefix_len = std::stoi(network_cidr.substr(slash_pos + 1));
    
    struct in_addr addr;
    inet_pton(AF_INET, network.c_str(), &addr);
    uint32_t network_addr = ntohl(addr.s_addr);
    uint32_t mask = (0xFFFFFFFF << (32 - prefix_len));
    uint32_t start_addr = (network_addr & mask) + 1;
    uint32_t end_addr = (start_addr | ~mask) - 1;
    
    const int max_concurrent = 50;
    std::vector<std::future<void>> active_futures;
    
    for (uint32_t ip = start_addr; ip <= end_addr; ip++) {
        if (active_futures.size() >= max_concurrent) {
            for (auto it = active_futures.begin(); it != active_futures.end(); ) {
                if (it->wait_for(std::chrono::milliseconds(0)) == std::future_status::ready) {
                    it = active_futures.erase(it);
                } else ++it;
            }
            if (active_futures.size() >= max_concurrent) std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        
        active_futures.push_back(std::async(std::launch::async, [ip, ports, callback, verbose]() {
            struct in_addr addr;
            addr.s_addr = htonl(ip);
            std::string ip_str = inet_ntoa(addr);
            
            EnhancedOSFingerprintScanner scanner(ip_str);
            scanner.scanPorts(ports, verbose);
            if (!scanner.getOpenPorts().empty()) {
                scanner.performFingerprinting(scanner.getOpenPorts()[0], verbose);
                callback(ip_str, scanner.getBestOSMatch());
            } else {
                callback(ip_str, std::make_pair("No open ports", 0.0));
            }
        }));
    }
    
    for (auto& future : active_futures) future.wait();
}

// Parse TCP options
void EnhancedOSFingerprintScanner::parseTcpOptions(const std::vector<uint8_t>& options, 
                                                 std::map<int, std::vector<uint8_t>>& parsed_options) {
    parsed_options.clear();
    
    for (size_t i = 0; i < options.size(); ) {
        uint8_t kind = options[i];
        if (kind == 0) break;
        else if (kind == 1) { i++; continue; }
        
        if (i + 1 >= options.size()) break;
        uint8_t len = options[i + 1];
        if (i + len > options.size() || len < 2) break;
        
        std::vector<uint8_t> option_data(options.begin() + i + 2, options.begin() + i + len);
        parsed_options[kind] = option_data;
        i += len;
    }
}

// Generate report
std::string EnhancedOSFingerprintScanner::generateReport(bool include_detailed_matches) const {
    std::stringstream report;
    report << "OS Fingerprinting Report for " << target_ip << "\n======================================\n\n";
    
    auto now = std::chrono::system_clock::now();
    auto now_time_t = std::chrono::system_clock::to_time_t(now);
    report << "Scan completed: " << std::put_time(std::localtime(&now_time_t), "%Y-%m-%d %H:%M:%S") << "\n\n";
    
    report << "OS Detection Results:\n---------------------\n";
    if (os_matches.empty()) {
        report << "No OS matches found.\n";
    } else {
        report << "Best match: " << os_matches[0].first << " (" << std::fixed << std::setprecision(2) 
               << os_matches[0].second << "% confidence)\n";
        if (include_detailed_matches && os_matches.size() > 1) {
            report << "\nAdditional matches:\n";
            for (size_t i = 1; i < os_matches.size(); i++) {
                report << "  - " << os_matches[i].first << " (" << os_matches[i].second << "%)\n";
            }
        }
    }
    
    report << "\nOpen Ports:\n----------\n";
    if (open_ports.empty()) report << "No open ports detected.\n";
    else for (int port : open_ports) report << "Port " << port << " - open\n";
    
    return report.str();
}

// Configuration
void EnhancedOSFingerprintScanner::setTimeout(int timeout_ms) {
    if (timeout_ms > 0) timeout = timeout_ms;
}

void EnhancedOSFingerprintScanner::setTargetIP(const std::string& ip) {
    target_ip = ip;
    m_scan_complete = false;
    os_matches.clear();
    open_ports.clear();
}

// Detection features
bool EnhancedOSFingerprintScanner::isFirewalled() const {
    bool has_open_ports = !open_ports.empty();
    if (has_open_ports && (os_matches.empty() || os_matches[0].second < 60.0)) return true;
    
    if (has_open_ports && open_ports.size() < 3) {
        std::set<int> common_ports = {80, 443, 22, 21, 23, 25, 53, 110, 143, 3389};
        for (int port : open_ports) if (common_ports.count(port)) return false;
        return true;
    }
    return false;
}

bool EnhancedOSFingerprintScanner::isLikelyHoneypot() const {
    if (os_matches.size() >= 2 && os_matches[0].second > 70.0 && os_matches[1].second > 70.0 && 
        os_matches[0].first != os_matches[1].first) return true;
    return open_ports.size() > 10;
}

// Detect OS method for main program integration
OSFingerprint EnhancedOSFingerprintScanner::detectOS(const std::string& ip, const std::vector<int>& ports) {
    setTargetIP(ip);
    scanPorts(ports, false); // Silent scan
    OSFingerprint result = {"Unknown", 0.0};
    
    if (!open_ports.empty()) {
        performFingerprinting(open_ports[0], false); // Silent fingerprinting
        auto best_match = getBestOSMatch();
        result.os_name = best_match.first;
        result.confidence = best_match.second;
        exportToCSV("os_fingerprints.csv"); // Export to default CSV file
    }
    
    return result;
}