#include <iostream>
#include <vector>
#include <set>
#include <string>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>
#include <cstring>
#include <errno.h>
#include <thread>
#include <mutex>
#include <stdexcept>
#include <chrono>
#include <poll.h>
#include <fcntl.h>
#include <algorithm>
#include <map>
#include <sstream>
#include <functional>
#include <memory>
#include <fstream>
#include <future>

#include "xbanner_grabber.hpp"
#include "packet_capture.hpp"
#include "os_fingerprint.hpp"

std::mutex mtx;

const std::map<int, std::string> commonPorts = {
    {20, "FTP-data"}, {21, "FTP"}, {22, "SSH"}, {23, "Telnet"},
    {25, "SMTP"}, {53, "DNS"}, {80, "HTTP"}, {110, "POP3"},
    {115, "SFTP"}, {123, "NTP"}, {143, "IMAP"}, {161, "SNMP"},
    {194, "IRC"}, {443, "HTTPS"}, {445, "SMB"}, {465, "SMTPS"},
    {514, "Syslog"}, {587, "SMTP-submission"}, {993, "IMAPS"},
    {995, "POP3S"}, {1080, "SOCKS"}, {1194, "OpenVPN"},
    {1433, "MSSQL"}, {1723, "PPTP"}, {3306, "MySQL"},
    {3389, "RDP"}, {5060, "SIP"}, {5432, "PostgreSQL"},
    {5900, "VNC"}, {8080, "HTTP-Proxy"}
};

struct PortScanResult {
    int port;
    std::string protocol;
    std::string service;
    std::string version;
    std::string banner;
    bool isOpen;
};

ServiceInfo toServiceInfo(const PortScanResult& psr) {
    ServiceInfo si;
    si.port = psr.port;
    si.protocol = psr.protocol;
    si.service = psr.service;
    si.version = psr.version;
    si.banner = psr.banner;
    si.status = psr.isOpen ? "open" : "closed";
    si.certInfo = "";
    return si;
}

struct ScanConfig {
    int timeout_ms = 1000;
    bool use_icmp = true;
    bool use_arp = true;
    bool scan_tcp = true;
    bool scan_udp = true;
    std::vector<int> tcp_ports;
    std::vector<int> udp_ports;
    bool scan_well_known_ports = true;
    bool aggressive_scan = false;
    int connect_timeout_ms = 500;
    bool grab_banners = true;
    int banner_timeout_ms = 2000;
    int maxPortThreads = 20;
    bool capture_packets = true;
    bool detect_os = true;
    std::string os_csv_file = "os_fingerprints.csv";
    std::string output_csv_file = "scan_results.csv";
};

const int ARP_PACKET_SIZE = sizeof(struct ethhdr) + 28;
const int BUFFER_SIZE = 1024;
const int MAX_THREADS_DEFAULT = 4;
const int MAX_PORT_THREADS_DEFAULT = 20;

class Socket {
public:
    explicit Socket(int fd) : fd_(fd) {}
    ~Socket() { if (fd_ >= 0) close(fd_); }
    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;
    int get() const { return fd_; }
private:
    int fd_;
};

unsigned short checksum(void* buffer, int len) {
    unsigned long sum = 0;
    unsigned short* buf = (unsigned short*)buffer;
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    if (len == 1) sum += *(unsigned char*)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

bool ping(int sock, const std::string& ip) {
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    if (inet_pton(AF_INET, ip.c_str(), &dest.sin_addr) <= 0) return false;

    char packet[sizeof(struct icmphdr)];
    struct icmphdr* icmp = (struct icmphdr*)packet;
    memset(packet, 0, sizeof(packet));
    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    icmp->un.echo.id = getpid();
    icmp->un.echo.sequence = 1;
    icmp->checksum = checksum(packet, sizeof(struct icmphdr));

    if (sendto(sock, packet, sizeof(struct icmphdr), 0, (struct sockaddr*)&dest, sizeof(dest)) < 0) {
        return false;
    }

    char buffer[BUFFER_SIZE];
    struct sockaddr_in from;
    socklen_t fromLen = sizeof(from);
    int received = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr*)&from, &fromLen);

    if (received > 0) {
        struct iphdr* ip_hdr = (struct iphdr*)buffer;
        struct icmphdr* reply = (struct icmphdr*)(buffer + (ip_hdr->ihl * 4));
        if (reply->type == ICMP_ECHOREPLY && reply->un.echo.id == icmp->un.echo.id) {
            return true;
        }
    }
    return false;
}

bool arpProbe(int sock, const std::string& ip, int ifindex, unsigned char* src_mac, struct in_addr* src_ip) {
    unsigned char packet[ARP_PACKET_SIZE];
    struct ethhdr* eth = (struct ethhdr*)packet;
    memcpy(eth->h_source, src_mac, 6);
    memset(eth->h_dest, 0xFF, 6);
    eth->h_proto = htons(ETH_P_ARP);

    unsigned char* arp_data = packet + sizeof(struct ethhdr);
    arp_data[0] = 0x00; arp_data[1] = 0x01;
    arp_data[2] = 0x08; arp_data[3] = 0x00;
    arp_data[4] = 6;
    arp_data[5] = 4;
    arp_data[6] = 0x00; arp_data[7] = 0x01;

    memcpy(arp_data + 8, src_mac, 6);
    memcpy(arp_data + 14, &src_ip->s_addr, 4);
    memset(arp_data + 18, 0, 6);
    if (inet_pton(AF_INET, ip.c_str(), arp_data + 24) <= 0) return false;

    struct sockaddr_ll addr;
    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_ifindex = ifindex;
    addr.sll_halen = 6;
    memset(addr.sll_addr, 0xFF, 6);

    if (sendto(sock, packet, ARP_PACKET_SIZE, 0, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        return false;
    }

    unsigned char buffer[BUFFER_SIZE];
    int received = recvfrom(sock, buffer, sizeof(buffer), 0, nullptr, nullptr);

    if (received > 0) {
        unsigned char* reply_arp = buffer + sizeof(struct ethhdr);
        if (reply_arp[6] == 0x00 && reply_arp[7] == 0x02) {
            char reply_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, reply_arp + 14, reply_ip, INET_ADDRSTRLEN);
            if (strcmp(reply_ip, ip.c_str()) == 0) return true;
        }
    }
    return false;
}

class NetworkDiscovery {
public:
    NetworkDiscovery(int numThreads = MAX_THREADS_DEFAULT, ScanConfig config = ScanConfig())
        : numThreads_(std::max(1U, std::thread::hardware_concurrency())), config_(config),
          bannerGrabber(),
          osScanner(config.os_csv_file) {
        if (config_.scan_well_known_ports && config_.tcp_ports.empty()) {
            for (int i = 1; i <= 1024; i++) config_.tcp_ports.push_back(i);
            config_.tcp_ports.push_back(1433);
            config_.tcp_ports.push_back(3306);
            config_.tcp_ports.push_back(3389);
            config_.tcp_ports.push_back(5432);
            config_.tcp_ports.push_back(8080);
            config_.tcp_ports.push_back(8443);
        }

        if (config_.scan_well_known_ports && config_.udp_ports.empty()) {
            config_.udp_ports = {53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 520, 1194, 1900, 5060};
        }

        if (config_.aggressive_scan) {
            config_.tcp_ports.clear();
            config_.udp_ports.clear();
            for (int i = 1; i <= 65535; i++) {
                config_.tcp_ports.push_back(i);
                if (i <= 1024 || (i >= 5000 && i <= 5500)) config_.udp_ports.push_back(i);
            }
        }
    }

    std::set<std::string> scan(const std::string& baseIp, int start, int end, const std::string& interface) {
        if (start > end || start < 0 || end > 255) throw std::invalid_argument("Invalid IP range");

        std::set<std::string> activeHosts;
        std::vector<std::future<std::set<std::string>>> futures;

        int rangeSize = end - start + 1;
        int chunkSize = (rangeSize + numThreads_ - 1) / numThreads_;

        auto startTime = std::chrono::steady_clock::now();

        for (int t = 0; t < numThreads_; ++t) {
            int threadStart = start + (t * chunkSize);
            int threadEnd = std::min(threadStart + chunkSize - 1, end);
            if (threadStart <= threadEnd) {
                futures.push_back(std::async(std::launch::async, &NetworkDiscovery::scanRange, this, baseIp, threadStart, threadEnd, interface));
            }
        }

        for (auto& fut : futures) {
            std::set<std::string> result = fut.get();
            activeHosts.insert(result.begin(), result.end());
        }

        auto endTime = std::chrono::steady_clock::now();
        std::chrono::duration<double> elapsed = endTime - startTime;
        std::cout << "Host discovery completed in " << elapsed.count() << " seconds\n";

        return activeHosts;
    }

    std::vector<PortScanResult> scanPorts(const std::string& ip) {
        std::vector<PortScanResult> results;
        std::mutex resultMutex;

        auto scanBatch = [&](const std::vector<int>& ports, const std::string& protocol) {
            int total_ports = ports.size();
            int threads = std::min(total_ports, static_cast<int>(std::thread::hardware_concurrency()));
            int batch_size = (total_ports + threads - 1) / threads;
            std::vector<std::future<void>> futures;
            for (int i = 0; i < threads; ++i) {
                int start = i * batch_size;
                int end = std::min(start + batch_size, total_ports);
                if (start < end) {
                    futures.push_back(std::async(std::launch::async, [&, start, end]() {
                        for (int j = start; j < end; j++) {
                            int port = ports[j];
                            ServiceInfo info = bannerGrabber.grabBanner(ip, port, protocol);
                            if (info.status == "open") {
                                bannerGrabber.fingerprint(info);
                                PortScanResult result;
                                result.port = info.port;
                                result.protocol = info.protocol;
                                result.service = info.service;
                                result.version = info.version;
                                result.banner = info.banner;
                                result.isOpen = true;
                                std::lock_guard<std::mutex> lock(resultMutex);
                                results.push_back(result);
                            }
                        }
                    }));
                }
            }
            for (auto& fut : futures) {
                fut.get();
            }
        };

        if (config_.scan_tcp) {
            scanBatch(config_.tcp_ports, "TCP");
        }

        if (config_.scan_udp) {
            scanBatch(config_.udp_ports, "UDP");
        }

        return results;
    }

    std::map<std::string, std::vector<PortScanResult>> scanNetworkAndPorts(
        const std::string& baseIp, int start, int end, const std::string& interface = "wlo1") {
        std::cout << "Starting Enhanced Network Discovery...\n";

        PacketCapture packetCapture;
        std::thread captureThread;
        if (config_.capture_packets) {
            if (!packetCapture.initialize(interface, "")) {
                std::cerr << "Packet capture initialization failed\n";
            } else {
                captureThread = std::thread([&packetCapture]() {
                    packetCapture.startCapture(-1);
                });
            }
        }

        std::set<std::string> activeHosts = scan(baseIp, start, end, interface);
        std::map<std::string, std::vector<PortScanResult>> networkResults;
        std::map<std::string, OSFingerprint> osResults;

        std::cout << "\nPerforming port scans and OS detection:\n";

        std::vector<std::future<void>> futures;
        for (const auto& host : activeHosts) {
            futures.push_back(std::async(std::launch::async, [&, host]() {
                std::cout << "Scanning ports on " << host << "...\n";
                std::vector<PortScanResult> portResults = scanPorts(host);
                networkResults[host] = portResults;

                if (config_.detect_os) {
                    std::cout << "Detecting OS on " << host << "...\n";
                    OSFingerprint osResult = osScanner.detectOS(host);
                    osResults[host] = osResult;
                }

                int tcpCount = 0, udpCount = 0;
                for (const auto& result : portResults) {
                    if (result.protocol == "TCP") tcpCount++;
                    else if (result.protocol == "UDP") udpCount++;
                }

                std::cout << "Host " << host << ": " << tcpCount << " TCP, "
                          << udpCount << " UDP ports open\n";
                if (config_.detect_os && osResults.count(host)) {
                    std::cout << "Detected OS: " << osResults[host].os_name
                              << " (confidence: " << osResults[host].confidence << "%)\n";
                }
            }));
        }

        for (auto& fut : futures) {
            fut.get();
        }

        if (config_.capture_packets && captureThread.joinable()) {
    packetCapture.stopCapture();
    captureThread.join();
    packetCapture.saveToCSV("captured_packets.csv");
    std::cout << "Packet capture saved to captured_packets.csv\n";
    }      

        return networkResults;
    }

protected:
    int numThreads_;
    ScanConfig config_;
    BannerGrabber bannerGrabber;
    OSFingerprintScanner osScanner;

    std::set<std::string> scanRange(const std::string& baseIp, int start, int end, const std::string& interface) {
        std::set<std::string> results;
        std::unique_ptr<Socket> icmpSock;
        if (config_.use_icmp) {
            int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
            if (sock >= 0) {
                icmpSock = std::make_unique<Socket>(sock);
                struct timeval tv = {config_.timeout_ms / 1000, (config_.timeout_ms % 1000) * 1000};
                setsockopt(icmpSock->get(), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            }
        }

        std::unique_ptr<Socket> arpSock;
        if (config_.use_arp) {
            int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
            if (sock >= 0) {
                arpSock = std::make_unique<Socket>(sock);
                struct timeval tv = {config_.timeout_ms / 1000, (config_.timeout_ms % 1000) * 1000};
                setsockopt(arpSock->get(), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            }
        }

        struct ifreq ifr;
        strncpy(ifr.ifr_name, interface.c_str(), IFNAMSIZ - 1);
        int ifindex = -1;
        int sockForIoctl = (arpSock ? arpSock->get() : (icmpSock ? icmpSock->get() : -1));
        if (sockForIoctl >= 0 && ioctl(sockForIoctl, SIOCGIFINDEX, &ifr) == 0) {
            ifindex = ifr.ifr_ifindex;
        }

        unsigned char src_mac[6];
        struct in_addr src_ip;
        if (sockForIoctl >= 0) {
            if (ioctl(sockForIoctl, SIOCGIFHWADDR, &ifr) == 0) {
                memcpy(src_mac, ifr.ifr_hwaddr.sa_data, 6);
            }
            if (ioctl(sockForIoctl, SIOCGIFADDR, &ifr) == 0) {
                src_ip = ((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr;
            }
        }

        for (int i = start; i <= end; ++i) {
            std::string ip = baseIp + std::to_string(i);
            std::string method;
            bool icmp_result = false;
            bool arp_result = false;

            {
                std::lock_guard<std::mutex> lock(mtx);
                std::cout << "Scanning " << ip << "... " << std::flush;
            }

            std::vector<std::future<void>> futures;
            if (config_.use_icmp && icmpSock) {
                futures.push_back(std::async(std::launch::async, [&]() { icmp_result = ping(icmpSock->get(), ip); }));
            }
            if (config_.use_arp && arpSock && ifindex >= 0) {
                futures.push_back(std::async(std::launch::async, [&]() { arp_result = arpProbe(arpSock->get(), ip, ifindex, src_mac, &src_ip); }));
            }
            for (auto& fut : futures) {
                fut.get();
            }

            if (icmp_result) method = "ICMP";
            else if (arp_result) method = "ARP";

            {
                std::lock_guard<std::mutex> lock(mtx);
                std::cout << (method.empty() ? "No response" : "Alive (" + method + ")") << "\n";
            }
            if (!method.empty()) results.insert(ip);
        }
        return results;
    }
};

int main(int argc, char* argv[]) {
    try {
        if (geteuid() != 0) {
            std::cerr << "This program requires root privileges.\n";
            return 1;
        }

        ScanConfig config;
        std::string baseIp = "192.168.193.";
        int start = 1;
        int end = 254;
        int numThreads = MAX_THREADS_DEFAULT;
        std::string interface = "wlo1";

        for (int i = 1; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--timeout" && i + 1 < argc) {
                config.timeout_ms = std::stoi(argv[++i]);
                config.connect_timeout_ms = config.timeout_ms / 2;
            } else if (arg == "--icmp-only") {
                config.use_icmp = true;
                config.use_arp = false;
            } else if (arg == "--arp-only") {
                config.use_icmp = false;
                config.use_arp = true;
            } else if (arg == "--interface" && i + 1 < argc) {
                interface = argv[++i];
            } else if (arg == "--tcp-only") {
                config.scan_tcp = true;
                config.scan_udp = false;
            } else if (arg == "--udp-only") {
                config.scan_tcp = false;
                config.scan_udp = true;
            } else if (arg == "--quick-scan") {
                config.tcp_ports = {21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080};
                config.udp_ports = {53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514};
                config.scan_well_known_ports = false;
            } else if (arg == "--aggressive") {
                config.aggressive_scan = true;
            } else if (arg == "--no-banners") {
                config.grab_banners = false;
            } else if (arg == "--no-packets") {
                config.capture_packets = false;
            } else if (arg == "--no-os") {
                config.detect_os = false;
            } else if (arg == "--os-csv" && i + 1 < argc) {
                config.os_csv_file = argv[++i];
            } else if (arg == "--tcp-ports" && i + 1 < argc) {
                std::string ports = argv[++i];
                std::istringstream portStream(ports);
                std::string port;
                config.tcp_ports.clear();
                config.scan_well_known_ports = false;
                while (std::getline(portStream, port, ',')) {
                    config.tcp_ports.push_back(std::stoi(port));
                }
            } else if (arg == "--udp-ports" && i + 1 < argc) {
                std::string ports = argv[++i];
                std::istringstream portStream(ports);
                std::string port;
                config.udp_ports.clear();
                config.scan_well_known_ports = false;
                while (std::getline(portStream, port, ',')) {
                    config.udp_ports.push_back(std::stoi(port));
                }
            } else if (arg == "--threads" && i + 1 < argc) {
                numThreads = std::stoi(argv[++i]);
            } else if (arg == "--max-port-threads" && i + 1 < argc) {
                config.maxPortThreads = std::stoi(argv[++i]);
            } else if (arg == "--ip-range" && i + 2 < argc) {
                baseIp = argv[++i];
                if (baseIp.back() != '.') baseIp += '.';
                std::string range = argv[++i];
                size_t delimPos = range.find('-');
                if (delimPos != std::string::npos) {
                    start = std::stoi(range.substr(0, delimPos));
                    end = std::stoi(range.substr(delimPos + 1));
                } else {
                    start = end = std::stoi(range);
                }
            } else if (arg == "--output-csv" && i + 1 < argc) {
                config.output_csv_file = argv[++i];
            } else if (arg == "--help") {
                std::cout << "Network Scanner Usage:\n"
                          << "  --timeout <ms>        Timeout in milliseconds (default: 1000)\n"
                          << "  --icmp-only           Use only ICMP\n"
                          << "  --arp-only            Use only ARP\n"
                          << "  --interface <if>      Network interface (default: wlo1)\n"
                          << "  --tcp-only            Scan only TCP ports\n"
                          << "  --udp-only            Scan only UDP ports\n"
                          << "  --quick-scan          Scan common ports only\n"
                          << "  --aggressive          Full port scan (1-65535)\n"
                          << "  --no-banners          Disable banner grabbing\n"
                          << "  --no-packets          Disable packet capture\n"
                          << "  --no-os               Disable OS detection\n"
                          << "  --os-csv <file>       OS fingerprint CSV file (default: os_fingerprints.csv)\n"
                          << "  --tcp-ports <list>    Comma-separated TCP ports\n"
                          << "  --udp-ports <list>    Comma-separated UDP ports\n"
                          << "  --threads <num>       Host discovery threads (default: 4)\n"
                          << "  --max-port-threads <num> Port scanning threads (default: 20)\n"
                          << "  --ip-range <ip> <n-m> IP range (e.g., 192.168.1 1-254)\n"
                          << "  --output-csv <file>   Output CSV file for scan results (default: scan_results.csv)\n"
                          << "  --help                Show this help\n";
                return 0;
            } else {
                std::cerr << "Unknown option: " << arg << "\nUse --help for usage.\n";
                return 1;
            }
        }

        std::cout << "Configuration:\n"
                  << "  Base IP: " << baseIp << "\n"
                  << "  Range: " << start << "-" << end << "\n"
                  << "  Interface: " << interface << "\n"
                  << "  Threads: " << numThreads << "\n"
                  << "  Timeout: " << config.timeout_ms << "ms\n"
                  << "  Probes: " << (config.use_icmp ? "ICMP " : "") << (config.use_arp ? "ARP" : "") << "\n"
                  << "  Scanning: " << (config.scan_tcp ? "TCP " : "") << (config.scan_udp ? "UDP" : "") << "\n"
                  << "  Banners: " << (config.grab_banners ? "Yes" : "No") << "\n"
                  << "  Packet Capture: " << (config.capture_packets ? "Yes" : "No") << "\n"
                  << "  OS Detection: " << (config.detect_os ? "Yes" : "No") << "\n"
                  << "  Output CSV: " << config.output_csv_file << "\n";

        NetworkDiscovery discovery(numThreads, config);
        std::cout << "\nScanning network...\n";
        std::map<std::string, std::vector<PortScanResult>> results =
            discovery.scanNetworkAndPorts(baseIp, start, end, interface);

        std::map<std::string, std::vector<ServiceInfo>> serviceInfoResults;
        for (const auto& host : results) {
            std::vector<ServiceInfo> hostServices;
            for (const auto& portResult : host.second) {
                ServiceInfo si = toServiceInfo(portResult);
                hostServices.push_back(si);
            }
            serviceInfoResults[host.first] = hostServices;
        }

        std::cout << "\n=== Scan Summary ===\n";
        std::cout << "Found " << results.size() << " active hosts:\n\n";
        for (const auto& host : results) {
            std::cout << "Host: " << host.first << "\n";
            std::cout << "  Open ports: " << host.second.size() << "\n";
            if (!host.second.empty()) {
                std::cout << "  Port details:\n";
                std::map<std::string, std::vector<PortScanResult>> portsByProtocol;
                for (const auto& port : host.second) {
                    portsByProtocol[port.protocol].push_back(port);
                }
                if (!portsByProtocol["TCP"].empty()) {
                    std::cout << "    TCP:\n";
                    for (const auto& port : portsByProtocol["TCP"]) {
                        std::cout << "      " << port.port << "/" << port.protocol
                                  << " (" << port.service << ")";
                        if (!port.version.empty()) {
                            std::cout << " Version: " << port.version;
                        }
                        if (!port.banner.empty()) {
                            std::cout << " - " << port.banner;
                        }
                        std::cout << "\n";
                    }
                }
                if (!portsByProtocol["UDP"].empty()) {
                    std::cout << "    UDP:\n";
                    for (const auto& port : portsByProtocol["UDP"]) {
                        std::cout << "      " << port.port << "/" << port.protocol
                                  << " (" << port.service << ")";
                        if (!port.version.empty()) {
                            std::cout << " Version: " << port.version;
                        }
                        if (!port.banner.empty()) {
                            std::cout << " - " << port.banner;
                        }
                        std::cout << "\n";
                    }
                }
            }
            std::cout << "\n";
        }

        if (config.grab_banners) {
            std::cout << "Exporting scan results to " << config.output_csv_file << "...\n";
            for (const auto& host : serviceInfoResults) {
                if (!host.second.empty()) {
                    try {
                        std::ofstream outfile(config.output_csv_file, std::ios::app);
                        if (!outfile.is_open()) {
                            BannerGrabber::writeToCSV(host.first, host.second, config.output_csv_file);
                        } else {
                            outfile.close();
                            BannerGrabber::writeToCSV(host.first, host.second, config.output_csv_file);
                        }
                        std::cout << "Results for " << host.first << " written to " << config.output_csv_file << "\n";
                    } catch (const std::exception& e) {
                        std::cerr << "Failed to write to CSV for " << host.first << ": " << e.what() << "\n";
                    }
                }
            }
            std::cout << "CSV export completed.\n";
        }

        std::cout << "Scan completed.\n";
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}