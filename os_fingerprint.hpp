#ifndef OS_FINGERPRINT_HPP
#define OS_FINGERPRINT_HPP

#include <string>
#include <map>
#include <vector>
#include <mutex>

/**
 * @struct OSFingerprint
 * @brief Structure to hold the results of an OS fingerprinting scan.
 */
struct OSFingerprint {
    std::string target_ip;    ///< The target IP address being scanned.
    std::string os_name;      ///< The detected operating system name.
    int confidence;           ///< Confidence level of the OS detection (0-100).
    bool fin_scan_rst;        ///< Whether a RST was received for the FIN scan.
    bool null_scan_rst;       ///< Whether a RST was received for the NULL scan.
    bool xmas_scan_rst;       ///< Whether a RST was received for the XMAS scan.
    int ttl;                  ///< Time-to-live value from the response.
    int window_size;          ///< TCP window size from the response.
};

/**
 * @class OSFingerprintScanner
 * @brief Class to perform OS fingerprinting on target IP addresses.
 */
class OSFingerprintScanner {
public:
    // Constants for scan types
    static const int OS_FINGERPRINT_FIN_SCAN  = 1; ///< FIN scan type identifier.
    static const int OS_FINGERPRINT_NULL_SCAN = 2; ///< NULL scan type identifier.
    static const int OS_FINGERPRINT_XMAS_SCAN = 3; ///< XMAS scan type identifier.

    /**
     * @brief Constructor initializing the CSV file path for logging results.
     * @param csv_file Path to the CSV file where scan results will be logged.
     */
    OSFingerprintScanner(const std::string& csv_file);

    /**
     * @brief Detects the operating system of a single IP address.
     * @param ip The target IP address to scan.
     * @param testPort The port to use for scanning (default is 80).
     * @return OSFingerprint struct containing the detection results.
     */
    OSFingerprint detectOS(const std::string& ip, int testPort = 80);

    /**
     * @brief Performs OS detection on a batch of IP addresses.
     * @param ips Vector of IP addresses to scan.
     * @param testPort The port to use for scanning (default is 80).
     * @return Map associating each IP address with its OSFingerprint result.
     */
    std::map<std::string, OSFingerprint> batchScan(const std::vector<std::string>& ips, int testPort = 80);

private:
    std::string csv_file_;        ///< Path to the CSV file for logging.
    static std::mutex csvMutex;   ///< Mutex for thread-safe CSV file access.

    /**
     * @brief Logs the OS fingerprint result to the CSV file.
     * @param fingerprint The OSFingerprint result to log.
     */
    void logToCSV(const OSFingerprint& fingerprint);
};

#endif // OS_FINGERPRINT_HPP