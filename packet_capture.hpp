#ifndef PACKET_CAPTURE_HPP
#define PACKET_CAPTURE_HPP

#include <string>
#include <vector>
#include <mutex>
#include <pcap/pcap.h>

/**
 * @struct PacketInfo
 * @brief Structure to hold information about a captured packet.
 */
struct PacketInfo {
    std::string timestamp;            ///< Timestamp of the packet capture in "YYYY-MM-DD HH:MM:SS" format.
    std::string sourceIP;             ///< Source IP address of the packet.
    std::string destIP;               ///< Destination IP address of the packet.
    int sourcePort;                   ///< Source port number (0 if not applicable).
    int destPort;                     ///< Destination port number (0 if not applicable).
    std::string protocol;             ///< Protocol type (e.g., "TCP", "UDP", "Other").
    int packetLength;                 ///< Total length of the packet in bytes.
    std::vector<unsigned char> payload; ///< Payload data of the packet.
};

/**
 * @class PacketCapture
 * @brief Class to capture and manage network packets using libpcap.
 */
class PacketCapture {
public:
    /**
     * @brief Constructs a PacketCapture object, initializing internal members.
     */
    PacketCapture();

    /**
     * @brief Destroys the PacketCapture object, closing the pcap handle if open.
     */
    ~PacketCapture();

    /**
     * @brief Initializes packet capture on a specified network interface with an optional filter.
     * @param interface Network interface name (empty string uses default interface).
     * @param filter Berkeley Packet Filter (BPF) string (empty for no filter).
     * @return True if initialization succeeds, false otherwise.
     */
    bool initialize(const std::string& interface, const std::string& filter);

    /**
     * @brief Starts capturing packets on the initialized interface.
     * @param packetCount Number of packets to capture (-1 for unlimited).
     * @return True if capture starts successfully, false if not initialized.
     */
    bool startCapture(int packetCount);

    /**
     * @brief Captures packets from a specified pcap file.
     * @param filename Path to the pcap file to read from.
     * @return True if file is read successfully, false otherwise.
     */
    bool captureFromFile(const std::string& filename);

    /**
     * @brief Stops an ongoing packet capture.
     */
    void stopCapture();

    /**
     * @brief Saves captured packet information to a CSV file.
     * @param filename Path to the output CSV file.
     * @return True if file is written successfully, false otherwise.
     */
    bool saveToCSV(const std::string& filename);

    /**
     * @brief Retrieves a list of available network interfaces.
     * @return Vector of interface names.
     */
    std::vector<std::string> getNetworkInterfaces();

    /**
     * @brief Static handler function for libpcap to process captured packets.
     * @param userData Pointer to the PacketCapture instance.
     * @param pkthdr Packet header containing metadata (e.g., timestamp, length).
     * @param packet Raw packet data.
     */
    static void packetHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);

    /** @brief Vector storing captured packet information, accessible publicly. */
    std::vector<PacketInfo> packets;

private:
    pcap_t* handle;               ///< Pointer to the libpcap session handle.
    bool running;                 ///< Flag indicating if capture is active.
    char errbuf[PCAP_ERRBUF_SIZE]; ///< Buffer for storing libpcap error messages.
    static std::mutex csvMutex;   ///< Mutex for thread-safe CSV file operations.

    /**
     * @brief Processes a captured packet and extracts its details into packets vector.
     * @param pkthdr Packet header with metadata.
     * @param packet Raw packet data.
     */
    void processPacket(const struct pcap_pkthdr* pkthdr, const u_char* packet);
};

#endif // PACKET_CAPTURE_HPP