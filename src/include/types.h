#pragma once
#include "device.h"
#include "utils.h"
#include <boost/beast/http.hpp>
#include <fmt/chrono.h>
#include <shared_mutex>
#include <spdk/nvme.h>
#include <string>
#include <tuple>
#include <vector>

// HTTP stuff
namespace http = boost::beast::http; // from <boost/beast/http.hpp>
typedef http::request<http::string_body> HttpRequest;
typedef http::response<http::string_body> HttpResponse;

// Basic Zstore types
typedef std::string ObjectKey;
typedef std::array<uint8_t, 32> ObjectKeyHash;
typedef std::string TargetDev;
typedef u64 Lba;
typedef u32 Length;

// Custom hash function for std::array<uint8_t, 32>
struct ArrayHash {
    std::size_t operator()(const std::array<uint8_t, 32> &key) const
    {
        std::size_t hash = 0;
        for (auto byte : key) {
            hash = hash * 31 + byte; // Simple hash combination
        }
        return hash;
    }
};

// Device types
typedef std::tuple<TargetDev, Lba, Length> TargetLbaTuple;
typedef std::tuple<Lba, Length> LbaTuple;
typedef std::tuple<std::pair<TargetDev, u32>, std::pair<TargetDev, u32>,
                   std::pair<TargetDev, u32>>
    DevTuple;

// This is the most important data structure of Zstore as it holds the mapping
// of object key to object location on the storage device.
//
// There are a couple of future improvements that can be made:
// - we can use a sha256 hash of the object key to reduce the size of the key
// - we can use the index of target device instead of the target device name
// - when we GC or renew epoch, it seems like we will need to create a blocking
// operation on the map
// https://www.boost.org/doc/libs/1_86_0/libs/unordered/doc/html/unordered.html#concurrent_blocking_operations
using MapEntry = std::tuple<TargetLbaTuple, TargetLbaTuple, TargetLbaTuple>;

// Circular buffer for RDMA writes
struct BufferEntry {
    ObjectKeyHash sha256_hash; // SHA256 hash: 32 bytes
    uint8_t epoch;             // Epoch: 1 byte
    uint8_t target_device_id;  // Target device ID: 1 byte
    uint64_t lba;              // Logical Block Address: 8 bytes
    uint32_t length;           // Length: 4 bytes
};

class ZstoreController;

struct DrainArgs {
    ZstoreController *ctrl;
    bool success;
    bool ready;
};

struct RequestContext {
    // The buffers are pre-allocated
    char *dataBuffer;

    uint64_t lba;
    uint32_t size;
    // uint8_t req_type;
    // char *data;
    // uint32_t successBytes;
    // uint32_t targetBytes;
    // uint32_t curOffset;
    void *cb_args;
    uint32_t ioOffset;
    bool available;

    ZstoreController *ctrl;
    struct spdk_thread *io_thread;
    Device *device;
    uint32_t zoneId;
    uint32_t offset;

    double stime;
    double ctime;
    uint64_t timestamp;
    struct timeval timeA;

    struct {
        struct spdk_nvme_ns *ns;
        struct spdk_nvme_qpair *qpair;
        char *data;
        uint64_t offset; // lba
        uint32_t size;   // lba_count
        uint32_t flags;
        // only used for management commands
        spdk_nvme_cmd_cb cb;
        void *ctx;
    } ioContext;
    uint32_t bufferSize; // for recording partial writes

    // HttpRequest request;
    // bool keep_alive;

    bool success;

    // For write append
    bool is_write;
    bool write_complete;
    uint64_t append_lba;
    std::string response_body;

    void Clear();
    // void Queue();
    // double GetElapsedTime();
    // void PrintStats();
    // void CopyFrom(const RequestContext &o);
};

struct IoThread {
    struct spdk_nvme_poll_group *group;
    struct spdk_thread *thread;
    uint32_t threadId;
    ZstoreController *controller;
};

struct RequestContextPool {
    RequestContext *contexts;
    std::vector<RequestContext *> availableContexts;
    uint32_t capacity;

    RequestContextPool(uint32_t cap);
    RequestContext *GetRequestContext(bool force);
    void ReturnRequestContext(RequestContext *slot);
};

// From SimpleSZD
/**
 * @brief Holds general information about a ZNS device.
 */
typedef struct {
    uint64_t
        lba_size; /**< Size of one block, also known as logical block address.*/
    uint64_t zone_size; /**<  Size of one zone in lbas.*/
    uint64_t zone_cap;  /**< Size of user availabe space in one zone. */
    uint64_t mdts;      /**<  Maximum data transfer size in bytes.*/
    uint64_t zasl;      /**<  Maximum size of one append command in bytes.*/
    uint64_t lba_cap;   /**<  Amount of lbas available on the device.*/
    uint64_t min_lba;   /**< Minimum lba that is allowed to be written to.*/
    uint64_t max_lba;   /**< Maximum lba that is allowed to be written to.*/
    const char *name;   /**< Name used by SPDK to identify device.*/
} DeviceInfo;
extern const DeviceInfo DeviceInfo_default;

using chrono_tp = std::chrono::high_resolution_clock::time_point;
struct Timer {
    chrono_tp t1;
    chrono_tp t2;
    chrono_tp t3;
    chrono_tp t4;
    chrono_tp t5;
    chrono_tp t6;
    // bool check;
};

struct cinfo {
    uint32_t generic_key;
    uint64_t generic_addr;
    uint32_t magic_key;
    uint64_t magic_addr;
};
