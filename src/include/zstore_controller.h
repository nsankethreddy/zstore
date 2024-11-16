#pragma once
#include "types.h"
#include <boost/asio/awaitable.hpp>
#include <boost/unordered/concurrent_flat_map.hpp>
#include <boost/unordered/concurrent_flat_set.hpp>
#include <cstring>
#include <queue>
#include <shared_mutex>
#include <spdk/env.h>
#include <spdk/thread.h>
#include <unistd.h>

namespace asio = boost::asio; // from <boost/asio.hpp>
using ZstoreMap = boost::concurrent_flat_map<ObjectKeyHash, MapEntry>;
using ZstoreBloomFilter = boost::concurrent_flat_set<ObjectKeyHash>;
using ZstoreGcSet = boost::concurrent_flat_set<TargetLbaTuple>;

class Device;
class Zone;

class ZstoreController
{
  public:
    int PopulateDevHash();
    int PopulateMap();
    Result<void> DumpAllMap();
    Result<void> ReadAllMap();

    void writeMapToFile(const std::string &filename);
    void readMapFromFile(const std::string &filename);

    // Result<void> PopulateMap(bool bogus, int key_experiment);
    // Result<void> PopulateDevHash(int key_experiment);

    Result<DevTuple> GetDevTuple(ObjectKeyHash object_key_hash);
    Result<DevTuple> GetDevTupleForRandomReads(ObjectKeyHash key_hash);

    int pivot;
    int queue_depth = 0;

    // ZStore Device Consistent Hashmap: this maintains a consistent hash map
    // which maps object key to tuple of devices. Right now this is
    // pre-populated and just randomly
    std::vector<DevTuple> mDevHash;
    std::shared_mutex mDevHashMutex;

    // ZStore Map: this maps key to tuple of ZNS target and lba
    ZstoreMap mMap;
    // Map APIs
    Result<bool> PutObject(const ObjectKeyHash &key_hash, MapEntry entry);
    std::optional<MapEntry> GetObject(const ObjectKeyHash &key_hash);
    Result<std::vector<ObjectKeyHash>> ListObjects();
    Result<MapEntry> CreateFakeObject(ObjectKeyHash key_hash, DevTuple tuple);
    Result<MapEntry> DeleteObject(const ObjectKeyHash &key_hash);

    // ZStore Bloom Filter: this maintains a bloom filter of hashes of
    // object name (key).
    //
    // For simplicity, right now we are just using a set to keep track of
    // the hashes
    ZstoreBloomFilter mBF;
    // Bloomfilter APIs
    Result<bool> SearchBF(const ObjectKeyHash &key_hash);
    Result<bool> UpdateBF(const ObjectKeyHash &key_hash);

    // ZStore GC Map: we keep tracks of blocks that we need to GC. Note that we
    // can potentially optimize this to be per zone tracking, which will help
    // scaning it
    ZstoreGcSet mGcSet;
    Result<bool> AddGcObject(const TargetLbaTuple &tuple);

    ZstoreController(asio::io_context &ioc) : mIoc_(ioc){};
    // The io_context is required for all I/O
    asio::io_context &mIoc_;

    ~ZstoreController();
    int Init(bool object, int key_experiment, int phase);

    // threads
    void initIoThread();
    // void initDispatchThread();
    // void initCompletionThread();
    // void initHttpThread();

    struct spdk_thread *GetIoThread(int id) { return mIoThread[id].thread; };
    // struct spdk_thread *GetDispatchThread() { return mDispatchThread; }
    // struct spdk_thread *GetHttpThread(int id) { return
    // mHttpThread[id].thread; } struct spdk_thread *GetCompletionThread() {
    // return mCompletionThread; }

    // SPDK components
    struct spdk_nvme_qpair *GetIoQpair();
    bool CheckIoQpair(std::string msg);
    int GetQueueDepth() { return mQueueDepth; };
    void setQueuDepth(int queue_depth) { mQueueDepth = queue_depth; };
    void setKeyExperiment(int key) { mKeyExperiment = key; };
    void setPhase(int phase) { mPhase = phase; };

    void SetEventPoller(spdk_poller *p) { mEventsPoller = p; }
    // void SetCompletionPoller(spdk_poller *p) { mCompletionPoller = p; }
    // void SetDispatchPoller(spdk_poller *p) { mDispatchPoller = p; }
    // void SetHttpPoller(spdk_poller *p) { mHttpPoller = p; }

    int GetContextPoolSize() { return mContextPoolSize; };
    void setContextPoolSize(int context_pool_size)
    {
        mContextPoolSize = context_pool_size;
    };

    void setNumOfDevices(int num_of_device) { mN = num_of_device; };

    // Setting up SPDK
    void register_ctrlr(std::vector<Device *> &g_devices,
                        struct spdk_nvme_ctrlr *ctrlr, const char *traddr,
                        const uint32_t zone_id1, const uint32_t zone_id2);
    void register_ns(struct spdk_nvme_ctrlr *ctrlr, struct spdk_nvme_ns *ns);

    int register_workers();
    int register_controllers(
        std::vector<Device *> &g_devices,
        const std::tuple<std::string, std::string, u32, u32> &dev_tuple);
    void unregister_controllers(std::vector<Device *> &g_devices);
    void zstore_cleanup();
    void zns_dev_init(
        std::vector<Device *> &g_devices,
        const std::tuple<std::string, std::string, u32, u32> &dev_tuple);

    int associate_workers_with_ns(Device *device);
    void cleanup_ns_worker_ctx();
    void cleanup(uint32_t task_count);

    int init_ns_worker_ctx(struct ns_worker_ctx *ns_ctx,
                           enum spdk_nvme_qprio qprio);

    // TODO:
    // void Append(uint64_t zslba, uint32_t size, void *data, void *cb_args);
    //
    // void Write(uint64_t offset, uint32_t size, void *data,
    //            zns_raid_request_complete cb_fn, void *cb_args);
    //
    // Result<void> Read(uint64_t offset, Device *dev, HttpRequest request,
    //                   std::function<void(HttpRequest)> fn);
    //
    // void Execute(uint64_t offset, uint32_t size, void *data, bool
    // is_write,
    //              zns_raid_request_complete cb_fn, void *cb_args);

    void Drain();

    // net::awaitable<void> EnqueueRead(RequestContext *ctx);
    // void EnqueueWrite(RequestContext *ctx);
    // std::queue<RequestContext *> &GetWriteQueue() { return mWriteQueue; }
    // int GetWriteQueueSize() { return mWriteQueue.size(); };
    // std::queue<RequestContext *> &GetReadQueue() { return mReadQueue; }
    // int GetReadQueueSize() { return mReadQueue.size(); };

    // int GetEventsToDispatchSize();

    // std::queue<RequestContext *> &GetRequestQueue();
    // std::shared_mutex &GetRequestQueueMutex();
    // std::shared_mutex &GetSessionMutex();
    // std::mutex &GetRequestQueueMutex();
    // int GetRequestQueueSize();

    // void UpdateIndexNeedLock(uint64_t lba, PhysicalAddr phyAddr);
    // void UpdateIndex(uint64_t lba, PhysicalAddr phyAddr);
    // int GetNumInflightRequests();

    // void WriteInDispatchThread(RequestContext *ctx);
    // void ReadInDispatchThread(RequestContext *ctx);
    // void EnqueueEvent(RequestContext *ctx);

    void ReclaimContexts();
    void Flush();
    void Dump();

    // bool Append(RequestContext *ctx, uint32_t offset);
    // bool Read(RequestContext *ctx, uint32_t pos, PhysicalAddr phyAddr);
    void Reset(RequestContext *ctx);
    bool IsResetDone();
    // void WriteComplete(RequestContext *ctx);
    // void ReadComplete(RequestContext *ctx);

    void AddZone(Zone *zone);
    const std::vector<Zone *> &GetZones();
    void PrintStats();

    bool start = false;
    chrono_tp stime;

    RequestContextPool *mRequestContextPool;
    // std::unordered_set<RequestContext *> mInflightRequestContext;

    bool verbose;
    bool isDraining;

    // debug
    // std::map<uint32_t, uint64_t> mReadCounts;
    // uint64_t mTotalReadCounts = 0;
    uint64_t mTotalCounts = 0;
    uint64_t mManagementCounts = 0;

    Device *GetDevice(const std::string &target_dev)
    {
        // NOTE currently we don't create mapping between target device to
        // Device object, as such mapping is static. As such we manually do a
        // switch on all target device cases
        if (target_dev == "Zstore2Dev1") {
            return mDevices[0];
        } else if (target_dev == "Zstore2Dev2") {
            return mDevices[1];
        } else if (target_dev == "Zstore3Dev1") {
            return mDevices[2];
        } else if (target_dev == "Zstore3Dev2") {
            return mDevices[3];
        } else if (target_dev == "Zstore4Dev1") {
            return mDevices[4];
        } else if (target_dev == "Zstore4Dev2") {
            return mDevices[5];
        } else {
            log_error("target device does not exist {}", target_dev);
        }
    };

    int mKeyExperiment;
    // 1: Random Read
    // 2: Sequential write (append) and read
    // 3: Target failure
    // 4: gateway failure
    // 5: Target and gateway failure
    // 6: GC
    // 7: Checkpoint

    int mPhase;
    // 1: prepare
    // 2: run

  private:
    // number of devices
    int mN;
    // context pool size
    int mContextPoolSize;
    int _map_size = 1'000'000;

    // RequestContext *getContextForUserRequest();
    // void doWrite(RequestContext *context);
    // void doRead(RequestContext *context);

    std::vector<Device *> mDevices;
    // std::queue<RequestContext *> mRequestQueue;
    // std::shared_mutex mRequestQueueMutex;

    spdk_poller *mEventsPoller = nullptr;
    // spdk_poller *mDispatchPoller = nullptr;
    // spdk_poller *mHttpPoller = nullptr;
    // spdk_poller *mCompletionPoller = nullptr;

    int mQueueDepth = 1;

    IoThread mIoThread[16];
    // struct spdk_thread *mDispatchThread;
    // IoThread mHttpThread[16];
    // struct spdk_thread *mCompletionThread;

    std::queue<RequestContext *> mEventsToDispatch;
    // std::queue<RequestContext *> mWriteQueue;
    // std::queue<RequestContext *> mReadQueue;

    std::vector<Zone *> mZones;
};
