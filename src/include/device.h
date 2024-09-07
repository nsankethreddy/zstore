#pragma once
#include "common.h"
#include "spdk/nvme.h"
#include "spdk/nvme_zns.h"
#include <set>
#include <unordered_map>
#include <vector>

class Zone;
class Device
{
  public:
    ~Device();
    void Init(struct spdk_nvme_ctrlr *ctrlr, int nsid);
    void InitZones(uint32_t numNeededZones, uint32_t numReservedZones);
    void EraseWholeDevice();
    void ConnectIoPairs();

    // I/O operations
    void Write(uint64_t offset, uint32_t size, void *ctx);  // zone write
    void Append(uint64_t offset, uint32_t size, void *ctx); // zone append
    void Read(uint64_t offset, uint32_t size, void *ctx);   // zone read

    // admin commands
    void ResetZone(Zone *zone, void *ctx);
    void FinishZone(Zone *zone, void *ctx); // seal
    bool HasAvailableZone();
    Zone *OpenZone();
    Zone *OpenZoneBySlba(uint64_t slba);
    void ReturnZone(Zone *);

    void AddAvailableZone(Zone *zone);

    void SetDeviceId(uint32_t deviceId) { mDeviceId = deviceId; }
    uint32_t GetDeviceId() { return mDeviceId; }

    struct spdk_nvme_ctrlr *GetController() { return mController; }
    struct spdk_nvme_ns *GetNamespace() { return mNamespace; }
    struct spdk_nvme_qpair *GetIoQueue() { return mQpair; }
    // struct spdk_nvme_qpair *GetIoQueue(uint32_t id) { return mIoQueues[id]; }

    uint64_t GetZoneCapacity();
    uint64_t GetZoneSize();
    uint32_t GetNumZones();

    void ReadZoneHeaders(std::map<uint64_t, uint8_t *> &zones);

    void SetDeviceTransportAddress(const char *addr);
    char *GetDeviceTransportAddress() const;

    void startIo(RequestContext *slot);
    void issueIo2(spdk_event_fn event_fn, RequestContext *slot);
    void issueIo(spdk_msg_fn msg_fn, RequestContext *slot);

  private:
    uint64_t bytes2Block(uint64_t bytes);
    uint64_t bytes2ZoneNum(uint64_t bytes);

    struct spdk_nvme_ctrlr *mController;
    struct spdk_nvme_ns *mNamespace;

    // struct spdk_nvme_qpair **mIoQueues;
    struct spdk_nvme_qpair *mQpair;

    uint64_t mZoneSize;     // in blocks
    uint64_t mZoneCapacity; // in blocks
    uint32_t mNumZones;     // in blocks

    uint32_t mDeviceId;

    std::set<Zone *> mAvailableZones;
    Zone *mZones;

    // debug
    std::map<uint32_t, uint64_t> mReadCounts;
    uint64_t mTotalReadCounts = 0;
    uint64_t mTotalReadSizes = 0;

    // indicate the PCIe slot - used to number the drives
    char mTransportAddress[SPDK_NVMF_TRADDR_MAX_LEN + 1];
};
