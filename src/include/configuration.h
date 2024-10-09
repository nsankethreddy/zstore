#pragma once
#include "utils.h"
#include <string>

class Configuration
{
  public:
    static Configuration &GetInstance()
    {
        static Configuration instance;
        return instance;
    }

    static void PrintConfigurations()
    {
        Configuration &instance = GetInstance();
        // const char *systemModeStrs[] = {"ZoneWrite-Only", "ZoneAppend-Only",
        //                                 "ZapRAID", "RAIZN-Simple"};
        // printf("ZapRAID Configuration:\n");
        log_info("-- Block size: {}", instance.GetBlockSize());
        // for (int i = 0; i < instance.gNumOpenSegments; i++) {
        //     printf("-- Raid mode: %d %d %d %d %d | %d--\n",
        //            instance.gStripeConfig[i].size,
        //            instance.gStripeConfig[i].dataSize,
        //            instance.gStripeConfig[i].paritySize,
        //            instance.gStripeConfig[i].unitSize,
        //            instance.gStripeConfig[i].groupSize,
        //            instance.gRaidScheme);
        // }
        // printf("-- System mode: %s --\n",
        //        systemModeStrs[(int)instance.gSystemMode]);
        // printf("-- GC Enable: %d --\n", instance.gEnableGc);
        // printf("-- Framework Enable: %d --\n",
        // instance.gEnableEventFramework);
        log_info("-- Storage size: {} -- ({} GiB)\n",
                 instance.gStorageSpaceInBytes,
                 instance.gStorageSpaceInBytes / 1024 / 1024 / 1024);
    }

    static void SetBlockSize(int blockSize)
    {
        GetInstance().gBlockSize = blockSize;
    }

    static int GetBlockSize() { return GetInstance().gBlockSize; }

    static int GetQueueDepth() { return GetInstance().gQueueDepth; }

    static int GetContextPoolSize() { return GetInstance().gContextPoolSize; }

    static int GetNumOfTargets() { return GetInstance().gNumOfTargets; }

    static int GetNumOfDevices() { return GetInstance().gNumOfDevices; }

    static int GetMetadataSize() { return GetInstance().gMetadataSize; }

    static int GetNumIoThreads() { return GetInstance().gNumIoThreads; }

    static int GetNumHttpThreads() { return GetInstance().gNumHttpThreads; }

    static bool UseDummyWorkload() { return GetInstance().gUseDummyWorkload; }
    static bool UseObject() { return GetInstance().gUseObject; }
    static bool UseHttp() { return GetInstance().gUseHttp; }
    static bool UseWorkStealing() { return GetInstance().gUseWorkStealing; }

    static bool GetDeviceSupportMetadata()
    {
        return GetInstance().gDeviceSupportMetadata;
    }

    static void SetDeviceSupportMetadata(bool flag)
    {
        GetInstance().gDeviceSupportMetadata = flag;
    }

    // static uint32_t GetReceiverThreadCoreId()
    // {
    //     return GetInstance().gReceiverThreadCoreId;
    // }

    // static uint32_t GetIndexThreadCoreId()
    // {
    //     return GetInstance().gIndexThreadCoreId;
    // }

    static uint32_t GetDispatchThreadCoreId()
    {
        return GetInstance().gDispatchThreadCoreId;
    }

    // static uint32_t GetCompletionThreadCoreId()
    // {
    //     return GetInstance().gCompletionThreadCoreId;
    // }

    static uint32_t GetIoThreadCoreId()
    {
        return GetInstance().gIoThreadCoreIdBase;
    }

    static uint32_t GetIoThreadCoreId(uint32_t thread_id)
    {
        return GetInstance().gIoThreadCoreIdBase + thread_id;
    }

    static uint32_t GetHttpThreadCoreId()
    {
        return GetInstance().gHttpThreadCoreIdBase;
    }

    static uint32_t GetHttpThreadCoreId(uint32_t thread_id)
    {
        return GetInstance().gHttpThreadCoreIdBase + thread_id;
    }

    static void SetStorageSpaceInBytes(uint64_t storageSpaceInBytes)
    {
        GetInstance().gStorageSpaceInBytes = storageSpaceInBytes;
    }

    static uint64_t GetStorageSpaceInBytes()
    {
        return GetInstance().gStorageSpaceInBytes;
    }

    static uint32_t GetTotalIo() { return GetInstance().gTotalIO; }

    static uint64_t GetZoneDist() { return GetInstance().gZoneDist; }

    static uint64_t GetZslba()
    {
        return GetInstance().gZoneDist * GetInstance().current_zone;
    }

  private:
    // Hardcode because they won't change
    const uint64_t gZoneDist = 0x80000; // zone size
    int gBlockSize = 4096;
    int gMetadataSize = 64;
    bool gDeviceSupportMetadata = true;
    // int gZoneCapacity = 0;

    // Configured parameters
    int gQueueDepth = 256;
    int gContextPoolSize = 4096;

    // how many targets one gateway talks to
    int gNumOfTargets = 1;
    // how many devices/drives on a target
    int gNumOfDevices = 1;

    bool gUseObject = false;
    bool gUseDummyWorkload = false;
    bool gUseHttp = true;
    // TODO: use other spdk thread to work stealing
    bool gUseWorkStealing = false;

    const int current_zone = 49;
    // uint32_t gTotalIO = 4'000'000;

    int gNumIoThreads = 2;
    int gNumHttpThreads = 8;

    uint64_t gStorageSpaceInBytes = 1024 * 1024 * 1024 * 1024ull; // 1TiB

    uint32_t gDispatchThreadCoreId = 1;
    uint32_t gIoThreadCoreIdBase = 2;
    uint32_t gHttpThreadCoreIdBase = gIoThreadCoreIdBase + gNumIoThreads;

    // Not used for now; functions collocated with dispatch thread.
    // uint32_t gCompletionThreadCoreId = 5;
    // uint32_t gIndexThreadCoreId = 6;
    // uint32_t gReceiverThreadCoreId = 8;
    // int gLargeRequestThreshold = 16 * 1024;

    // FIXME total IO more than this causes failures
    // FIXME queue size larger than 64 causes issue
    uint32_t gTotalIO = 2'000'000;
    // uint32_t gTotalIO = 500'000;
};
