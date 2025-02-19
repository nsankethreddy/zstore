#include "../include/object.h"
#include "../include/utils.h"
#include "../object.cc"
#include <cassert>
#include <cassert> // For assert
#include <cstring>
#include <iostream>
#include <spdk/env.h>
#include <spdk/nvme.h>
#include <spdk/nvme_zns.h>
#include <spdk/string.h>

static bool g_completion_done = false;

// Simple completion callback that just signals we're done
static void zone_append_completion(void *arg, const struct spdk_nvme_cpl *cpl)
{
    bool *done = static_cast<bool *>(arg);
    *done = true;

    if (spdk_nvme_cpl_is_error(cpl)) {
        std::cerr << "[ERROR] Zone append completion status: "
                  << spdk_nvme_cpl_get_status_string(&cpl->status) << "\n";
    } else {
        // If successful, cdw0 holds the LBA where data was appended
        uint64_t start_lba = cpl->cdw0;
        std::cout << "[INFO] Successfully appended buffer to LBA: 0x"
                  << std::hex << start_lba << "\n";
    }
}

void sendBufferToZnsSSD(const std::vector<uint8_t> &buffer)
{
    // -----------------------------
    // 1. Initialize SPDK Environment
    // -----------------------------
    struct spdk_env_opts opts;
    spdk_env_opts_init(&opts);
    opts.name = "send_buffer_app";
    opts.core_mask = "0x1"; // pin to core 0 (example)
    if (spdk_env_init(&opts) < 0) {
        std::cerr << "[ERROR] spdk_env_init() failed.\n";
        return;
    }

    // -----------------------------
    // 2. Connect to an NVMe device
    //    (Local PCIe example)
    // -----------------------------
    struct spdk_nvme_transport_id trid = {};
    spdk_nvme_trid_populate_transport(&trid, SPDK_NVME_TRANSPORT_PCIE);
    // If you have a specific PCI BDF, set it here, e.g.:
    // strncpy(trid.traddr, "0000:81:00.0", sizeof(trid.traddr));

    struct spdk_nvme_ctrlr_opts ctrlr_opts;
    spdk_nvme_ctrlr_get_default_ctrlr_opts(&ctrlr_opts, sizeof(ctrlr_opts));

    // Attempt to connect
    struct spdk_nvme_ctrlr *ctrlr =
        spdk_nvme_connect(&trid, &ctrlr_opts, sizeof(ctrlr_opts));
    if (!ctrlr) {
        std::cerr << "[ERROR] spdk_nvme_connect() failed.\n";
        spdk_env_fini();
        return;
    }

    // --------------------------------------------------
    // 3. Pick the first namespace & verify it's ZNS
    // --------------------------------------------------
    // For simplicity, we assume namespace 1
    uint32_t ns_id = 1;
    struct spdk_nvme_ns *ns = spdk_nvme_ctrlr_get_ns(ctrlr, ns_id);
    if (!ns) {
        std::cerr << "[ERROR] Failed to get namespace " << ns_id << "\n";
        spdk_nvme_detach(ctrlr);
        spdk_env_fini();
        return;
    }
    // Check that it's a ZNS namespace
    if (spdk_nvme_ns_get_csi(ns) != SPDK_NVME_CSI_ZNS) {
        std::cerr << "[ERROR] Namespace " << ns_id << " is not ZNS.\n";
        spdk_nvme_detach(ctrlr);
        spdk_env_fini();
        return;
    }

    // --------------------------------------------------
    // 4. Allocate I/O QPair
    // --------------------------------------------------
    // (Using default options here)
    struct spdk_nvme_qpair *qpair =
        spdk_nvme_ctrlr_alloc_io_qpair(ctrlr, nullptr, 0);
    if (!qpair) {
        std::cerr << "[ERROR] spdk_nvme_ctrlr_alloc_io_qpair() failed.\n";
        spdk_nvme_detach(ctrlr);
        spdk_env_fini();
        return;
    }

    // --------------------------------------------------
    // 5. Allocate DMA buffer and copy data
    // --------------------------------------------------
    // We'll do a single zone append for the entire buffer.
    // The drive I/O size must be aligned to block size.
    // For a simpler approach, we require buffer.size() is a multiple of the
    // namespace's block size (extended sector size).
    uint32_t block_size = spdk_nvme_ns_get_extended_sector_size(ns);
    if (buffer.size() % block_size != 0) {
        std::cerr << "[ERROR] Buffer length is not a multiple of block size ("
                  << block_size << " bytes).\n";
        spdk_nvme_ctrlr_free_io_qpair(qpair);
        spdk_nvme_detach(ctrlr);
        spdk_env_fini();
        return;
    }

    // Number of LBAs to write
    uint32_t num_blocks = buffer.size() / block_size;

    void *dma_buf = spdk_dma_zmalloc(buffer.size(), 4096, nullptr);
    if (!dma_buf) {
        std::cerr << "[ERROR] spdk_dma_zmalloc() failed.\n";
        spdk_nvme_ctrlr_free_io_qpair(qpair);
        spdk_nvme_detach(ctrlr);
        spdk_env_fini();
        return;
    }

    // Copy user buffer into DMA buffer
    memcpy(dma_buf, buffer.data(), buffer.size());

    // --------------------------------------------------
    // 6. Send the Zone Append command
    // --------------------------------------------------
    // For this example, let's use the first zone, whose size might be e.g.
    // 0x80000 blocks (this is just an example—real devices vary). Typically
    // you'd query the zone size via spdk_nvme_zns_get_zone_info().
    uint64_t zone_size_in_blocks = 0x80000;       // example
    uint64_t zone_slba = zone_size_in_blocks * 0; // zone #0

    g_completion_done = false;

    int rc = spdk_nvme_zns_zone_append(
        ns,         // The ZNS namespace
        qpair,      // The I/O qpair
        dma_buf,    // Data buffer
        zone_slba,  // The starting LBA of the zone you want to append to
        num_blocks, // Number of blocks to write
        zone_append_completion, // Completion callback
        &g_completion_done,     // Argument to completion callback
        0                       // I/O flags
    );

    if (rc != 0) {
        std::cerr << "[ERROR] spdk_nvme_zns_zone_append() failed, rc=" << rc
                  << "\n";
        spdk_dma_free(dma_buf);
        spdk_nvme_ctrlr_free_io_qpair(qpair);
        spdk_nvme_detach(ctrlr);
        spdk_env_fini();
        return;
    }

    // --------------------------------------------------
    // 7. Poll for I/O completion
    // --------------------------------------------------
    while (!g_completion_done) {
        // Process completions
        spdk_nvme_qpair_process_completions(qpair, 0);
    }

    // --------------------------------------------------
    // 8. Clean up
    // --------------------------------------------------
    spdk_dma_free(dma_buf);
    spdk_nvme_ctrlr_free_io_qpair(qpair);
    spdk_nvme_detach(ctrlr);
    spdk_env_fini();

    std::cout << "[INFO] Buffer successfully appended to ZNS SSD.\n";
}

void testSerializationDeserialization(int datalen)
{
    // 1. Create and initialize a ZstoreObject
    ZstoreObject original_obj;
    original_obj.entry.type = LogEntryType::kData;
    original_obj.entry.seqnum = 42;
    original_obj.entry.chunk_seqnum = 24;
    original_obj.datalen = datalen; // Example data length
    original_obj.body = std::malloc(original_obj.datalen);
    std::memset(original_obj.body, 0xCD,
                original_obj.datalen); // Fill with example data (0xCD)
    std::strcpy(original_obj.key_hash, "test_key_hash");
    original_obj.key_size =
        static_cast<uint16_t>(std::strlen(original_obj.key_hash));

    // 2. Serialize to buffer
    auto buffer = WriteZstoreObjectToBuffer(original_obj);

    // Send buffer to SSD
    sendBufferToZnsSSD(buffer);

    // Read buffer from SSD

    // 3. Deserialize back to a new ZstoreObject
    ZstoreObject deserialized_obj;
    bool success = ReadBufferToZstoreObject(buffer.data(), buffer.size(),
                                            deserialized_obj);

    // 4. Check if deserialization succeeded
    assert(success && "Deserialization failed!");

    // 5. Compare original and deserialized objects
    assert(original_obj.entry.type == deserialized_obj.entry.type);
    assert(original_obj.entry.seqnum == deserialized_obj.entry.seqnum);
    assert(original_obj.entry.chunk_seqnum ==
           deserialized_obj.entry.chunk_seqnum);
    assert(original_obj.datalen == deserialized_obj.datalen);
    assert(original_obj.key_size == deserialized_obj.key_size);
    assert(std::strcmp(original_obj.key_hash, deserialized_obj.key_hash) == 0);

    // 6. Compare the body contents
    if (original_obj.datalen > 0 && original_obj.body &&
        deserialized_obj.body) {
        assert(std::memcmp(original_obj.body, deserialized_obj.body,
                           original_obj.datalen) == 0);
    }

    // Clean up dynamically allocated memory
    if (original_obj.body)
        std::free(original_obj.body);
    if (deserialized_obj.body)
        std::free(deserialized_obj.body);

    // If all assertions pass
    log_info("Test passed: Serialization and deserialization are correct!  "
             "Data length: {}",
             datalen);
}

int main()
{
    // Run the test
    testSerializationDeserialization(128);
    testSerializationDeserialization(1024);
    testSerializationDeserialization(4096);
    testSerializationDeserialization(4096 * 4);
    testSerializationDeserialization(4096 * 16);

    return 0;
}
