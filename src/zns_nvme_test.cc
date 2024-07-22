#include "include/utils.hpp"
#include "include/zns_device.h"
#include "spdk/env.h"
#include "spdk/event.h"
#include "spdk/log.h"
#include "spdk/nvme.h"
#include "spdk/nvme_zns.h"
#include "spdk/nvmf_spec.h"
#include <atomic>

static void read_complete(void *arg, const struct spdk_nvme_cpl *completion)
{
    struct ZstoreContext *ctx = static_cast<struct ZstoreContext *>(arg);

    ctx->num_completed += 1;
    if (spdk_nvme_cpl_is_error(completion)) {
        SPDK_ERRLOG("nvme io read error: %s\n",
                    spdk_nvme_cpl_get_status_string(&completion->status));
        ctx->num_fail += 1;
        ctx->num_queued -= 1;

        spdk_nvme_ctrlr_free_io_qpair(ctx->qpair);
        spdk_app_stop(-1);
        return;
    }

    // compare read and write buffer
    int cmp_res = memcmp(ctx->write_buff, ctx->read_buff, ctx->buff_size);
    if (cmp_res != 0) {
        log_error("read and write buffer are not the same!");
        spdk_nvme_ctrlr_free_io_qpair(ctx->qpair);
        spdk_app_stop(-1);
        return;
    } else {
        log_info("read and write buffer are the same. load {}",
                 ctx->count.load());
    }

    ctx->count.fetch_add(1);
    ctx->num_success += 1;
    ctx->num_queued -= 1;

    if (ctx->count.load() == 4 * 0x100) {
        log_info("read zone complete. load {}\n", ctx->count.load());
        spdk_nvme_ctrlr_free_io_qpair(ctx->qpair);
        spdk_app_stop(0);
        return;
    }

    memset(ctx->read_buff, 0x34, ctx->buff_size);
    // uint64_t lba = ctx->count.load();
    uint64_t lba = ctx->count.load() / 0x100 *
                       spdk_nvme_zns_ns_get_zone_size_sectors(ctx->ns) +
                   ctx->count.load() % 0x100;

    int rc = spdk_nvme_ns_cmd_read(ctx->ns, ctx->qpair, ctx->read_buff, lba, 1,
                                   read_complete, ctx, 0);
    SPDK_NOTICELOG("read lba:0x%lx\n", lba);
    if (rc != 0) {
        SPDK_ERRLOG("%s error while reading from nvme: %d\n",
                    spdk_strerror(-rc), rc);
        spdk_nvme_ctrlr_free_io_qpair(ctx->qpair);
        spdk_app_stop(-1);
        return;
    }
}

static void read_zone(void *arg)
{
    struct ZstoreContext *ctx = static_cast<struct ZstoreContext *>(arg);

    uint64_t zone_size = spdk_nvme_zns_ns_get_zone_size_sectors(ctx->ns);
    int append_times = 0x100;
    int zone_num = 4;

    ctx->count = 0;
    ctx->num_queued += 1;

    for (uint64_t slba = 0; slba < zone_num * zone_size; slba += zone_size) {
        for (int i = 0; i < append_times; i++) {
            ctx->num_queued++;

            memset(ctx->read_buff, 0x34, ctx->buff_size);
            int rc = spdk_nvme_ns_cmd_read(ctx->ns, ctx->qpair, ctx->read_buff,
                                           slba, 1, read_complete, ctx, 0);
            SPDK_NOTICELOG("read lba:0x%x to read buffer\n", slba);
            if (rc) {
                log_error("{} error while reading from bdev: {} \n",
                          spdk_strerror(-rc), rc);
                spdk_nvme_ctrlr_free_io_qpair(ctx->qpair);
                spdk_app_stop(-1);
                return;
            }
        }
    }
    while (ctx->num_queued) {
        spdk_nvme_qpair_process_completions(ctx->qpair, 0);
    }
}

static void write_zone_complete(void *arg,
                                const struct spdk_nvme_cpl *completion)
{
    struct ZstoreContext *ctx = static_cast<struct ZstoreContext *>(arg);
    ctx->num_completed += 1;

    if (spdk_nvme_cpl_is_error(completion)) {
        log_error("nvme io write error: {}\n",
                  spdk_nvme_cpl_get_status_string(&completion->status));
        ctx->num_fail += 1;
        ctx->num_queued -= 1;

        spdk_nvme_ctrlr_free_io_qpair(ctx->qpair);
        spdk_app_stop(-1);
        return;
    }

    SPDK_NOTICELOG("append lba:0x%lx\n", completion->cdw0);

    ctx->count.fetch_sub(1);
    ctx->num_success += 1;
    ctx->num_queued -= 1;

    if (ctx->count.load() == 0) {
        log_info("write zone complete.\n");
        read_zone(ctx);
    }
}

static void write_zone(void *arg)
{
    struct ZstoreContext *ctx = static_cast<struct ZstoreContext *>(arg);
    uint64_t zone_size = spdk_nvme_zns_ns_get_zone_size_sectors(ctx->ns);
    int append_times = 0x100;
    int zone_num = 4;
    ctx->count = zone_num * append_times;

    char *valpt =
        (char *)ZnsDevice::z_calloc(*this->qpair_, 4096, sizeof(char));
    snprintf(valpt, 4096, "%s:%s", key.data(), val.data());

    memset(ctx->write_buff, 0x12, ctx->buff_size);
    for (uint64_t slba = 0; slba < zone_num * zone_size; slba += zone_size) {
        for (int i = 0; i < append_times; i++) {
            ctx->num_queued++;
            // FIXME:
            // 1. check error code
            // 2. set up buffer? step size?
            //
            //
            int rc =
                spdk_nvme_zns_zone_append(ctx->ns, ctx->qpair, ctx->write_buff,
                                          slba, 1, write_zone_complete, ctx, 0);
            if (rc != 0) {
                log_error("{} error while write_zone: {}\n", spdk_strerror(-rc),
                          rc);
                spdk_nvme_ctrlr_free_io_qpair(ctx->qpair);
                spdk_app_stop(-1);
                return;
            }
        }
    }

    while (ctx->num_queued) {
        spdk_nvme_qpair_process_completions(ctx->qpair, 0);
    }
}

static void reset_zone_complete(void *arg, const struct spdk_nvme_cpl *cpl)
{
    log_info("Entered reset zone complete");
    struct ZstoreContext *ctx = static_cast<struct ZstoreContext *>(arg);

    ctx->num_completed += 1;
    if (spdk_nvme_cpl_is_error(cpl)) {
        spdk_nvme_qpair_print_completion(ctx->qpair,
                                         (struct spdk_nvme_cpl *)cpl);
        fprintf(stderr, "Reset all zone error - status = %s\n",
                spdk_nvme_cpl_get_status_string(&cpl->status));
        ctx->num_fail += 1;
        ctx->num_queued -= 1;
        log_debug(
            "reset zone complete: queued {} completed {} success {} fail {}",
            ctx->num_queued, ctx->num_completed, ctx->num_success,
            ctx->num_fail);
        SPDK_ERRLOG("nvme io reset error: %s\n",
                    spdk_nvme_cpl_get_status_string(&cpl->status));
        spdk_nvme_ctrlr_free_io_qpair(ctx->qpair);
        spdk_app_stop(-1);
        return;
    }
    ctx->num_success += 1;
    ctx->num_queued -= 1;

    log_debug("reset zone complete: queued {} completed {} success {} fail {}, "
              "load {}",
              ctx->num_queued, ctx->num_completed, ctx->num_success,
              ctx->num_fail, ctx->count.load());
    // when all reset is done, do writes
    ctx->count.fetch_sub(1);
    if (ctx->count.load() == 0) {
        log_info("reset zone complete. load {}\n", ctx->count.load());
        write_zone(ctx);
    }
}

static void reset_zone(void *arg)
{
    log_info("reset zone");
    struct ZstoreContext *ctx = static_cast<struct ZstoreContext *>(arg);
    int zone_num = 10;
    ctx->count = zone_num;
    uint64_t zone_size = spdk_nvme_zns_ns_get_zone_size_sectors(ctx->ns);
    log_debug("Reset zone: num {}, size {}, loop {}", zone_num, zone_size,
              zone_num * zone_size);
    ctx->num_queued++;

    // z_reset(ctx);

    // log_info("Reset whole zone ");
    // bool done = false;
    // auto resetComplete = [](void *arg, const struct spdk_nvme_cpl
    // *completion) {
    //     bool *done = (bool *)arg;
    //     *done = true;
    // };

    // spdk_nvme_zns_reset_zone(ctx->ns, ctx->qpair, 0, true,
    // reset_zone_complete,
    //                          ctx);

    // uint8_t *buffer = (uint8_t *)spdk_zmalloc(
    //     4096, 4096, NULL, SPDK_ENV_SOCKET_ID_ANY, SPDK_MALLOC_DMA);
    // spdk_nvme_ns_cmd_read(ctx->ns, ctx->qpair, buffer, 0, 1, resetComplete,
    //                       &done, 0);
    // spdk_nvme_ns_cmd_read(ctx->ns, ctx->qpair, ctx->read_buff, 0, 4096,
    //                       reset_zone_complete, ctx, 0);

    // while (!done) {
    //     spdk_nvme_qpair_process_completions(ctx->qpair, 0);
    // }

    int stupid = 0;
    for (uint64_t slba = 0; slba < zone_num * zone_size; slba += zone_size) {
        stupid += 1;
        // log_debug("Reset zone: slba {}", slba);
        int rc = spdk_nvme_zns_reset_zone(ctx->ns, ctx->qpair, slba, 0,
                                          reset_zone_complete, ctx);
        // int rc = spdk_nvme_ns_cmd_zone_management(
        //             ctx->ns, ctx->qpair,
        //             SPDK_NVME_ZONE_MANAGEMENT_SEND, SPDK_NVME_ZONE_RESET,
        // i,
        //          if (rc == -ENOMEM) {
        if (rc == -ENOMEM) {
            log_debug("Queueing io: {}, {}", rc, spdk_strerror(-rc));
        } else if (rc) {
            log_error("{} error while resetting zone: {}\n", spdk_strerror(-rc),
                      rc);
            spdk_nvme_ctrlr_free_io_qpair(ctx->qpair);
            spdk_app_stop(-1);
            return;
        }

        log_debug("Reset zone: slba {}: load {}", slba, ctx->count.load());
    }
    while (ctx->num_queued) {
        // log_debug("reached here: queued {}", ctx->num_queued);
        spdk_nvme_qpair_process_completions(ctx->qpair, 0);
    }
    log_info("reset_zone end, load {}, stupid {}", ctx->count.load(), stupid);
}

static void test_start(void *arg1)
{
    log_info("test start");
    struct ZstoreContext *ctx = static_cast<struct ZstoreContext *>(arg1);
    uint32_t buf_align;

    zns_dev_init(ctx);

    zstore_init(ctx);

    // Setting up context done

    ctx->buff_size = spdk_nvme_ns_get_sector_size(ctx->ns);
    // buf_align = spdk_nvme_ns_get_sector_size(ctx->ns);
    buf_align = 1;
    // ctx->buff_size = spdk_nvme_ns_get_sector_size(ctx->ns) *
    //                  spdk_nvme_ns_get_md_size(ctx->ns);
    // buf_align = spdk_nvme_ns_get_optimal_io_boundary(ctx->ns);

    // 4096
    log_info("buffer size: {}", ctx->buff_size);
    // 1
    log_info("buffer align: {}", buf_align);

    ctx->write_buff =
        static_cast<char *>(spdk_dma_zmalloc(ctx->buff_size, buf_align, NULL));
    // ctx->write_buff = static_cast<char *>(
    //     spdk_zmalloc(ctx->buff_size, buf_align, NULL,
    //     SPDK_ENV_SOCKET_ID_ANY,
    //                  SPDK_MALLOC_DMA));

    if (!ctx->write_buff) {
        SPDK_ERRLOG("Failed to allocate buffer\n");
        spdk_nvme_ctrlr_free_io_qpair(ctx->qpair);
        spdk_nvme_detach(ctx->ctrlr);
        spdk_app_stop(-1);
        return;
    }
    // ctx->read_buff = static_cast<char *>(
    //     spdk_zmalloc(ctx->buff_size, buf_align, NULL,
    //     SPDK_ENV_SOCKET_ID_ANY,
    //                  SPDK_MALLOC_DMA));
    ctx->read_buff =
        static_cast<char *>(spdk_dma_zmalloc(ctx->buff_size, buf_align, NULL));

    if (!ctx->read_buff) {
        SPDK_ERRLOG("Failed to allocate buffer\n");
        spdk_nvme_ctrlr_free_io_qpair(ctx->qpair);
        spdk_nvme_detach(ctx->ctrlr);
        spdk_app_stop(-1);
        return;
    }
    // block size:4096 write unit:1 zone size:80000 zone num:406 max append
    // size:503 max open zone:14 max active zone:14

    // SPDK_NOTICELOG("block size: %d, write unit: %d, zone size: %lx, zone num:
    // "
    //                "%lu, max append size: %d,  max open "
    //                "zone: %d,max active zone: %d\n ",
    //                spdk_nvme_ns_get_sector_size(ctx->ns),
    //                spdk_nvme_ns_get_md_size(ctx->ns),
    //                spdk_nvme_zns_ns_get_zone_size_sectors(ctx->ns), // zone
    //                size spdk_nvme_zns_ns_get_num_zones(ctx->ns),
    //                spdk_nvme_zns_ctrlr_get_max_zone_append_size(ctx->ctrlr) /
    //                    spdk_nvme_ns_get_sector_size(ctx->ns),
    //                spdk_nvme_zns_ns_get_max_open_zones(ctx->ns),
    //                spdk_nvme_zns_ns_get_max_active_zones(ctx->ns));
    log_info("block size: {}, write unit: {}, zone size: {}, zone num: "
             "{}, max append size: {},  max open "
             "zone: {}, max active zone: {}\n ",
             spdk_nvme_ns_get_sector_size(ctx->ns),
             spdk_nvme_ns_get_md_size(ctx->ns),
             spdk_nvme_zns_ns_get_zone_size_sectors(ctx->ns), // zone size
             spdk_nvme_zns_ns_get_num_zones(ctx->ns),
             spdk_nvme_zns_ctrlr_get_max_zone_append_size(ctx->ctrlr) /
                 spdk_nvme_ns_get_sector_size(ctx->ns),
             spdk_nvme_zns_ns_get_max_open_zones(ctx->ns),
             spdk_nvme_zns_ns_get_max_active_zones(ctx->ns));

    z_get_device_info(ctx);

    // working
    reset_zone(ctx);

    // write_zone(ctx);

    // read_zone(ctx);

    log_info("Test start finish");
    return;
}

int main(int argc, char **argv)
{
    struct spdk_app_opts opts = {};
    int rc = 0;
    struct ZstoreContext ctx = {};

    spdk_app_opts_init(&opts, sizeof(opts));
    opts.name = "test_nvme";

    if ((rc = spdk_app_parse_args(argc, argv, &opts, NULL, NULL, NULL, NULL)) !=
        SPDK_APP_PARSE_ARGS_SUCCESS) {
        exit(rc);
    }
    // ctx.bdev_name = const_cast<char *>(g_bdev_name);
    log_info("HERE");
    rc = spdk_app_start(&opts, test_start, &ctx);
    if (rc) {
        SPDK_ERRLOG("ERROR starting application\n");
    }

    spdk_dma_free(ctx.write_buff);
    spdk_dma_free(ctx.read_buff);

    spdk_app_fini();

    return rc;
}
