/*
 * mod_sip_pcap.cpp
 * FreeSWITCH module: capture SIP signaling packets to PCAP files.
 *
 * Scans sip_profiles/ for profiles with:
 *   <param name="capture_signaling_packets" value="true"/>
 *
 * Opens one libpcap capture thread per matching profile using that
 * profile's sip-ip and sip-port. Writes per-Call-ID PCAP files.
 *
 * No siptrace. No log hooks. No performance impact.
 *
 * Config : autoload_configs/sip_pcap.conf.xml
 * API    : sip_pcap status | list | flush
 */

#include <switch.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pthread.h>
#include <sys/time.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

SWITCH_MODULE_LOAD_FUNCTION(mod_sip_pcap_load);
SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_sip_pcap_shutdown);
SWITCH_MODULE_DEFINITION(mod_sip_pcap, mod_sip_pcap_load,
                         mod_sip_pcap_shutdown, nullptr);

/* ── PCAP file format ────────────────────────────────────────────────────── */
static const uint32_t PCAPFILE_MAGIC   = 0xa1b2c3d4u;
static const uint16_t PCAPFILE_VER_MAJ = 2u;
static const uint16_t PCAPFILE_VER_MIN = 4u;
static const uint32_t PCAPFILE_SNAPLEN = 65535u;

#pragma pack(push,1)
struct pcap_ghdr_t { uint32_t magic; uint16_t vmaj,vmin; int32_t tz;
                     uint32_t sig,snap,net; };
struct pcap_rhdr_t { uint32_t ts_sec,ts_usec,inc,orig; };
#pragma pack(pop)

/* ── Global config ───────────────────────────────────────────────────────── */
static struct {
    char output_dir[512];
    bool enabled;
    bool save_calls;
    bool save_registrations;
    bool save_options;
} g_cfg;

/* ── SIP profile descriptor ──────────────────────────────────────────────── */
struct SipProfile { std::string name, sip_ip; uint16_t sip_port; };

/* ── PCAP writer ─────────────────────────────────────────────────────────── */
class PcapWriter {
public:
    PcapWriter(const std::string &path, int dlt) : path_(path) {
        fp_ = fopen(path.c_str(), "wb");
        if (!fp_) throw std::runtime_error("open failed: " + path);
        pcap_ghdr_t h = {PCAPFILE_MAGIC, PCAPFILE_VER_MAJ, PCAPFILE_VER_MIN,
                         0, 0, PCAPFILE_SNAPLEN, (uint32_t)dlt};
        fwrite(&h, sizeof(h), 1, fp_);
    }
    ~PcapWriter() { if (fp_) fclose(fp_); }

    void write_frame(const struct pcap_pkthdr *hdr, const uint8_t *pkt) {
        std::lock_guard<std::mutex> lk(mu_);
        if (!fp_) return;
        pcap_rhdr_t r = {(uint32_t)hdr->ts.tv_sec, (uint32_t)hdr->ts.tv_usec,
                         hdr->caplen, hdr->len};
        fwrite(&r,   sizeof(r),    1, fp_);
        fwrite(pkt,  hdr->caplen,  1, fp_);
        fflush(fp_);
        ++count_;
    }
    const std::string &path()  const { return path_; }
    uint64_t           count() const { return count_; }
private:
    std::string path_;
    FILE       *fp_    = nullptr;
    std::mutex  mu_;
    uint64_t    count_ = 0;
};

/* ── Writer registry (Call-ID → PcapWriter) ─────────────────────────────── */
static std::mutex g_wmu;
static std::unordered_map<std::string, std::shared_ptr<PcapWriter>> g_writers;

static std::shared_ptr<PcapWriter> get_writer(const std::string &cid, int dlt) {
    std::lock_guard<std::mutex> lk(g_wmu);
    auto it = g_writers.find(cid);
    if (it != g_writers.end()) return it->second;

    /* sanitise Call-ID for use as filename */
    std::string safe = cid;
    for (char &c : safe)
        if (!isalnum((unsigned char)c) && c != '-' && c != '_') c = '_';

    char ts[32]; time_t now = time(nullptr); struct tm tm_ = {};
    gmtime_r(&now, &tm_);
    strftime(ts, sizeof(ts), "%Y%m%dT%H%M%SZ", &tm_);
    std::string path = std::string(g_cfg.output_dir) + "/" + safe + "_" + ts + ".pcap";

    try {
        auto w = std::make_shared<PcapWriter>(path, dlt);
        g_writers[cid] = w;
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO,
            "mod_sip_pcap: new capture [%s] -> %s\n", cid.c_str(), path.c_str());
        return w;
    } catch (const std::exception &e) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
            "mod_sip_pcap: %s\n", e.what());
        return nullptr;
    }
}

/* ── SIP message classifier ──────────────────────────────────────────────── */
static std::string sip_hdr(const char *msg, size_t len, const char *name_lc) {
    /* find "\n<name>:" case-insensitively */
    std::string body(msg, len), lo = body;
    std::transform(lo.begin(), lo.end(), lo.begin(),
                   [](unsigned char c){ return (char)std::tolower(c); });
    std::string needle = std::string("\n") + name_lc + ":";
    auto pos = lo.find(needle);
    if (pos == std::string::npos) return "";
    auto col = body.find(':', pos + 1);
    if (col == std::string::npos) return "";
    auto s = body.find_first_not_of(" \t", col + 1);
    if (s == std::string::npos) return "";
    auto e = body.find_first_of("\r\n", s);
    std::string v = body.substr(s, (e == std::string::npos) ? std::string::npos : e - s);
    while (!v.empty() && isspace((unsigned char)v.back())) v.pop_back();
    return v;
}

enum class SipKind { UNKNOWN, REGISTER, OPTIONS, CALL };

static SipKind classify(const char *msg, size_t len) {
    if (len < 8) return SipKind::UNKNOWN;
    if (!strncmp(msg, "REGISTER ", 9)) return SipKind::REGISTER;
    if (!strncmp(msg, "OPTIONS ",  8)) return SipKind::OPTIONS;
    if (!strncmp(msg, "SIP/2.0 ",  8)) {
        std::string cs = sip_hdr(msg, len, "cseq");
        if (cs.find("REGISTER") != std::string::npos) return SipKind::REGISTER;
        if (cs.find("OPTIONS")  != std::string::npos) return SipKind::OPTIONS;
        return SipKind::CALL;
    }
    return SipKind::CALL; /* INVITE BYE ACK CANCEL etc. */
}

static bool want(SipKind k) {
    switch (k) {
    case SipKind::REGISTER: return g_cfg.save_registrations;
    case SipKind::OPTIONS:  return g_cfg.save_options;
    case SipKind::CALL:     return g_cfg.save_calls;
    default:                return false;
    }
}

/* ── Capture context (one per SIP profile) ───────────────────────────────── */
struct Ctx {
    SipProfile        profile;
    pcap_t           *pcap    = nullptr;
    std::atomic<bool> running {false};
    pthread_t         tid     = 0;
};

static std::vector<Ctx *> g_ctxs;

/* ── libpcap callback ────────────────────────────────────────────────────── */
static void on_pkt(uint8_t *user, const struct pcap_pkthdr *hdr,
                   const uint8_t *pkt)
{
    Ctx *ctx = reinterpret_cast<Ctx *>(user);
    int  dlt = pcap_datalink(ctx->pcap);

    /* locate IPv4 header */
    const uint8_t *ip = nullptr;
    size_t rem = hdr->caplen;

    switch (dlt) {
    case DLT_EN10MB: {
        if (rem < 14) return;
        uint16_t et = ntohs(*(const uint16_t *)(pkt + 12));
        if (et == 0x8100 && rem >= 18) { et = ntohs(*(const uint16_t *)(pkt+16)); ip = pkt+18; rem -= 18; }
        else                           {                                            ip = pkt+14; rem -= 14; }
        if (et != 0x0800) return;
        break;
    }
    case DLT_RAW: case 101:
        ip = pkt; break;
    case DLT_LINUX_SLL:
        if (rem < 16) return;
        ip = pkt+16; rem -= 16; break;
    case DLT_LINUX_SLL2:
        if (rem < 20) return;
        ip = pkt+20; rem -= 20; break;
    default: return;
    }

    if (!ip || rem < 20) return;
    const struct ip *ih = (const struct ip *)ip;
    if (ih->ip_v != 4) return;
    size_t ihl = (size_t)ih->ip_hl * 4;
    if (ihl < 20 || rem < ihl + 8) return;
    if (ih->ip_p != IPPROTO_UDP) return;

    const struct udphdr *uh = (const struct udphdr *)(ip + ihl);
    uint16_t sp = ntohs(uh->source), dp = ntohs(uh->dest);
    if (sp != ctx->profile.sip_port && dp != ctx->profile.sip_port) return;

    /* optional: filter by bound IP */
    if (!ctx->profile.sip_ip.empty() &&
        ctx->profile.sip_ip != "0.0.0.0" &&
        ctx->profile.sip_ip != "auto")
    {
        in_addr bound = {};
        if (inet_pton(AF_INET, ctx->profile.sip_ip.c_str(), &bound) == 1)
            if (ih->ip_src.s_addr != bound.s_addr &&
                ih->ip_dst.s_addr != bound.s_addr) return;
    }

    size_t off = ihl + 8;
    if (rem <= off) return;
    const char *sip = (const char *)(ip + off);
    size_t      slen = rem - off;

    SipKind k = classify(sip, slen);
    if (!want(k)) return;

    std::string cid = sip_hdr(sip, slen, "call-id");
    if (cid.empty()) cid = sip_hdr(sip, slen, "i");
    if (cid.empty()) return;

    auto w = get_writer(cid, dlt);
    if (w) w->write_frame(hdr, pkt);
}

/* ── Capture thread (pure pthread) ──────────────────────────────────────── */
static void *capture_thread(void *arg)
{
    Ctx *ctx = static_cast<Ctx *>(arg);
    char errbuf[PCAP_ERRBUF_SIZE] = {};

    ctx->pcap = pcap_create("any", errbuf);
    if (!ctx->pcap) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
            "mod_sip_pcap: [%s] pcap_create: %s\n",
            ctx->profile.name.c_str(), errbuf);
        ctx->running = false;
        return nullptr;
    }

    pcap_set_snaplen(ctx->pcap, (int)PCAPFILE_SNAPLEN);
    pcap_set_promisc(ctx->pcap, 0);
    pcap_set_timeout(ctx->pcap, 200);       /* 200 ms — keeps loop responsive */
    pcap_set_immediate_mode(ctx->pcap, 1);

    int rc = pcap_activate(ctx->pcap);
    if (rc < 0) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
            "mod_sip_pcap: [%s] pcap_activate: %s\n",
            ctx->profile.name.c_str(), pcap_geterr(ctx->pcap));
        pcap_close(ctx->pcap); ctx->pcap = nullptr;
        ctx->running = false;
        return nullptr;
    }

    /* BPF: only UDP on this profile's SIP port */
    char bpf[64];
    snprintf(bpf, sizeof(bpf), "udp port %u", (unsigned)ctx->profile.sip_port);
    struct bpf_program fp = {};
    if (pcap_compile(ctx->pcap, &fp, bpf, 1, PCAP_NETMASK_UNKNOWN) == 0) {
        pcap_setfilter(ctx->pcap, &fp);
        pcap_freecode(&fp);
    }

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE,
        "mod_sip_pcap: [%s] capturing udp/%u ip=%s\n",
        ctx->profile.name.c_str(), ctx->profile.sip_port,
        ctx->profile.sip_ip.empty() ? "any" : ctx->profile.sip_ip.c_str());

    while (ctx->running) {
        int r = pcap_dispatch(ctx->pcap, -1, on_pkt, (uint8_t *)ctx);
        if (r == PCAP_ERROR) {
            if (ctx->running)
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
                    "mod_sip_pcap: [%s] pcap_dispatch: %s\n",
                    ctx->profile.name.c_str(), pcap_geterr(ctx->pcap));
            break;
        }
    }

    pcap_close(ctx->pcap);
    ctx->pcap = nullptr;
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE,
        "mod_sip_pcap: [%s] thread done\n", ctx->profile.name.c_str());
    return nullptr;
}

/* ── Parse one <profile> XML node ───────────────────────────────────────── */
static void parse_profile(switch_xml_t prof, const char *fname,
                           std::vector<SipProfile> &out)
{
    if (!prof) return;

    bool        capture  = false;
    std::string sip_ip;
    uint16_t    sip_port = 5060;

    const char *prof_name = switch_xml_attr(prof, "name");
    if (!prof_name || !*prof_name) prof_name = fname;

    /* params live under <settings> in standard FS profiles */
    switch_xml_t settings = switch_xml_child(prof, "settings");
    switch_xml_t parent   = settings ? settings : prof;

    for (switch_xml_t p = switch_xml_child(parent, "param"); p; p = p->next) {
        const char *n = switch_xml_attr(p, "name");
        const char *v = switch_xml_attr(p, "value");
        if (!n || !v || !*n || !*v) continue;

        if      (!strcasecmp(n, "capture_signaling_packets"))
            capture = switch_true(v);
        else if (!strcasecmp(n, "sip-ip"))
            sip_ip = v;
        else if (!strcasecmp(n, "sip-port"))
            sip_port = (uint16_t)atoi(v);
    }

    if (!capture) return;

    SipProfile sp;
    sp.name     = prof_name;
    sp.sip_ip   = sip_ip;
    sp.sip_port = sip_port ? sip_port : 5060;
    out.push_back(sp);

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO,
        "mod_sip_pcap: profile [%s] capture=true port=%u ip=%s\n",
        sp.name.c_str(), sp.sip_port,
        sp.sip_ip.empty() ? "any" : sp.sip_ip.c_str());
}

/* ── Scan sip_profiles/ directory ───────────────────────────────────────── */
static std::vector<SipProfile> scan_profiles(switch_memory_pool_t *pool)
{
    std::vector<SipProfile> out;

    char dir_path[1024];
    snprintf(dir_path, sizeof(dir_path), "%s/sip_profiles",
             SWITCH_GLOBAL_dirs.conf_dir);

    switch_dir_t *d = nullptr;
    if (switch_dir_open(&d, dir_path, pool) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING,
            "mod_sip_pcap: cannot open %s\n", dir_path);
        return out;
    }

    const char *entry;
    char        fbuf[512];
    while ((entry = switch_dir_next_file(d, fbuf, sizeof(fbuf)))) {
        size_t elen = strlen(entry);
        if (elen < 4 || strcasecmp(entry + elen - 4, ".xml") != 0) continue;

        char fpath[1536];
        snprintf(fpath, sizeof(fpath), "%s/%s", dir_path, entry);

        switch_xml_t root = switch_xml_parse_file(fpath);
        if (!root) continue;

        const char *rname = switch_xml_name(root);

        /* Three possible structures:
         *   <profile name="…">…</profile>
         *   <include><profile …/></include>
         *   anything else containing <profile> children */
        if (rname && !strcasecmp(rname, "profile")) {
            parse_profile(root, entry, out);
        } else {
            for (switch_xml_t p = switch_xml_child(root, "profile");
                 p; p = p->next)
                parse_profile(p, entry, out);
        }

        switch_xml_free(root);
    }
    switch_dir_close(d);
    return out;
}

/* ── API ─────────────────────────────────────────────────────────────────── */
SWITCH_STANDARD_API(sip_pcap_cmd)
{
    if (!cmd || !*cmd || !strcmp(cmd, "status")) {
        stream->write_function(stream,
            "mod_sip_pcap status:\n"
            "  output-dir         : %s\n"
            "  save-calls         : %s\n"
            "  save-registrations : %s\n"
            "  save-options       : %s\n"
            "  capture threads    : %zu\n",
            g_cfg.output_dir,
            g_cfg.save_calls         ? "yes" : "no",
            g_cfg.save_registrations ? "yes" : "no",
            g_cfg.save_options       ? "yes" : "no",
            g_ctxs.size());
        for (Ctx *c : g_ctxs)
            stream->write_function(stream,
                "    [%s] port=%u ip=%s running=%s\n",
                c->profile.name.c_str(), c->profile.sip_port,
                c->profile.sip_ip.empty() ? "any" : c->profile.sip_ip.c_str(),
                c->running.load() ? "yes" : "no");
        std::lock_guard<std::mutex> lk(g_wmu);
        stream->write_function(stream,
            "  active pcap files  : %zu\n", g_writers.size());

    } else if (!strcmp(cmd, "list")) {
        std::lock_guard<std::mutex> lk(g_wmu);
        if (g_writers.empty()) {
            stream->write_function(stream, "No active captures.\n");
        } else {
            for (auto &kv : g_writers)
                stream->write_function(stream,
                    "  [%s]\n    -> %s  (%llu pkts)\n",
                    kv.first.c_str(), kv.second->path().c_str(),
                    (unsigned long long)kv.second->count());
        }
    } else if (!strcmp(cmd, "flush")) {
        std::lock_guard<std::mutex> lk(g_wmu);
        size_t n = g_writers.size(); g_writers.clear();
        stream->write_function(stream, "Closed %zu writer(s).\n", n);
    } else {
        stream->write_function(stream,
            "Usage: sip_pcap <status|list|flush>\n");
    }
    return SWITCH_STATUS_SUCCESS;
}

/* ── Module load ─────────────────────────────────────────────────────────── */
SWITCH_MODULE_LOAD_FUNCTION(mod_sip_pcap_load)
{
    *module_interface =
        switch_loadable_module_create_module_interface(pool, modname);

    switch_api_interface_t *api = nullptr;
    SWITCH_ADD_API(api, "sip_pcap",
                   "SIP PCAP capture: status | list | flush",
                   sip_pcap_cmd, "<status|list|flush>");

    /* defaults */
    memset(&g_cfg, 0, sizeof(g_cfg));
    strncpy(g_cfg.output_dir, SWITCH_GLOBAL_dirs.log_dir,
            sizeof(g_cfg.output_dir) - 1);
    g_cfg.enabled            = true;
    g_cfg.save_calls         = true;
    g_cfg.save_registrations = true;
    g_cfg.save_options       = false;

    /* read sip_pcap.conf.xml */
    switch_xml_t cfg, xml, settings, p;
    if ((xml = switch_xml_open_cfg("sip_pcap.conf", &cfg, nullptr))) {
        if ((settings = switch_xml_child(cfg, "settings"))) {
            for (p = switch_xml_child(settings, "param"); p; p = p->next) {
                const char *n = switch_xml_attr(p, "name");
                const char *v = switch_xml_attr(p, "value");
                if (!n || !v || !*n || !*v) continue;
                if      (!strcasecmp(n, "output-dir"))
                    strncpy(g_cfg.output_dir, v, sizeof(g_cfg.output_dir)-1);
                else if (!strcasecmp(n, "enabled"))
                    g_cfg.enabled = switch_true(v);
                else if (!strcasecmp(n, "save-calls"))
                    g_cfg.save_calls = switch_true(v);
                else if (!strcasecmp(n, "save-registrations"))
                    g_cfg.save_registrations = switch_true(v);
                else if (!strcasecmp(n, "save-options"))
                    g_cfg.save_options = switch_true(v);
            }
        }
        switch_xml_free(xml);
    }

    switch_dir_make_recursive(g_cfg.output_dir, SWITCH_FPROT_OS_DEFAULT, pool);

    if (!g_cfg.enabled) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE,
            "mod_sip_pcap: disabled.\n");
        return SWITCH_STATUS_SUCCESS;
    }

    auto profiles = scan_profiles(pool);
    if (profiles.empty()) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE,
            "mod_sip_pcap: loaded — no profiles have "
            "capture_signaling_packets=true.\n");
        return SWITCH_STATUS_SUCCESS;
    }

    /* start one pthread per profile */
    for (auto &sp : profiles) {
        Ctx *ctx = new Ctx();
        ctx->profile = sp;
        ctx->running = true;

        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

        int err = pthread_create(&ctx->tid, &attr, capture_thread, ctx);
        pthread_attr_destroy(&attr);

        if (err != 0) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
                "mod_sip_pcap: pthread_create failed for [%s]: %s\n",
                sp.name.c_str(), strerror(err));
            ctx->running = false;
            delete ctx;
            continue;
        }
        g_ctxs.push_back(ctx);
    }

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE,
        "mod_sip_pcap loaded — %zu thread(s) started, output: %s\n"
        "  save-calls=%s  save-registrations=%s  save-options=%s\n",
        g_ctxs.size(), g_cfg.output_dir,
        g_cfg.save_calls         ? "yes" : "no",
        g_cfg.save_registrations ? "yes" : "no",
        g_cfg.save_options       ? "yes" : "no");

    return SWITCH_STATUS_SUCCESS;
}

/* ── Module shutdown ─────────────────────────────────────────────────────── */
SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_sip_pcap_shutdown)
{
    for (Ctx *c : g_ctxs) {
        c->running = false;
        if (c->pcap) pcap_breakloop(c->pcap);
    }
    for (Ctx *c : g_ctxs) {
        if (c->tid) pthread_join(c->tid, nullptr);
        delete c;
    }
    g_ctxs.clear();

    { std::lock_guard<std::mutex> lk(g_wmu); g_writers.clear(); }

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE,
        "mod_sip_pcap: unloaded.\n");
    return SWITCH_STATUS_SUCCESS;
}
