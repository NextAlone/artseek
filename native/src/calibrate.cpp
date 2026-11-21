#include "calibrate.hpp"
#include "dex.hpp"
#include "mem.hpp"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>

extern "C" {
extern const unsigned char _binary_sentinel_dex_start[];
extern const unsigned char _binary_sentinel_dex_end[];
}

namespace artseek {

bool hasEmbeddedSentinel() {
    auto s = reinterpret_cast<uintptr_t>(&_binary_sentinel_dex_start[0]);
    auto e = reinterpret_cast<uintptr_t>(&_binary_sentinel_dex_end[0]);
    return e > s;
}

size_t embeddedSentinelSize() {
    auto s = reinterpret_cast<uintptr_t>(&_binary_sentinel_dex_start[0]);
    auto e = reinterpret_cast<uintptr_t>(&_binary_sentinel_dex_end[0]);
    return (e > s) ? static_cast<size_t>(e - s) : 0;
}

Json SelfCheckReport::toJson(bool recalibrated, const ArtLayout& layout) const {
    Json arr = Json::array();
    for (const auto& c : checks) {
        Json item = Json::object();
        item.set("name", c.name);
        item.set("ok", c.ok);
        if (!c.detail.empty()) item.set("detail", c.detail);
        arr.push(std::move(item));
    }
    Json out = Json::object();
    out.set("passed", passed);
    out.set("recalibrated", recalibrated);
    out.set("checks", std::move(arr));
    out.set("layout", layout.toNumericMap());
    return out;
}

namespace {

struct ClsChain {
    uint64_t dc = 0;
    uint64_t df = 0;
    uint64_t begin = 0;
    int dcOff = -1;
    int dfOff = -1;
    bool ok = false;
};

struct MarkerSpec {
    std::string name;
    uint64_t val;
    bool wide;
};

class InferEngine {
public:
    explicit InferEngine(ProcMem& mem) : mem_(mem) {}

    bool infer(ArtLayout& out, std::string* err) {
        ArtLayout res; // defaults for secondary fields; all 18+ core fields overwritten below

        const std::string kNeedle = "ZZ_SENTINEL_ASCII";
        const std::string kSentDesc = "LSentinel;";
        const std::string kDottedName = "Sentinel";
        const std::vector<std::string> kDeclared = {"i1", "l1", "s1", "i2", "next"};
        const std::vector<MarkerSpec> kMarkers = {
            {"i1", 0x11111111ULL, false},
            {"l1", 0x2222222222222222ULL, true},
            {"i2", 0x33333333ULL, false},
        };
        const std::string kSubDesc = "LSentinel$Sub;";
        constexpr uint32_t kSubMarker = 0x55556666u;
        const std::string kAltDesc = "LSentinel$Tiny;";
        constexpr uint32_t kAltMarker = 0x0BADF00Du;
        constexpr int32_t kAccessMain = 0x1;
        constexpr int32_t kAccessAlt = 0x11;

        // 1) String layout + object header
        auto textPos = scanBytes(reinterpret_cast<const uint8_t*>(kNeedle.data()), kNeedle.size());
        if (textPos.empty()) {
            if (err) *err = "sentinel string ZZ_SENTINEL_ASCII not found in heap";
            return false;
        }
        uint64_t strObj = 0;
        for (uint64_t P : textPos) {
            if (P < 16) continue;
            if (mem_.u32(P - 8) == static_cast<uint32_t>(kNeedle.size() << 1)) {
                uint64_t cand = P - 16;
                if ((cand & 7) == 0 && classLike(untag(mem_.u32(cand))).ok) {
                    strObj = cand;
                    break;
                }
            }
        }
        if (strObj == 0) {
            if (err) *err = "could not validate sentinel mirror::String header";
            return false;
        }
        res.obj_header = 8;
        res.klass_off = 0;
        res.heap_ref_sz = 4;
        res.str_count = 8;
        res.str_hash = 12;
        res.str_data = 16;

        // 2) klass_ -> Class (3-step dex chain)
        uint64_t strClass = untag(mem_.u32(strObj));
        ClsChain strChain = classLike(strClass);
        if (!strChain.ok) {
            if (err) *err = "String klass_ failed 3-step dex chain";
            return false;
        }
        res.cls_dex_cache = static_cast<uint64_t>(strChain.dcOff);
        res.dc_dex_file = static_cast<uint64_t>(strChain.dfOff);

        // 3) Sentinel instance & class
        uint64_t sentInst = 0;
        uint64_t sentClass = 0;
        int32_t sentTypeIdx = -1;
        int typeIdxOff = -1;
        std::shared_ptr<DexFile> dexSent;

        for (uint64_t ref : scanRef(static_cast<uint32_t>(strObj))) {
            for (uint64_t cand = ref & ~7ULL; ref - cand < 0x100 && cand >= 0x2000; cand -= 8) {
                uint64_t k = untag(mem_.u32(cand));
                if (k < 0x2000 || (k & 7) != 0 || k > 0xFFFFFFFFULL) {
                    if (cand < 8) break;
                    continue;
                }
                if (!classLike(k).ok) {
                    if (cand < 8) break;
                    continue;
                }
                int32_t ti = -1;
                int toff = -1;
                std::shared_ptr<DexFile> dd;
                if (classDescriptor(k, kSentDesc, ti, toff, dd)) {
                    sentInst = cand;
                    sentClass = k;
                    sentTypeIdx = ti;
                    typeIdxOff = toff;
                    dexSent = std::move(dd);
                    break;
                }
                if (cand < 8) break;
            }
            if (sentInst != 0) break;
        }
        if (sentInst == 0 || !dexSent) {
            if (err) *err = "could not locate Sentinel instance / class";
            return false;
        }
        res.cls_dex_type_idx = static_cast<uint64_t>(typeIdxOff);

        // Subclass instance & class
        uint64_t subInst = findInstanceByMarker(kSubMarker, kSubDesc);
        if (subInst == 0) {
            if (err) *err = "could not locate Sentinel$Sub instance";
            return false;
        }
        uint64_t subClass = untag(mem_.u32(subInst));
        int32_t subTypeIdx = -1;
        int subTypeOff = -1;
        std::shared_ptr<DexFile> dexSub;
        if (!classDescriptor(subClass, kSubDesc, subTypeIdx, subTypeOff, dexSub) || !dexSub) {
            if (err) *err = "could not resolve Sentinel$Sub descriptor";
            return false;
        }

        // 4) ifields_ + ArtField layout
        // Older ART keeps instance and static fields in separate arrays (ifields_ / sfields_);
        // newer ART merges them into one fields_ array, so the array holding the declared
        // instance fields may also carry the static ones.
        const std::unordered_set<std::string> wantStatic = {"sMarker", "sKeep"};
        const size_t kInstCount = kDeclared.size();
        const size_t kMergedCount = kInstCount + wantStatic.size();
        size_t nd = 0;
        int ifieldsOff = -1, afStride = -1, afDecl = -1;
        for (int off = 24; off <= 104 && ifieldsOff < 0; off += 8) {
            uint64_t arr = untag(mem_.u64(sentClass + static_cast<uint64_t>(off)));
            if (arr < 0x1000 || !mem_.isMapped(arr)) continue;
            nd = mem_.u32(arr);
            if (nd != kInstCount && nd != kMergedCount) continue;
            for (int stride : {12, 16, 20, 24}) {
                for (int decl : {0, 4, 8, 12}) {
                    if (decl + 4 > stride) continue;
                    bool good = true;
                    for (size_t i = 0; i < nd; ++i) {
                        uint64_t p = arr + 4 + i * static_cast<uint64_t>(stride) + static_cast<uint64_t>(decl);
                        if (mem_.u32(p) != static_cast<uint32_t>(sentClass)) {
                            good = false;
                            break;
                        }
                    }
                    if (good) {
                        ifieldsOff = off;
                        afStride = stride;
                        afDecl = decl;
                        break;
                    }
                }
                if (ifieldsOff >= 0) break;
            }
        }
        if (ifieldsOff < 0) {
            if (err) *err = "failed to infer Class.ifields_ / ArtField stride";
            return false;
        }
        const bool mergedFields = (nd == kMergedCount);
        res.cls_ifields = static_cast<uint64_t>(ifieldsOff);
        res.af_stride = static_cast<uint64_t>(afStride);
        res.af_decl = static_cast<uint64_t>(afDecl);

        uint64_t arr = untag(mem_.u64(sentClass + res.cls_ifields));
        std::vector<uint64_t> recs(nd);
        for (size_t i = 0; i < nd; ++i) {
            recs[i] = arr + 4 + i * res.af_stride;
        }

        std::unordered_set<std::string> wantNames(kDeclared.begin(), kDeclared.end());
        if (mergedFields) wantNames.insert(wantStatic.begin(), wantStatic.end());
        int afDex = -1;
        for (int slot : {0, 4, 8, 12}) {
            if (slot == afDecl || slot + 4 > afStride) continue;
            std::unordered_set<std::string> seen;
            bool okAll = true;
            for (uint64_t rc : recs) {
                auto fn = dexSent->field(mem_.u32(rc + static_cast<uint64_t>(slot)));
                if (!wantNames.count(fn.name) || !seen.insert(fn.name).second) {
                    okAll = false;
                    break;
                }
            }
            if (okAll) {
                afDex = slot;
                break;
            }
        }
        if (afDex < 0) {
            if (err) *err = "failed to infer ArtField.field_dex_idx_";
            return false;
        }
        res.af_dex = static_cast<uint64_t>(afDex);

        auto instOff = [&](const MarkerSpec& mk) -> int {
            int step = mk.wide ? 8 : 4;
            for (int off = 0; off < 0x100; off += step) {
                if (mk.wide) {
                    if (mem_.u64(sentInst + static_cast<uint64_t>(off)) == mk.val) return off;
                } else {
                    if (mem_.u32(sentInst + static_cast<uint64_t>(off)) == static_cast<uint32_t>(mk.val)) return off;
                }
            }
            return -1;
        };

        std::unordered_map<std::string, MarkerSpec> byName;
        for (const auto& mk : kMarkers) byName[mk.name] = mk;

        int afOff = -1;
        for (int slot : {0, 4, 8, 12}) {
            if (slot == afDecl || slot == afDex || slot + 4 > afStride) continue;
            int score = 0, total = 0;
            for (uint64_t rc : recs) {
                auto fn = dexSent->field(mem_.u32(rc + res.af_dex));
                auto it = byName.find(fn.name);
                if (it == byName.end()) continue;
                ++total;
                int obs = instOff(it->second);
                if (obs >= 0 && static_cast<int>(mem_.u32(rc + static_cast<uint64_t>(slot))) == obs) {
                    ++score;
                }
            }
            if (total > 0 && score == total) {
                afOff = slot;
                break;
            }
        }
        if (afOff < 0) {
            if (err) *err = "failed to infer ArtField.offset_";
            return false;
        }
        res.af_off = static_cast<uint64_t>(afOff);

        // 4a) ArtField.access_flags_: the slot whose ACC_STATIC bit separates static from
        // instance fields. Only observable on the merged array; it is what lets readers split
        // that array back into instance and static fields, so it must resolve there.
        constexpr uint32_t kAccStatic = 0x0008;
        if (mergedFields) {
            int afAccess = -1;
            for (int slot : {0, 4, 8, 12}) {
                if (slot == afDecl || slot == afDex || slot == afOff || slot + 4 > afStride) continue;
                bool okAll = true;
                for (uint64_t rc : recs) {
                    auto fn = dexSent->field(mem_.u32(rc + res.af_dex));
                    bool isStatic = (mem_.u32(rc + static_cast<uint64_t>(slot)) & kAccStatic) != 0;
                    if (isStatic != (wantStatic.count(fn.name) != 0)) {
                        okAll = false;
                        break;
                    }
                }
                if (okAll) {
                    afAccess = slot;
                    break;
                }
            }
            if (afAccess < 0) {
                if (err) *err = "failed to infer ArtField.access_flags_ on merged Class.fields_";
                return false;
            }
            res.af_access = static_cast<uint64_t>(afAccess);
            res.cls_sfields = res.cls_ifields;
        }

        // 4b) Bonus: infer Class.sfields_ (static fields: sMarker, sKeep) when it is a separate array
        for (int off = 24; !mergedFields && off <= 104; off += 8) {
            if (off == ifieldsOff) continue;
            uint64_t sarr = untag(mem_.u64(sentClass + static_cast<uint64_t>(off)));
            if (sarr < 0x1000 || !mem_.isMapped(sarr)) continue;
            if (mem_.u32(sarr) != 2) continue;
            bool okS = true;
            std::unordered_set<std::string> seenS;
            for (size_t i = 0; i < 2; ++i) {
                uint64_t rc = sarr + 4 + i * res.af_stride;
                if (mem_.u32(rc + res.af_decl) != static_cast<uint32_t>(sentClass)) {
                    okS = false;
                    break;
                }
                auto fn = dexSent->field(mem_.u32(rc + res.af_dex));
                if (!wantStatic.count(fn.name) || !seenS.insert(fn.name).second) {
                    okS = false;
                    break;
                }
            }
            if (okS) {
                res.cls_sfields = static_cast<uint64_t>(off);
                break;
            }
        }

        // 5) super_class_ (Sub -> Sentinel -> Object -> 0)
        int superOff = -1;
        for (int off = 24; off < 112; off += 4) {
            if (mem_.u32(subClass + static_cast<uint64_t>(off)) != static_cast<uint32_t>(sentClass)) {
                continue;
            }
            uint64_t objc = untag(mem_.u32(sentClass + static_cast<uint64_t>(off)));
            if (objc < 0x2000) continue;
            if (mem_.u32(objc + static_cast<uint64_t>(off)) == 0) {
                superOff = off;
                break;
            }
        }
        if (superOff < 0) {
            if (err) *err = "failed to infer Class.super_class_";
            return false;
        }
        res.cls_super = static_cast<uint64_t>(superOff);

        // 6) access_flags_ (Sentinel public 0x1 vs Tiny public final 0x11)
        uint64_t altInst = findInstanceByMarker(kAltMarker, kAltDesc);
        if (altInst == 0) {
            if (err) *err = "could not locate Sentinel$Tiny instance";
            return false;
        }
        uint64_t altClass = untag(mem_.u32(altInst));
        int accessOff = -1;
        for (int off = 24; off < 112; off += 4) {
            if (off == superOff || off == typeIdxOff) continue;
            if (mem_.i32(sentClass + static_cast<uint64_t>(off)) == kAccessMain &&
                mem_.i32(altClass + static_cast<uint64_t>(off)) == kAccessAlt) {
                accessOff = off;
                break;
            }
        }
        if (accessOff >= 0) {
            res.cls_access = static_cast<uint64_t>(accessOff);
        }

        // 7) name_ (Sentinel.class.getName() was invoked in Sentinel.main)
        int nameOff = -1;
        for (int off = 24; off < 96; off += 4) {
            uint64_t p = untag(mem_.u32(sentClass + static_cast<uint64_t>(off)));
            if (p < 0x1000 || (p & 7) != 0) continue;
            if (auto s = decodeAsciiStr(p, res.str_count, res.str_data)) {
                if (*s == kDottedName || *s == kSentDesc) {
                    nameOff = off;
                    break;
                }
            }
        }
        if (nameOff >= 0) {
            res.cls_name = static_cast<uint64_t>(nameOff);
        }

        // 8) object_size_ (mode of consecutive spacing between Sentinel instances)
        std::vector<uint64_t> addrs;
        for (uint64_t ref : scanRef(static_cast<uint32_t>(kMarkers[0].val))) {
            for (uint64_t cand = ref & ~7ULL; ref - cand < 0x100 && cand >= 0x2000; cand -= 8) {
                if (mem_.u32(cand) == static_cast<uint32_t>(sentClass)) {
                    addrs.push_back(cand);
                }
                if (cand < 8) break;
            }
        }
        std::sort(addrs.begin(), addrs.end());
        addrs.erase(std::unique(addrs.begin(), addrs.end()), addrs.end());
        std::unordered_map<uint32_t, int> hist;
        for (size_t i = 1; i < addrs.size(); ++i) {
            uint64_t d2 = addrs[i] - addrs[i - 1];
            if (d2 > 0 && d2 < 0x1000) {
                hist[static_cast<uint32_t>(d2)]++;
            }
        }
        uint32_t bestSz = 0;
        int bestN = 0;
        for (const auto& [sz, cnt] : hist) {
            if (cnt > bestN) {
                bestSz = sz;
                bestN = cnt;
            }
        }
        res.inst_size = bestSz;
        int objSizeOff = -1;
        if (bestSz != 0) {
            for (int off = 64; off < 112; off += 4) {
                if (mem_.u32(sentClass + static_cast<uint64_t>(off)) == bestSz) {
                    objSizeOff = off;
                    break;
                }
            }
            if (objSizeOff >= 0) {
                res.cls_obj_size = static_cast<uint64_t>(objSizeOff);
            }
        }

        // 9) dex_class_def_idx_ (joint constraint on Sentinel & Sentinel$Sub)
        int classDefOff = -1;
        for (int off = 64; off < 112; off += 4) {
            if (off == typeIdxOff || off == objSizeOff || off == accessOff) continue;
            uint32_t v1 = mem_.u32(sentClass + static_cast<uint64_t>(off));
            uint32_t v2 = mem_.u32(subClass + static_cast<uint64_t>(off));
            if (v1 == v2 || v1 >= dexSent->classDefsSize() || v2 >= dexSub->classDefsSize()) {
                continue;
            }
            if (dexSent->u32(dexSent->classDefsOff() + v1 * 32) == static_cast<uint32_t>(sentTypeIdx) &&
                dexSub->u32(dexSub->classDefsOff() + v2 * 32) == static_cast<uint32_t>(subTypeIdx)) {
                classDefOff = off;
                break;
            }
        }
        if (classDefOff >= 0) {
            res.cls_dex_class_def = static_cast<uint64_t>(classDefOff);
        }

        // 10) Offsets with no sentinel marker follow their calibrated neighbours. The 32-bit
        // tail of mirror::Class keeps its field order across ART versions
        // (access_flags_, class_flags_, class_size_, ..., dex_type_idx_, num_reference_instance_fields_,
        //  ..., object_size_, object_size_alloc_fast_path_, primitive_type_, <ref offsets>, status_)
        // but slides as a block when pointer members before it are added or removed
        // (e.g. sfields_ merged into fields_), so fixed defaults go stale.
        if (accessOff >= 0) {
            res.cls_class_flags = static_cast<uint64_t>(accessOff) + 4;
            res.cls_class_size = static_cast<uint64_t>(accessOff) + 8;
        }
        res.cls_num_ref_inst = static_cast<uint64_t>(typeIdxOff) + 4;
        if (objSizeOff >= 0) {
            res.cls_obj_size_fast = static_cast<uint64_t>(objSizeOff) + 4;
            res.cls_prim_type = static_cast<uint64_t>(objSizeOff) + 8;
            res.cls_status = static_cast<uint64_t>(objSizeOff) + 16;
        }

        res.fingerprint = readBuildFingerprint();
        res.source = "calibrated";
        out = std::move(res);
        return true;
    }

private:
    bool isDexMagic(uint64_t addr) {
        if (addr < 0x1000 || !mem_.isMapped(addr)) return false;
        uint8_t m[4] = {0};
        mem_.readBytes(addr, m, 4);
        return std::memcmp(m, "dex\n", 4) == 0 || std::memcmp(m, "cdex", 4) == 0;
    }

    ClsChain classLike(uint64_t addr) {
        if (addr < 0x1000 || (addr & 7) != 0) return {};
        auto it = clsMemo_.find(addr);
        if (it != clsMemo_.end()) return it->second;

        ClsChain res;
        if (!mem_.isMapped(addr)) {
            clsMemo_[addr] = res;
            return res;
        }
        for (int off = 0; off < 0x60; off += 4) {
            uint64_t y = untag(mem_.u32(addr + static_cast<uint64_t>(off)));
            if (y < 0x1000 || !mem_.isMapped(y)) continue;
            for (int off2 = 0; off2 < 0x80; off2 += 4) {
                uint64_t z = untag(mem_.u64(y + static_cast<uint64_t>(off2)));
                if (z < 0x1000 || !mem_.isMapped(z)) continue;
                if (isDexMagic(z)) {
                    res = ClsChain{y, z, z, off, off2, true};
                    clsMemo_[addr] = res;
                    return res;
                }
                for (int off3 = 0; off3 < 0x20; off3 += 4) {
                    uint64_t w = untag(mem_.u64(z + static_cast<uint64_t>(off3)));
                    if (isDexMagic(w)) {
                        res = ClsChain{y, z, w, off, off2, true};
                        clsMemo_[addr] = res;
                        return res;
                    }
                }
            }
        }
        clsMemo_[addr] = res;
        return res;
    }

    bool classDescriptor(uint64_t classAddr, const std::string& want,
                         int32_t& outTypeIdx, int& outTypeOff,
                         std::shared_ptr<DexFile>& outDex) {
        ClsChain ch = classLike(classAddr);
        if (!ch.ok) return false;
        auto it = dexCache_.find(ch.begin);
        std::shared_ptr<DexFile> dd;
        if (it != dexCache_.end()) {
            dd = it->second;
        } else {
            dd = DexFile::load(mem_, ch.begin);
            dexCache_[ch.begin] = dd;
        }
        if (!dd) return false;
        for (int off = 64; off < 112; off += 4) {
            int32_t v = mem_.i32(classAddr + static_cast<uint64_t>(off));
            if (v < 0 || static_cast<uint32_t>(v) >= dd->typeIdsSize()) continue;
            if (dd->typeDesc(static_cast<uint32_t>(v)) == want) {
                outTypeIdx = v;
                outTypeOff = off;
                outDex = dd;
                return true;
            }
        }
        return false;
    }

    uint64_t findInstanceByMarker(uint32_t marker, const std::string& wantDesc) {
        for (uint64_t ref : scanRef(marker)) {
            for (uint64_t cand = ref & ~7ULL; ref - cand < 0x100 && cand >= 0x2000; cand -= 8) {
                uint64_t k = untag(mem_.u32(cand));
                if (k < 0x2000 || (k & 7) != 0 || k > 0xFFFFFFFFULL) {
                    if (cand < 8) break;
                    continue;
                }
                if (!classLike(k).ok) {
                    if (cand < 8) break;
                    continue;
                }
                int32_t ti = -1;
                int toff = -1;
                std::shared_ptr<DexFile> dd;
                if (classDescriptor(k, wantDesc, ti, toff, dd)) {
                    return cand;
                }
                if (cand < 8) break;
            }
        }
        return 0;
    }

    std::vector<uint64_t> scanBytes(const uint8_t* needle, size_t nlen) {
        std::vector<uint64_t> out;
        mem_.eachHeapChunk([&](uint64_t base, const uint8_t* buf, size_t len) -> bool {
            size_t idx = 0;
            while (idx + nlen <= len) {
                const void* p = ::memmem(buf + idx, len - idx, needle, nlen);
                if (!p) break;
                size_t j = static_cast<size_t>(static_cast<const uint8_t*>(p) - buf);
                out.push_back(base + j);
                idx = j + 1;
            }
            return true;
        });
        return out;
    }

    std::vector<uint64_t> scanRef(uint32_t target) {
        std::vector<uint64_t> out;
        mem_.eachHeapChunk([&](uint64_t base, const uint8_t* buf, size_t len) -> bool {
            for (size_t off = 0; off + 4 <= len; off += 4) {
                uint32_t v;
                std::memcpy(&v, buf + off, 4);
                if (v == target) out.push_back(base + off);
            }
            return true;
        });
        return out;
    }

    std::optional<std::string> decodeAsciiStr(uint64_t addr, uint64_t countOff, uint64_t dataOff) {
        if (!mem_.isMapped(addr)) return std::nullopt;
        uint32_t cnt = mem_.u32(addr + countOff);
        if ((cnt & 1u) != 0) return std::nullopt;
        uint32_t len = cnt >> 1;
        if (len == 0 || len > 512) return std::nullopt;
        std::string s(len, '\0');
        mem_.readBytes(addr + dataOff, s.data(), len);
        for (unsigned char c : s) {
            if (c < 0x20 || c >= 0x7F) return std::nullopt;
        }
        return s;
    }

    ProcMem& mem_;
    std::unordered_map<uint64_t, ClsChain> clsMemo_;
    std::unordered_map<uint64_t, std::shared_ptr<DexFile>> dexCache_;
};

} // namespace

bool calibrateWithEmbeddedSentinel(const std::string& cacheDir,
                                   ArtLayout& outLayout,
                                   std::string* err) {
    if (!hasEmbeddedSentinel()) {
        if (err) *err = "embedded sentinel.dex is empty";
        return false;
    }
    if (!ensureCacheDir(cacheDir, err)) {
        return false;
    }

    std::string dexPath = cacheDir + "/sentinel.dex";
    std::string layoutPath = cacheDir + "/layout.json";

    // Write embedded sentinel.dex with mode 0600 (root-only)
    int fd = ::open(dexPath.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) {
        if (err) *err = std::string("open ") + dexPath + ": " + std::strerror(errno);
        return false;
    }
    ::fchmod(fd, 0600);
    const unsigned char* data = _binary_sentinel_dex_start;
    size_t total = embeddedSentinelSize();
    size_t written = 0;
    while (written < total) {
        ssize_t w = ::write(fd, data + written, total - written);
        if (w < 0) {
            if (errno == EINTR) continue;
            if (err) *err = std::string("write sentinel.dex: ") + std::strerror(errno);
            ::close(fd);
            ::unlink(dexPath.c_str());
            return false;
        }
        written += static_cast<size_t>(w);
    }
    ::fsync(fd);
    ::close(fd);

    int pipeFds[2] = {-1, -1};
    if (::pipe(pipeFds) != 0) {
        if (err) *err = std::string("pipe: ") + std::strerror(errno);
        ::unlink(dexPath.c_str());
        return false;
    }

    pid_t child = ::fork();
    if (child < 0) {
        if (err) *err = std::string("fork: ") + std::strerror(errno);
        ::close(pipeFds[0]);
        ::close(pipeFds[1]);
        ::unlink(dexPath.c_str());
        return false;
    }

    if (child == 0) {
        // Child process: launch app_process64 Sentinel
        ::close(pipeFds[0]);
        ::dup2(pipeFds[1], STDOUT_FILENO);
        ::close(pipeFds[1]);

        int devNull = ::open("/dev/null", O_RDWR);
        if (devNull >= 0) {
            ::dup2(devNull, STDIN_FILENO);
            ::dup2(devNull, STDERR_FILENO);
            if (devNull > 2) ::close(devNull);
        }

        ::setenv("CLASSPATH", dexPath.c_str(), 1);

        const char* appProc = "/system/bin/app_process64";
        if (::access(appProc, X_OK) != 0) {
            appProc = "/system/bin/app_process";
        }
        char* const argv[] = {
            const_cast<char*>(appProc),
            const_cast<char*>("/system/bin"),
            const_cast<char*>("--nice-name=artseek_sentinel"),
            const_cast<char*>("Sentinel"),
            nullptr
        };
        ::execv(appProc, argv);
        ::_exit(127);
    }

    // Parent process
    ::close(pipeFds[1]);

    // RAII cleanup: ALWAYS kill sentinel child and unlink sentinel.dex!
    struct Cleanup {
        pid_t& pid;
        int& rfd;
        const std::string& path;
        ~Cleanup() {
            if (rfd >= 0) ::close(rfd);
            if (pid > 0) {
                ::kill(pid, SIGKILL);
                int status = 0;
                ::waitpid(pid, &status, 0);
            }
            ::unlink(path.c_str());
        }
    } cleanup{child, pipeFds[0], dexPath};

    // Wait for Sentinel to print "ready " (up to 10 seconds)
    std::string outBuf;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    bool ready = false;
    while (std::chrono::steady_clock::now() < deadline) {
        auto remMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                         deadline - std::chrono::steady_clock::now())
                         .count();
        if (remMs <= 0) break;
        struct pollfd pfd{pipeFds[0], POLLIN, 0};
        int pr = ::poll(&pfd, 1, static_cast<int>(std::min<int64_t>(remMs, 500)));
        if (pr > 0) {
            char tmp[512];
            ssize_t n = ::read(pipeFds[0], tmp, sizeof(tmp));
            if (n > 0) {
                outBuf.append(tmp, static_cast<size_t>(n));
                if (outBuf.find("ready ") != std::string::npos) {
                    ready = true;
                    break;
                }
            } else if (n == 0) {
                break; // child closed stdout / exited prematurely
            }
        }
        int status = 0;
        if (::waitpid(child, &status, WNOHANG) == child) {
            child = -1;
            break;
        }
    }

    if (!ready) {
        if (err) {
            *err = "sentinel process did not become ready (output='" + outBuf + "')";
        }
        return false;
    }

    // Attach to sentinel process and infer all ART layout offsets
    ProcMem mem;
    if (!mem.open(child, err)) {
        return false;
    }
    InferEngine engine(mem);
    ArtLayout inferred;
    if (!engine.infer(inferred, err)) {
        return false;
    }
    mem.close();

    // Save calibrated layout.json (0600)
    if (!saveLayoutFile(layoutPath, inferred, err)) {
        return false;
    }
    inferred.source = "calibrated(" + layoutPath + ")";
    outLayout = std::move(inferred);
    return true;
}

SelfCheckReport runSelfCheck(ArtRuntime& rt, int pid) {
    SelfCheckReport rep;
    rep.passed = true;

    auto add = [&](std::string name, bool ok, std::string detail) {
        rep.checks.push_back(CheckItem{std::move(name), ok, std::move(detail)});
        if (!ok) rep.passed = false;
    };

    // 1) 64-bit ELF check
    std::string bitDetail;
    bool is64 = isProcess64Bit(pid, &bitDetail);
    add("pointer_size_64bit", is64, bitDetail);

    // 2) String encoding check ("java.lang.String")
    const std::string kNeedle = "java.lang.String";
    bool strOk = false;
    std::string strDetail = "java.lang.String not found in heap";
    rt.mem().eachHeapChunk([&](uint64_t base, const uint8_t* buf, size_t len) -> bool {
        if (strOk) return false;
        const void* p = ::memmem(buf, len, kNeedle.data(), kNeedle.size());
        if (!p) return true;
        size_t off = static_cast<size_t>(static_cast<const uint8_t*>(p) - buf);
        uint64_t dataAddr = base + off;
        if (dataAddr < rt.layout().str_data) return true;
        uint64_t cand = dataAddr - rt.layout().str_data;
        if ((cand & 7) != 0 || cand < 0x1000) return true;
        uint32_t cnt = rt.mem().u32(cand + rt.layout().str_count);
        if ((cnt >> 1) == kNeedle.size() && (cnt & 1u) == 0) {
            if (auto s = rt.decodeString(cand, true); s && *s == kNeedle) {
                strOk = true;
                strDetail = hexAddr(cand) + " compressed Latin-1 count_=(len<<1)";
                return false;
            }
        }
        return true;
    });
    add("mirror_string_encoding", strOk, strDetail);

    // 3) java.lang.Class self-referential anchor
    uint64_t anc = rt.anchor();
    if (anc == 0) {
        add("class_anchor", false, "self-referential java.lang.Class not found");
        return rep;
    }
    auto ancDesc = rt.descriptor(anc);
    bool ancOk = ancDesc && *ancDesc == "Ljava/lang/Class;";
    add("class_anchor", ancOk, hexAddr(anc) + (ancDesc ? (" " + *ancDesc) : " (unresolved)"));
    if (!ancOk) return rep;

    // 4) DexCache -> DexFile -> dex resolution for Ljava/lang/String;
    uint64_t sc = rt.stringClass();
    if (sc == 0) {
        add("dex_resolution", false, "failed to resolve Ljava/lang/String;");
        return rep;
    }
    uint64_t dc = rt.mem().u32(sc + rt.layout().cls_dex_cache);
    std::string loc = rt.dexLocation(dc);
    add("dex_resolution", true, hexAddr(sc) + " via " + loc);

    // 5) mirror::Class offsets + superclass chain (String -> Object -> 0)
    uint32_t cs = rt.mem().u32(sc + rt.layout().cls_class_size);
    int32_t tidx = rt.mem().i32(sc + rt.layout().cls_dex_type_idx);
    uint64_t sup = rt.mem().u32(sc + rt.layout().cls_super);
    auto supDesc = rt.descriptor(sup);
    bool clsOk = (cs >= 0x30 && cs < (1u << 20) && tidx >= 0 &&
                  supDesc && *supDesc == "Ljava/lang/Object;" &&
                  rt.mem().u32(sup + rt.layout().cls_super) == 0);
    add("mirror_class_layout", clsOk,
        "class_size=" + std::to_string(cs) + " type_idx=" + std::to_string(tidx) +
            " super=" + (supDesc ? *supDesc : "null"));

    // 6) ArtField layout + String.count offset cross-check
    uint64_t ifArr = untag(rt.mem().u64(sc + rt.layout().cls_ifields));
    bool afOk = false;
    std::string afDetail = "ifields_ invalid";
    if (ifArr >= 0x1000 && rt.mem().isMapped(ifArr)) {
        uint32_t n = rt.mem().u32(ifArr);
        if (n > 0 && n < 1000) {
            uint32_t decl = rt.mem().u32(ifArr + 4 + rt.layout().af_decl);
            const auto& fl = rt.fieldLayout(sc);
            auto cit = fl.byName.find("count");
            bool countMatches = (cit != fl.byName.end() && cit->second.type == "I" &&
                                 cit->second.offset == rt.layout().str_count);
            afOk = (decl == static_cast<uint32_t>(sc)) && countMatches;
            afDetail = "n=" + std::to_string(n) + " decl=" + hexAddr(decl) +
                       " String.count=" + (cit != fl.byName.end() ? std::to_string(cit->second.offset) : "missing");
        }
    }
    add("artfield_layout", afOk, afDetail);

    // 7) Compressed reference sanity on String.name_ (if initialized) or DexCache.location_
    uint32_t nameRef = rt.mem().u32(sc + rt.layout().cls_name);
    if (nameRef != 0) {
        auto s = rt.decodeString(nameRef, true);
        bool okName = s && (*s == "java.lang.String" || *s == "Ljava/lang/String;");
        add("compressed_ref", okName,
            "name_=" + hexAddr(nameRef) + " -> " + (s ? *s : "<decode fail>"));
    } else {
        bool locOk = !loc.empty();
        add("compressed_ref", locOk, "name_==0 (lazy); dexLocation=" + loc);
    }

    return rep;
}

} // namespace artseek
