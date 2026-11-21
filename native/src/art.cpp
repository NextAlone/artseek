#include "art.hpp"

#include <algorithm>
#include <cstring>
#include <queue>

namespace artseek {

namespace {
constexpr uint32_t kAccStatic = 0x0008;
} // namespace

std::string descToDot(const std::string& desc) {
    if (desc.size() >= 2 && desc.front() == 'L' && desc.back() == ';') {
        std::string out = desc.substr(1, desc.size() - 2);
        std::replace(out.begin(), out.end(), '/', '.');
        return out;
    }
    return desc;
}

std::string dotToDesc(const std::string& dot) {
    if (dot.empty()) return {};
    if (dot[0] == 'L' || dot[0] == '[') return dot;
    if (dot == "int") return "I";
    if (dot == "long") return "J";
    if (dot == "boolean") return "Z";
    if (dot == "byte") return "B";
    if (dot == "char") return "C";
    if (dot == "short") return "S";
    if (dot == "float") return "F";
    if (dot == "double") return "D";
    if (dot == "void") return "V";
    std::string out = "L" + dot + ";";
    std::replace(out.begin(), out.end(), '.', '/');
    return out;
}

std::string shortClassName(const std::string& nameOrDesc) {
    std::string d = descToDot(nameOrDesc);
    auto pos = d.rfind('.');
    if (pos != std::string::npos) return d.substr(pos + 1);
    return d;
}

bool globMatch(std::string_view pat, std::string_view str) {
    size_t p = 0, s = 0;
    size_t starIdx = std::string_view::npos;
    size_t matchIdx = 0;
    while (s < str.size()) {
        if (p < pat.size() && (pat[p] == '?' || pat[p] == str[s])) {
            ++p;
            ++s;
        } else if (p < pat.size() && pat[p] == '*') {
            starIdx = p++;
            matchIdx = s;
        } else if (starIdx != std::string_view::npos) {
            p = starIdx + 1;
            s = ++matchIdx;
        } else {
            return false;
        }
    }
    while (p < pat.size() && pat[p] == '*') ++p;
    return p == pat.size();
}

bool typeMatchesPattern(const std::string& desc, const std::string& pattern) {
    if (pattern.empty()) return true;
    std::string dot = descToDot(desc);
    if (pattern.find('*') != std::string::npos || pattern.find('?') != std::string::npos) {
        return globMatch(pattern, dot) || globMatch(pattern, desc);
    }
    if (desc == pattern || dot == pattern) return true;
    if (dotToDesc(pattern) == desc) return true;
    return false;
}

std::vector<uint8_t> encodeUtf16LE(std::string_view utf8) {
    std::vector<uint8_t> out;
    out.reserve(utf8.size() * 2);
    auto pushU16 = [&](uint16_t u) {
        out.push_back(static_cast<uint8_t>(u & 0xFF));
        out.push_back(static_cast<uint8_t>((u >> 8) & 0xFF));
    };
    size_t i = 0;
    while (i < utf8.size()) {
        uint32_t cp = 0;
        unsigned char c = static_cast<unsigned char>(utf8[i]);
        if ((c & 0x80) == 0) {
            cp = c;
            ++i;
        } else if ((c & 0xE0) == 0xC0 && i + 1 < utf8.size()) {
            cp = ((c & 0x1F) << 6) | (static_cast<unsigned char>(utf8[i + 1]) & 0x3F);
            i += 2;
        } else if ((c & 0xF0) == 0xE0 && i + 2 < utf8.size()) {
            cp = ((c & 0x0F) << 12) |
                 ((static_cast<unsigned char>(utf8[i + 1]) & 0x3F) << 6) |
                 (static_cast<unsigned char>(utf8[i + 2]) & 0x3F);
            i += 3;
        } else if ((c & 0xF8) == 0xF0 && i + 3 < utf8.size()) {
            cp = ((c & 0x07) << 18) |
                 ((static_cast<unsigned char>(utf8[i + 1]) & 0x3F) << 12) |
                 ((static_cast<unsigned char>(utf8[i + 2]) & 0x3F) << 6) |
                 (static_cast<unsigned char>(utf8[i + 3]) & 0x3F);
            i += 4;
        } else {
            ++i;
            continue;
        }
        if (cp <= 0xFFFF) {
            pushU16(static_cast<uint16_t>(cp));
        } else {
            cp -= 0x10000;
            pushU16(static_cast<uint16_t>(0xD800 + (cp >> 10)));
            pushU16(static_cast<uint16_t>(0xDC00 + (cp & 0x3FF)));
        }
    }
    return out;
}

static void appendUtf8(std::string& out, uint32_t cp) {
    if (cp <= 0x7F) {
        out.push_back(static_cast<char>(cp));
    } else if (cp <= 0x7FF) {
        out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp <= 0xFFFF) {
        out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp <= 0x10FFFF) {
        out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
}

ArtRuntime::ArtRuntime(ProcMem& mem, const ArtLayout& layout)
    : mem_(mem), L_(layout) {}

void ArtRuntime::setLayout(const ArtLayout& l) {
    L_ = l;
    clearCache();
}

void ArtRuntime::clearCache() {
    anchor_ = 0;
    strClass_ = 0;
    viewRootImplClass_ = 0;
    activityThreadClass_ = 0;
    classIndexBuilt_ = false;
    dexByDC_.clear();
    dexLoc_.clear();
    descCache_.clear();
    classesByDesc_.clear();
    allClasses_.clear();
    fieldLayouts_.clear();
    staticFieldLayouts_.clear();
    isViewCache_.clear();
    isActivityCache_.clear();
}

bool ArtRuntime::beginRequest(std::string* err) {
    mem_.clearPageCache();
    mem_.resetStats();
    return mem_.refreshMaps(err);
}

void ArtRuntime::endRequest(bool enableMadvise) {
    mem_.madviseCleanup(enableMadvise);
}

std::optional<std::string> ArtRuntime::decodeString(uint64_t addr, bool strictPrintable) {
    if (addr < 0x1000 || (addr & 7) != 0) return std::nullopt;
    if (!mem_.isMapped(addr)) return std::nullopt;

    // If we already know java.lang.String class, reject non-String objects quickly when strict
    if (strictPrintable && strClass_ != 0) {
        if (mem_.u32(addr + L_.klass_off) != static_cast<uint32_t>(strClass_)) {
            return std::nullopt;
        }
    }

    uint32_t cnt = mem_.u32(addr + L_.str_count);
    // ART Android 9+: kCompressed == 0 for Latin-1, bit 0 == 1 for UTF-16
    bool compressed = (cnt & 1u) == 0;
    uint32_t len = cnt >> 1;
    uint32_t maxLen = strictPrintable ? 8192u : 65536u;
    if (len > maxLen) return std::nullopt;
    if (len == 0) return std::string{};

    if (compressed) {
        std::vector<uint8_t> raw(len);
        mem_.readBytes(addr + L_.str_data, raw.data(), len);
        std::string out;
        out.reserve(len);
        for (uint8_t c : raw) {
            if (strictPrintable && (c < 0x09 || (c > 0x0D && c < 0x20))) {
                return std::nullopt;
            }
            if (c < 0x80) {
                out.push_back(static_cast<char>(c));
            } else {
                // Latin-1 (ISO-8859-1) -> UTF-8
                appendUtf8(out, c);
            }
        }
        return out;
    }

    std::vector<uint8_t> raw(static_cast<size_t>(len) * 2);
    mem_.readBytes(addr + L_.str_data, raw.data(), raw.size());
    std::string out;
    out.reserve(len * 2);
    for (uint32_t i = 0; i < len; ++i) {
        uint16_t u;
        std::memcpy(&u, raw.data() + i * 2, 2);
        if (strictPrintable && u < 0x20 && u != 0x09 && u != 0x0A && u != 0x0D) {
            return std::nullopt;
        }
        if (u >= 0xD800 && u <= 0xDBFF) {
            if (i + 1 < len) {
                uint16_t low;
                std::memcpy(&low, raw.data() + (i + 1) * 2, 2);
                if (low >= 0xDC00 && low <= 0xDFFF) {
                    uint32_t cp = 0x10000u + (((u - 0xD800u) << 10) | (low - 0xDC00u));
                    appendUtf8(out, cp);
                    ++i;
                    continue;
                }
            }
            appendUtf8(out, 0xFFFD);
        } else if (u >= 0xDC00 && u <= 0xDFFF) {
            appendUtf8(out, 0xFFFD);
        } else {
            appendUtf8(out, u);
        }
    }
    return out;
}

bool ArtRuntime::isClassShaped(uint64_t addr) {
    if (addr < 0x1000 || (addr & 7) != 0) return false;
    if (!mem_.isMapped(addr)) return false;
    if (mem_.u32(addr + L_.cls_obj_size) > (1u << 22)) return false;
    uint32_t cs = mem_.u32(addr + L_.cls_class_size);
    if (cs < 0x30 || cs > (1u << 20)) return false;
    // Note: access_flags_ == 0 is allowed for runtime-generated classes!
    if (mem_.u32(addr + L_.cls_obj_size_fast) == 0 &&
        mem_.u32(addr + L_.cls_prim_type) == 0 &&
        mem_.u32(addr + L_.cls_super) == 0) {
        return false;
    }
    return true;
}

std::optional<ClassInfo> ArtRuntime::readClass(uint64_t addr) {
    if (!isClassShaped(addr)) return std::nullopt;
    ClassInfo ci;
    ci.addr = addr;
    ci.superClass = mem_.u32(addr + L_.cls_super);
    ci.objSize = mem_.u32(addr + L_.cls_obj_size);
    ci.classFlags = mem_.u32(addr + L_.cls_class_flags);
    ci.status = mem_.u32(addr + L_.cls_status);
    ci.typeIdx = mem_.i32(addr + L_.cls_dex_type_idx);
    ci.classDef = mem_.i32(addr + L_.cls_dex_class_def);
    ci.dexCache = mem_.u32(addr + L_.cls_dex_cache);
    ci.numRefInst = mem_.u32(addr + L_.cls_num_ref_inst);
    uint32_t np = mem_.u32(addr + L_.cls_name);
    if (np != 0) {
        if (auto s = decodeString(np, true)) {
            ci.name = std::move(*s);
        }
    }
    return ci;
}

uint64_t ArtRuntime::anchor() {
    if (anchor_ != 0) return anchor_;
    uint64_t found = 0;
    mem_.eachHeapWord8([&](uint64_t a, uint32_t w0) -> bool {
        if (w0 != static_cast<uint32_t>(a)) return true;
        if (!isClassShaped(a)) return true;
        // Prefer candidate whose dex descriptor resolves to Ljava/lang/Class;
        uint32_t dc = mem_.u32(a + L_.cls_dex_cache);
        int32_t tidx = mem_.i32(a + L_.cls_dex_type_idx);
        if (dc != 0 && tidx >= 0) {
            if (auto d = dexFor(dc)) {
                if (d->typeDesc(static_cast<uint32_t>(tidx)) == "Ljava/lang/Class;") {
                    found = a;
                    return false; // exact match!
                }
            }
        }
        if (found == 0) found = a;
        return true;
    }, false); // anchor is in boot.art; scan cleanly without bitmap assumptions
    anchor_ = found;
    return anchor_;
}

uint64_t ArtRuntime::findDexBegin(uint64_t dexFilePtr) {
    if (dexFilePtr < 0x1000 || !mem_.isMapped(dexFilePtr)) return 0;
    uint8_t buf[0x100];
    mem_.readBytes(dexFilePtr, buf, sizeof(buf));
    for (size_t i = 0; i + 8 <= sizeof(buf); i += 4) {
        uint64_t raw;
        std::memcpy(&raw, buf + i, 8);
        uint64_t v = untag(raw);
        if (v < 0x1000 || !mem_.isMapped(v)) continue;
        uint8_t mag[8];
        mem_.readBytes(v, mag, 8);
        if (std::memcmp(mag, "dex\n", 4) == 0 || std::memcmp(mag, "cdex", 4) == 0) {
            return v;
        }
    }
    return 0;
}

std::shared_ptr<DexFile> ArtRuntime::dexFor(uint64_t dexCache) {
    if (dexCache < 0x1000) return nullptr;
    auto it = dexByDC_.find(dexCache);
    if (it != dexByDC_.end()) return it->second;

    std::shared_ptr<DexFile> d;
    uint32_t loc = mem_.u32(dexCache + 12);
    if (loc != 0) {
        if (auto s = decodeString(loc, true)) {
            dexLoc_[dexCache] = *s;
        }
    }
    uint64_t df = untag(mem_.u64(dexCache + L_.dc_dex_file));
    if (df >= 0x1000) {
        // Direct check if df already points to dex magic, else probe DexFile struct
        uint8_t mag[4] = {0};
        if (mem_.isMapped(df)) {
            mem_.readBytes(df, mag, 4);
        }
        uint64_t begin = 0;
        if (std::memcmp(mag, "dex\n", 4) == 0 || std::memcmp(mag, "cdex", 4) == 0) {
            begin = df;
        } else {
            begin = findDexBegin(df);
        }
        if (begin != 0) {
            d = DexFile::load(mem_, begin);
        }
    }
    dexByDC_[dexCache] = d;
    return d;
}

std::string ArtRuntime::dexLocation(uint64_t dexCache) {
    dexFor(dexCache);
    auto it = dexLoc_.find(dexCache);
    return it != dexLoc_.end() ? it->second : std::string{};
}

std::string ArtRuntime::primDescriptor(const std::string& n) {
    if (n == "int") return "I";
    if (n == "long") return "J";
    if (n == "boolean") return "Z";
    if (n == "byte") return "B";
    if (n == "char") return "C";
    if (n == "short") return "S";
    if (n == "float") return "F";
    if (n == "double") return "D";
    if (n == "void") return "V";
    return {};
}

std::optional<std::string> ArtRuntime::descriptor(uint64_t classAddr) {
    if (classAddr < 0x1000 || (classAddr & 7) != 0) return std::nullopt;
    auto it = descCache_.find(classAddr);
    if (it != descCache_.end()) {
        if (it->second.empty()) return std::nullopt;
        return it->second;
    }
    descCache_[classAddr] = {}; // recursion guard

    auto ci = readClass(classAddr);
    if (!ci) return std::nullopt;

    // 1. Authoritative: DexCache -> DexFile -> type_ids[dex_type_idx_]
    if (ci->dexCache != 0 && ci->typeIdx >= 0) {
        if (auto d = dexFor(ci->dexCache)) {
            std::string s = d->typeDesc(static_cast<uint32_t>(ci->typeIdx));
            if (!s.empty() && (s[0] == 'L' || s[0] == '[')) {
                descCache_[classAddr] = s;
                return s;
            }
        }
    }

    // 2. Fallback: lazily cached mirror::Class.name_
    if (!ci->name.empty()) {
        std::string n = ci->name;
        if (n[0] != 'L' && n[0] != '[') {
            std::string p = primDescriptor(n);
            if (!p.empty()) {
                descCache_[classAddr] = p;
                return p;
            }
            n = dotToDesc(n);
        }
        descCache_[classAddr] = n;
        return n;
    }

    // 3. Array classes with lazily-null name_: resolve via mirror::Class::component_type_ (cls_dex_cache - 4 = +12)
    if (L_.cls_dex_cache >= 4) {
        uint64_t comp = mem_.u32(classAddr + (L_.cls_dex_cache - 4));
        if (comp >= 0x1000 && comp != classAddr && (comp & 7) == 0 && isClassShaped(comp)) {
            if (auto cd = descriptor(comp); cd && !cd->empty()) {
                std::string arrDesc = "[" + *cd;
                descCache_[classAddr] = arrDesc;
                return arrDesc;
            }
        }
    }

    // 4. Primitive classes with lazily-null name_: resolve via primitive_type_ (low 16 bits = Primitive::Type)
    uint32_t pt = mem_.u32(classAddr + L_.cls_prim_type) & 0xFFFFu;
    if (pt >= 1 && pt <= 9) {
        static const char* kPrimDescs[] = {"", "Z", "B", "C", "S", "I", "J", "F", "D", "V"};
        std::string pd = kPrimDescs[pt];
        descCache_[classAddr] = pd;
        return pd;
    }

    return std::nullopt;
}

std::string ArtRuntime::dottedName(uint64_t classAddr) {
    auto d = descriptor(classAddr);
    if (!d) return {};
    return descToDot(*d);
}

std::vector<std::string> ArtRuntime::superClasses(uint64_t classAddr) {
    std::vector<std::string> out;
    std::unordered_set<uint64_t> seen;
    uint64_t cur = mem_.u32(classAddr + L_.cls_super);
    for (int depth = 0; cur >= 0x1000 && depth < 64 && !seen.count(cur); ++depth) {
        seen.insert(cur);
        auto d = descriptor(cur);
        if (!d) break;
        if (*d == "Ljava/lang/Object;") break;
        out.push_back(descToDot(*d));
        cur = mem_.u32(cur + L_.cls_super);
    }
    return out;
}

bool ArtRuntime::isInstanceOf(uint64_t classAddr, const std::string& targetType) {
    std::unordered_set<uint64_t> seen;
    uint64_t cur = classAddr;
    for (int depth = 0; cur >= 0x1000 && depth < 64 && !seen.count(cur); ++depth) {
        seen.insert(cur);
        auto d = descriptor(cur);
        if (d && typeMatchesPattern(*d, targetType)) return true;
        cur = mem_.u32(cur + L_.cls_super);
    }
    return false;
}

bool ArtRuntime::isViewClass(uint64_t classAddr) {
    if (classAddr < 0x1000) return false;
    auto it = isViewCache_.find(classAddr);
    if (it != isViewCache_.end()) return it->second;
    bool r = isInstanceOf(classAddr, "Landroid/view/View;");
    isViewCache_[classAddr] = r;
    return r;
}

bool ArtRuntime::isActivityClass(uint64_t classAddr) {
    if (classAddr < 0x1000) return false;
    auto it = isActivityCache_.find(classAddr);
    if (it != isActivityCache_.end()) return it->second;
    bool r = isInstanceOf(classAddr, "Landroid/app/Activity;");
    isActivityCache_[classAddr] = r;
    return r;
}

void ArtRuntime::ensureClassIndex() {
    if (classIndexBuilt_) return;
    uint64_t k = anchor();
    if (k == 0) return;
    uint32_t kl = static_cast<uint32_t>(k);

    allClasses_.clear();
    classesByDesc_.clear();

    mem_.eachHeapWord8([&](uint64_t a, uint32_t w0) -> bool {
        if (w0 != kl) return true;
        if (!isClassShaped(a)) return true;
        allClasses_.push_back(a);
        if (auto d = descriptor(a)) {
            classesByDesc_[*d].push_back(a);
            if (*d == "Ljava/lang/String;" && strClass_ == 0) strClass_ = a;
            else if (*d == "Landroid/view/ViewRootImpl;" && viewRootImplClass_ == 0) viewRootImplClass_ = a;
            else if (*d == "Landroid/app/ActivityThread;" && activityThreadClass_ == 0) activityThreadClass_ = a;
        }
        return true;
    }, true);

    classIndexBuilt_ = true;
}

uint64_t ArtRuntime::findClass(const std::string& nameOrDesc) {
    ensureClassIndex();
    std::string want = dotToDesc(nameOrDesc);
    auto it = classesByDesc_.find(want);
    if (it != classesByDesc_.end() && !it->second.empty()) {
        return it->second.front();
    }
    return 0;
}

std::vector<uint64_t> ArtRuntime::findClassesMatching(const std::string& pattern, bool includeSubclasses) {
    ensureClassIndex();
    std::vector<uint64_t> out;
    std::unordered_set<uint64_t> seen;

    bool hasGlob = (pattern.find('*') != std::string::npos || pattern.find('?') != std::string::npos);
    if (!hasGlob && !includeSubclasses) {
        std::string want = dotToDesc(pattern);
        auto it = classesByDesc_.find(want);
        if (it != classesByDesc_.end()) {
            return it->second;
        }
        return out;
    }

    for (uint64_t cls : allClasses_) {
        auto d = descriptor(cls);
        if (!d) continue;
        bool matched = typeMatchesPattern(*d, pattern);
        if (!matched && includeSubclasses) {
            matched = isInstanceOf(cls, pattern);
        }
        if (matched && seen.insert(cls).second) {
            out.push_back(cls);
        }
    }
    return out;
}

uint64_t ArtRuntime::stringClass() {
    if (strClass_ != 0) return strClass_;
    strClass_ = findClass("java.lang.String");
    return strClass_;
}

uint64_t ArtRuntime::viewRootImplClass() {
    if (viewRootImplClass_ != 0) return viewRootImplClass_;
    viewRootImplClass_ = findClass("android.view.ViewRootImpl");
    return viewRootImplClass_;
}

uint64_t ArtRuntime::activityThreadClass() {
    if (activityThreadClass_ != 0) return activityThreadClass_;
    activityThreadClass_ = findClass("android.app.ActivityThread");
    return activityThreadClass_;
}

std::vector<ArtFieldInfo> ArtRuntime::readRawInstanceFields(uint64_t classAddr) {
    std::vector<ArtFieldInfo> out;
    std::unordered_set<uint64_t> seen;
    for (uint64_t c = classAddr; c >= 0x1000 && !seen.count(c) && seen.size() < 128; ) {
        seen.insert(c);
        uint64_t arr = untag(mem_.u64(c + L_.cls_ifields));
        if (arr >= 0x1000 && mem_.isMapped(arr)) {
            uint32_t n = mem_.u32(arr);
            if (n > 0 && n < 4000) {
                for (uint32_t i = 0; i < n; ++i) {
                    uint64_t p = arr + 4 + static_cast<uint64_t>(i) * L_.af_stride;
                    ArtFieldInfo fi;
                    fi.declClass = mem_.u32(p + L_.af_decl);
                    fi.access = mem_.u32(p + L_.af_access);
                    // A merged fields_ array also lists static fields; they are not part of the instance layout.
                    if ((fi.access & kAccStatic) != 0) continue;
                    fi.dexIdx = mem_.u32(p + L_.af_dex);
                    fi.offset = mem_.u32(p + L_.af_off);
                    if (fi.declClass >= 0x1000) {
                        uint32_t dc = mem_.u32(fi.declClass + L_.cls_dex_cache);
                        if (dc != 0) {
                            if (auto d = dexFor(dc)) {
                                auto fn = d->field(fi.dexIdx);
                                fi.name = std::move(fn.name);
                                fi.type = std::move(fn.type);
                            }
                        }
                    }
                    out.push_back(std::move(fi));
                }
            }
        }
        c = mem_.u32(c + L_.cls_super);
    }
    return out;
}

const FieldLayout& ArtRuntime::fieldLayout(uint64_t classAddr) {
    auto it = fieldLayouts_.find(classAddr);
    if (it != fieldLayouts_.end()) return it->second;

    FieldLayout fl;
    auto raw = readRawInstanceFields(classAddr);
    for (const auto& f : raw) {
        if (!f.name.empty() && !fl.byName.count(f.name)) {
            fl.byName[f.name] = f;
        }
        if (!fl.byOff.count(f.offset)) {
            fl.byOff[f.offset] = f;
        }
    }
    fl.fields.reserve(fl.byOff.size());
    for (const auto& kv : fl.byOff) {
        fl.fields.push_back(kv.second);
        if (!kv.second.type.empty() && (kv.second.type[0] == 'L' || kv.second.type[0] == '[')) {
            fl.refFields.push_back(kv.second);
        }
    }
    std::sort(fl.fields.begin(), fl.fields.end(),
              [](const ArtFieldInfo& a, const ArtFieldInfo& b) { return a.offset < b.offset; });
    std::sort(fl.refFields.begin(), fl.refFields.end(),
              [](const ArtFieldInfo& a, const ArtFieldInfo& b) { return a.offset < b.offset; });

    auto [ins, _] = fieldLayouts_.emplace(classAddr, std::move(fl));
    return ins->second;
}

const FieldLayout& ArtRuntime::staticFieldLayout(uint64_t classAddr) {
    auto it = staticFieldLayouts_.find(classAddr);
    if (it != staticFieldLayouts_.end()) return it->second;

    FieldLayout fl;
    auto tryReadSFieldsAt = [&](uint64_t slotOff) -> bool {
        uint64_t arr = untag(mem_.u64(classAddr + slotOff));
        if (arr < 0x1000 || !mem_.isMapped(arr)) return false;
        uint32_t n = mem_.u32(arr);
        if (n == 0 || n >= 4000) return false;
        // Verify first ArtField declaring_class points back to classAddr
        if (mem_.u32(arr + 4 + L_.af_decl) != static_cast<uint32_t>(classAddr)) return false;
        for (uint32_t i = 0; i < n; ++i) {
            uint64_t p = arr + 4 + static_cast<uint64_t>(i) * L_.af_stride;
            ArtFieldInfo fi;
            fi.declClass = mem_.u32(p + L_.af_decl);
            fi.access = mem_.u32(p + L_.af_access);
            // A merged fields_ array also lists instance fields; skip them here.
            if ((fi.access & kAccStatic) == 0) continue;
            fi.dexIdx = mem_.u32(p + L_.af_dex);
            fi.offset = mem_.u32(p + L_.af_off);
            if (fi.declClass >= 0x1000) {
                uint32_t dc = mem_.u32(fi.declClass + L_.cls_dex_cache);
                if (dc != 0) {
                    if (auto d = dexFor(dc)) {
                        auto fn = d->field(fi.dexIdx);
                        fi.name = std::move(fn.name);
                        fi.type = std::move(fn.type);
                    }
                }
            }
            if (!fi.name.empty()) {
                fl.byName[fi.name] = fi;
                fl.byOff[fi.offset] = fi;
                fl.fields.push_back(fi);
            }
        }
        return !fl.fields.empty();
    };

    // With a merged fields_ array (cls_sfields == cls_ifields) there is no other slot to probe.
    if (!tryReadSFieldsAt(L_.cls_sfields) && L_.cls_sfields != L_.cls_ifields) {
        // Fallback probe around ifields_
        for (uint64_t off = 32; off <= 80; off += 8) {
            if (off == L_.cls_ifields || off == L_.cls_sfields) continue;
            if (tryReadSFieldsAt(off)) break;
        }
    }

    auto [ins, _] = staticFieldLayouts_.emplace(classAddr, std::move(fl));
    return ins->second;
}

uint64_t ArtRuntime::readRefField(uint64_t obj, const FieldLayout& fl, const std::string& name) {
    auto it = fl.byName.find(name);
    if (it == fl.byName.end()) return 0;
    return mem_.u32(obj + it->second.offset);
}

int32_t ArtRuntime::readIntField(uint64_t obj, const FieldLayout& fl, const std::string& name, int32_t def) {
    auto it = fl.byName.find(name);
    if (it == fl.byName.end()) return def;
    const auto& t = it->second.type;
    if (t == "Z") return mem_.u8(obj + it->second.offset) != 0 ? 1 : 0;
    if (t == "B") return static_cast<int8_t>(mem_.u8(obj + it->second.offset));
    if (t == "S") return static_cast<int16_t>(mem_.u16(obj + it->second.offset));
    if (t == "C") return static_cast<int32_t>(mem_.u16(obj + it->second.offset));
    return mem_.i32(obj + it->second.offset);
}

int64_t ArtRuntime::readLongField(uint64_t obj, const FieldLayout& fl, const std::string& name, int64_t def) {
    auto it = fl.byName.find(name);
    if (it == fl.byName.end()) return def;
    if (it->second.type == "J") return mem_.i64(obj + it->second.offset);
    return readIntField(obj, fl, name, static_cast<int32_t>(def));
}

bool ArtRuntime::readBoolField(uint64_t obj, const FieldLayout& fl, const std::string& name, bool def) {
    auto it = fl.byName.find(name);
    if (it == fl.byName.end()) return def;
    return mem_.u8(obj + it->second.offset) != 0;
}

float ArtRuntime::readFloatField(uint64_t obj, const FieldLayout& fl, const std::string& name, float def) {
    auto it = fl.byName.find(name);
    if (it == fl.byName.end()) return def;
    return mem_.f32(obj + it->second.offset);
}

double ArtRuntime::readDoubleField(uint64_t obj, const FieldLayout& fl, const std::string& name, double def) {
    auto it = fl.byName.find(name);
    if (it == fl.byName.end()) return def;
    if (it->second.type == "D") return mem_.f64(obj + it->second.offset);
    return static_cast<double>(mem_.f32(obj + it->second.offset));
}

std::string ArtRuntime::readCharSeq(uint64_t addr) {
    if (addr < 0x1000 || (addr & 7) != 0 || !mem_.isMapped(addr)) return {};
    uint64_t kl = mem_.u32(addr + L_.klass_off);
    if (kl < 0x1000) return {};

    // Fast path: java.lang.String
    if (strClass_ != 0 && kl == strClass_) {
        if (auto s = decodeString(addr, false)) return *s;
        return {};
    }
    auto desc = descriptor(kl);
    if (!desc) return {};
    if (*desc == "Ljava/lang/String;") {
        strClass_ = kl;
        if (auto s = decodeString(addr, false)) return *s;
        return {};
    }

    const auto& fl = fieldLayout(kl);

    // StringBuilder / StringBuffer (AbstractStringBuilder)
    if (*desc == "Ljava/lang/StringBuilder;" || *desc == "Ljava/lang/StringBuffer;") {
        uint64_t valArr = readRefField(addr, fl, "value");
        int32_t count = readIntField(addr, fl, "count", -1);
        if (valArr >= 0x1000 && count > 0 && count <= 65536) {
            uint64_t akl = mem_.u32(valArr + L_.klass_off);
            auto ad = descriptor(akl);
            int32_t alen = mem_.i32(valArr + 8);
            if (ad && *ad == "[B") {
                int32_t coder = readIntField(addr, fl, "coder", 0);
                if (coder == 0) {
                    int32_t n = std::min(count, alen);
                    std::vector<uint8_t> raw(static_cast<size_t>(n));
                    mem_.readBytes(valArr + 12, raw.data(), raw.size());
                    std::string out;
                    out.reserve(raw.size());
                    for (uint8_t b : raw) {
                        if (b < 0x80) out.push_back(static_cast<char>(b));
                        else appendUtf8(out, b);
                    }
                    return out;
                } else {
                    int32_t n = std::min(count, alen / 2);
                    std::vector<uint8_t> raw(static_cast<size_t>(n) * 2);
                    mem_.readBytes(valArr + 12, raw.data(), raw.size());
                    std::string out;
                    for (int32_t i = 0; i < n; ++i) {
                        uint16_t u;
                        std::memcpy(&u, raw.data() + i * 2, 2);
                        appendUtf8(out, u);
                    }
                    return out;
                }
            } else if (ad && *ad == "[C") {
                int32_t n = std::min(count, alen);
                std::vector<uint8_t> raw(static_cast<size_t>(n) * 2);
                mem_.readBytes(valArr + 12, raw.data(), raw.size());
                std::string out;
                for (int32_t i = 0; i < n; ++i) {
                    uint16_t u;
                    std::memcpy(&u, raw.data() + i * 2, 2);
                    appendUtf8(out, u);
                }
                return out;
            }
        }
        return {};
    }

    // SpannableStringBuilder: mText ([C), mGapStart, mGapLength
    if (*desc == "Landroid/text/SpannableStringBuilder;") {
        uint64_t arr = readRefField(addr, fl, "mText");
        if (arr >= 0x1000) {
            int32_t alen = mem_.i32(arr + 8);
            int32_t gapStart = readIntField(addr, fl, "mGapStart", 0);
            int32_t gapLen = readIntField(addr, fl, "mGapLength", 0);
            if (alen > 0 && alen <= 65536 && gapStart >= 0 && gapLen >= 0 && gapStart + gapLen <= alen) {
                std::vector<uint8_t> raw(static_cast<size_t>(alen) * 2);
                mem_.readBytes(arr + 12, raw.data(), raw.size());
                std::string out;
                for (int32_t i = 0; i < alen; ++i) {
                    if (i >= gapStart && i < gapStart + gapLen) continue;
                    uint16_t u;
                    std::memcpy(&u, raw.data() + i * 2, 2);
                    if (u == 0) continue;
                    if (u >= 0xD800 && u <= 0xDBFF && i + 1 < alen) {
                        int32_t ni = i + 1;
                        if (ni >= gapStart && ni < gapStart + gapLen) ni = gapStart + gapLen;
                        if (ni < alen) {
                            uint16_t low;
                            std::memcpy(&low, raw.data() + ni * 2, 2);
                            if (low >= 0xDC00 && low <= 0xDFFF) {
                                appendUtf8(out, 0x10000u + (((u - 0xD800u) << 10) | (low - 0xDC00u)));
                                i = ni;
                                continue;
                            }
                        }
                    }
                    appendUtf8(out, u);
                }
                return out;
            }
        }
    }

    // SpannableString / SpannedString / CharSequence wrappers
    for (const char* cand : {"mText", "mSource", "text", "value"}) {
        uint64_t v = readRefField(addr, fl, cand);
        if (v >= 0x1000 && v != addr) {
            uint64_t vkl = mem_.u32(v + L_.klass_off);
            if (vkl != 0) {
                auto vd = descriptor(vkl);
                if (vd && *vd == "Ljava/lang/String;") {
                    if (auto s = decodeString(v, false)) return *s;
                }
            }
        }
    }
    return {};
}

std::vector<std::pair<uint64_t, uint64_t>> ArtRuntime::collectClassMetadataRanges(
    const std::vector<uint64_t>& classAddrs) {
    std::vector<std::pair<uint64_t, uint64_t>> ranges;
    for (uint64_t c : classAddrs) {
        if (c < 0x1000 || !mem_.isMapped(c)) continue;
        uint32_t c32 = static_cast<uint32_t>(c);
        // Probe pointer slots in mirror::Class (ifields_, methods_, sfields_, etc.)
        // LengthPrefixedArray<ArtField/ArtMethod> has count at +0 and elements starting at +4
        // where element[0].declaring_class_ == c32.
        for (uint64_t off = 24; off <= 80; off += 8) {
            uint64_t arr = untag(mem_.u64(c + off));
            if (arr < 0x1000 || !mem_.isMapped(arr)) continue;
            uint32_t n = mem_.u32(arr);
            if (n == 0 || n > 65536) continue;
            if (mem_.u32(arr + 4 + L_.af_decl) != c32) continue;

            uint64_t stride = 0;
            if (off == L_.cls_ifields || off == L_.cls_sfields) {
                stride = L_.af_stride;
            } else {
                // ArtMethod array: detect stride dynamically (typically 24, 32, 40, or 48 bytes)
                if (n == 1) {
                    stride = 48;
                } else {
                    for (uint64_t cand : {16ULL, 24ULL, 32ULL, 40ULL, 48ULL, 56ULL, 64ULL}) {
                        if (mem_.u32(arr + 4 + cand) == c32) {
                            stride = cand;
                            break;
                        }
                    }
                    if (stride == 0) stride = 48;
                }
            }
            ranges.emplace_back(arr, arr + 4 + static_cast<uint64_t>(n) * stride);
        }
    }
    std::sort(ranges.begin(), ranges.end());
    return ranges;
}

bool ArtRuntime::isPlausibleInstance(uint64_t addr, uint64_t klassAddr,
                                     const std::vector<std::pair<uint64_t, uint64_t>>& excludedRanges) {
    // 1) Exclude ArtField / ArtMethod metadata arrays belonging to target classes
    for (const auto& [lo, hi] : excludedRanges) {
        if (addr >= lo && addr < hi) return false;
        if (lo > addr) break;
    }
    // 2) Reject interior slots of a mirror::Class (e.g. Class.super_class_ at +32, static Class fields)
    uint64_t anc = anchor();
    if (anc != 0) {
        uint32_t anc32 = static_cast<uint32_t>(anc);
        for (uint64_t back = 8; back <= 128 && addr > back + 0x1000; back += 8) {
            uint64_t candCls = addr - back;
            if (mem_.u32(candCls + L_.klass_off) == anc32 && isClassShaped(candCls)) {
                uint32_t clsSz = mem_.u32(candCls + L_.cls_class_size);
                if (clsSz >= back && candCls + clsSz > addr) {
                    return false;
                }
                break;
            }
        }
    }
    // 3) Reject interior slots of Class[] / Object[] arrays holding Class pointers (e.g. iftable_, DexCache)
    for (uint64_t back = 12; back <= 64 && addr > back + 0x1000; back += 4) {
        uint64_t candArr = addr - back;
        if ((candArr & 7) != 0) continue;
        uint32_t akl = mem_.u32(candArr + L_.klass_off);
        if (akl < 0x1000 || (akl & 7) != 0) continue;
        auto ad = descriptor(akl);
        if (ad && (*ad == "[Ljava/lang/Class;" || *ad == "[Ljava/lang/Object;")) {
            int32_t alen = mem_.i32(candArr + 8);
            uint32_t idx = static_cast<uint32_t>((back - 12) / 4);
            if (alen > 0 && alen < 1000000 && idx < static_cast<uint32_t>(alen)) {
                return false;
            }
        }
    }
    // 4) Validate shadow$_monitor_ (art::LockWord) at addr + 4
    // Rejects Object[]/Class[]/DexCache slots where the adjacent 32-bit word is another heap pointer!
    uint32_t mon = mem_.u32(addr + 4);
    uint32_t state = (mon >> 30) & 3u;
    if (state == 1u) {
        // kFatLocked: monitor_id is a small index in MonitorPool (< 1M), never a heap addr 0x6f../0x76..
        if ((mon & 0x0FFFFFFFu) >= 0x00100000u) return false;
    } else if (state == 0u) {
        // kUnlocked / kThinLocked: lock_count bits [27:16] should be small (< 256)
        uint32_t lockCount = (mon >> 16) & 0x0FFFu;
        if (lockCount >= 256u) return false;
    }
    (void)klassAddr;
    return true;
}

std::vector<std::pair<uint64_t, uint64_t>> ArtRuntime::scanInstances(
    const std::vector<uint64_t>& classAddrs, size_t limit) {
    std::vector<std::pair<uint64_t, uint64_t>> out;
    if (classAddrs.empty() || limit == 0) return out;

    std::unordered_set<uint32_t> targetSet;
    targetSet.reserve(classAddrs.size() * 2);
    for (uint64_t c : classAddrs) {
        if (c >= 0x1000) targetSet.insert(static_cast<uint32_t>(c));
    }
    auto excluded = collectClassMetadataRanges(classAddrs);

    mem_.eachHeapWord8([&](uint64_t a, uint32_t w0) -> bool {
        if (targetSet.count(w0)) {
            if (!isPlausibleInstance(a, static_cast<uint64_t>(w0), excluded)) {
                return true;
            }
            out.emplace_back(a, static_cast<uint64_t>(w0));
            if (out.size() >= limit) return false;
        }
        return true;
    }, true);
    return out;
}

static size_t findBytes(const uint8_t* hay, size_t hayLen, const uint8_t* needle, size_t needleLen, size_t from) {
    if (needleLen == 0 || from + needleLen > hayLen) return std::string::npos;
    const void* p = ::memmem(hay + from, hayLen - from, needle, needleLen);
    if (!p) return std::string::npos;
    return static_cast<size_t>(static_cast<const uint8_t*>(p) - hay);
}

std::vector<StringHit> ArtRuntime::findStringsContaining(const std::string& needle, size_t limit) {
    std::vector<StringHit> out;
    if (needle.empty() || limit == 0) return out;

    uint64_t sc = stringClass();
    std::vector<uint8_t> wide = encodeUtf16LE(needle);
    bool asciiOnly = true;
    for (unsigned char c : needle) {
        if (c >= 0x80) { asciiOnly = false; break; }
    }

    std::unordered_set<uint64_t> seen;

    auto tryCandidate = [&](uint64_t dataPos, bool isWide) -> bool {
        // Walk backwards from dataPos to find the enclosing mirror::String header!
        // Note: dataPos could be in the middle of the string, not just offset 0 of str_data!
        // Wait: if needle is a substring at offset k inside string data, strObj = dataPos - k - L.str_data.
        // Fast check offset 0 first, then scan backwards up to 1024 bytes (aligned 8) checking klass_ == strClass!
        uint64_t minBase = (dataPos > 2048 + L_.str_data) ? (dataPos - 2048 - L_.str_data) : 0x1000;
        uint64_t startCand = (dataPos >= L_.str_data) ? ((dataPos - L_.str_data) & ~7ULL) : 0;
        if (startCand < 0x1000) return true;

        // First check exact start (needle at beginning of string)
        auto checkObj = [&](uint64_t cand) -> bool {
            if (cand < 0x1000 || (cand & 7) != 0 || seen.count(cand)) return false;
            if (sc != 0 && mem_.u32(cand + L_.klass_off) != static_cast<uint32_t>(sc)) return false;
            uint32_t cnt = mem_.u32(cand + L_.str_count);
            bool comp = (cnt & 1u) == 0;
            if (isWide && comp) return false;
            if (!isWide && !comp) return false;
            uint32_t len = cnt >> 1;
            uint64_t endData = cand + L_.str_data + static_cast<uint64_t>(len) * (comp ? 1u : 2u);
            if (dataPos < cand + L_.str_data || dataPos >= endData) return false;
            auto txt = decodeString(cand, sc == 0);
            if (txt && txt->find(needle) != std::string::npos) {
                seen.insert(cand);
                out.push_back(StringHit{cand, std::move(*txt)});
                return true;
            }
            return false;
        };

        if (dataPos >= L_.str_data && ((dataPos - L_.str_data) & 7) == 0) {
            if (checkObj(dataPos - L_.str_data)) {
                return out.size() < limit;
            }
        }
        // Substring match: scan backwards aligned by 8 for klass_ == strClass
        if (sc != 0) {
            for (uint64_t cand = startCand; cand >= minBase; cand -= 8) {
                if (mem_.u32(cand + L_.klass_off) == static_cast<uint32_t>(sc)) {
                    if (checkObj(cand)) {
                        return out.size() < limit;
                    }
                    break; // hit preceding String object
                }
                if (cand < 8) break;
            }
        }
        return out.size() < limit;
    };

    mem_.eachHeapChunk([&](uint64_t base, const uint8_t* buf, size_t len) -> bool {
        if (asciiOnly) {
            size_t idx = 0;
            while (idx < len) {
                size_t j = findBytes(buf, len, reinterpret_cast<const uint8_t*>(needle.data()), needle.size(), idx);
                if (j == std::string::npos) break;
                idx = j + 1;
                if (!tryCandidate(base + j, false)) return false;
            }
        }
        if (!wide.empty()) {
            size_t idx = 0;
            while (idx < len) {
                size_t j = findBytes(buf, len, wide.data(), wide.size(), idx);
                if (j == std::string::npos) break;
                idx = j + 2;
                if (!tryCandidate(base + j, true)) return false;
            }
        }
        return out.size() < limit;
    });

    std::sort(out.begin(), out.end(),
              [](const StringHit& a, const StringHit& b) { return a.addr < b.addr; });
    return out;
}

std::optional<RefOwner> ArtRuntime::resolveOwner(uint64_t refAddr, uint32_t target) {
    // Walk backwards on 8-byte aligned candidate object headers (ART objects are 8B aligned!)
    uint64_t start = refAddr & ~7ULL;
    for (uint64_t owner = start; owner >= 0x1000 && (refAddr - owner) < 0x1200; owner -= 8) {
        if (owner == refAddr) {
            // refAddr is at offset 0 (klass_ itself), not an instance field
            if (owner < 8) break;
            continue;
        }
        uint64_t kl = mem_.u32(owner + L_.klass_off);
        if (kl < 0x1000 || (kl & 7) != 0) {
            if (owner < 8) break;
            continue;
        }
        auto d = descriptor(kl);
        if (!d) {
            if (owner < 8) break;
            continue;
        }
        uint32_t relOff = static_cast<uint32_t>(refAddr - owner);

        // Object array owner: [L...; or [[...
        if ((*d)[0] == '[') {
            if ((d->size() >= 2 && ((*d)[1] == 'L' || (*d)[1] == '[')) &&
                relOff >= 12 && ((relOff - 12) % 4 == 0)) {
                int32_t alen = mem_.i32(owner + 8);
                uint32_t elemIdx = (relOff - 12) / 4;
                if (alen > 0 && alen < 1000000 && elemIdx < static_cast<uint32_t>(alen)) {
                    if (mem_.u32(refAddr) == target) {
                        RefOwner ro;
                        ro.refAddr = refAddr;
                        ro.ownerAddr = owner;
                        ro.ownerClass = descToDot(*d);
                        ro.fieldName = "[" + std::to_string(elemIdx) + "]";
                        ro.fieldType = d->substr(1);
                        return ro;
                    }
                }
            }
            if (owner < 8) break;
            continue;
        }

        // Regular object owner
        const auto& fl = fieldLayout(kl);
        auto fit = fl.byOff.find(relOff);
        if (fit == fl.byOff.end()) {
            if (owner < 8) break;
            continue;
        }
        const auto& fi = fit->second;
        if (fi.type.empty() || (fi.type[0] != 'L' && fi.type[0] != '[')) {
            if (owner < 8) break;
            continue;
        }
        if (mem_.u32(refAddr) != target) {
            if (owner < 8) break;
            continue;
        }
        RefOwner ro;
        ro.refAddr = refAddr;
        ro.ownerAddr = owner;
        ro.ownerClass = descToDot(*d);
        ro.fieldName = fi.name;
        ro.fieldType = fi.type;
        return ro;
    }
    return std::nullopt;
}

std::vector<RefOwner> ArtRuntime::whoRefs(uint32_t target, size_t limit) {
    auto res = whoRefsBatch({target}, limit);
    auto it = res.find(target);
    if (it != res.end()) return std::move(it->second);
    return {};
}

std::unordered_map<uint32_t, std::vector<RefOwner>> ArtRuntime::whoRefsBatch(
    const std::vector<uint32_t>& targets, size_t limitPerTarget) {
    std::unordered_map<uint32_t, std::vector<RefOwner>> out;
    if (targets.empty() || limitPerTarget == 0) return out;

    std::unordered_set<uint32_t> targetSet(targets.begin(), targets.end());
    std::unordered_map<uint32_t, std::vector<uint64_t>> rawHits;

    // Single heap pass for all targets in batch!
    mem_.eachHeapChunk([&](uint64_t base, const uint8_t* buf, size_t len) -> bool {
        for (size_t off = 0; off + 4 <= len; off += 4) {
            uint32_t v;
            std::memcpy(&v, buf + off, 4);
            if (targetSet.count(v)) {
                auto& vec = rawHits[v];
                if (vec.size() < limitPerTarget * 4) {
                    vec.push_back(base + off);
                }
            }
        }
        return true;
    });

    for (auto& [tgt, refs] : rawHits) {
        std::unordered_set<uint64_t> seenOwners;
        auto& owners = out[tgt];
        for (uint64_t r : refs) {
            if (owners.size() >= limitPerTarget) break;
            auto ro = resolveOwner(r, tgt);
            if (!ro) continue;
            if (!seenOwners.insert(ro->ownerAddr).second) continue;
            owners.push_back(std::move(*ro));
        }
    }
    return out;
}

static bool isGraphSkipField(const std::string& name) {
    static const std::unordered_set<std::string> kSkip = {
        "mParent", "mContext", "mAttachInfo", "mResources",
        "mWindow", "mRootView", "mDisplay", "mDrawingCache",
        "mRenderNode", "mOverlay", "mOutlineProvider",
        "mTransientStateCount", "mStateListAnimator",
        "mThread", "mHandler", "mChoreographer",
        "mApplication", "mBase", "mPackageInfo",
        "shadow$_klass_", "shadow$_monitor_"
    };
    return kSkip.count(name) > 0;
}

std::vector<CrawlHit> ArtRuntime::crawlStrings(uint64_t root, const std::string& match,
                                               int depth, int maxObjects) {
    std::vector<CrawlHit> out;
    if (root < 0x1000) return out;
    uint64_t sc = stringClass();

    struct Item {
        uint64_t addr;
        int d;
        std::string path;
    };
    std::unordered_set<uint64_t> seen;
    std::queue<Item> q;
    seen.insert(root);
    q.push({root, 0, ""});

    int visited = 0;
    while (!q.empty()) {
        Item it = std::move(q.front());
        q.pop();
        if (++visited > maxObjects) break;

        uint64_t kl = mem_.u32(it.addr + L_.klass_off);
        if (kl < 0x1000) continue;

        if (sc != 0 && kl == sc) {
            if (auto s = decodeString(it.addr, false)) {
                if (!s->empty() && (match.empty() || s->find(match) != std::string::npos)) {
                    out.push_back(CrawlHit{it.path, std::move(*s), it.addr});
                }
            }
            continue;
        }
        if (it.d >= depth) continue;

        auto desc = descriptor(kl);
        if (!desc) continue;

        if ((*desc)[0] == '[') {
            if (desc->size() >= 2 && ((*desc)[1] == 'L' || (*desc)[1] == '[')) {
                int32_t n = mem_.i32(it.addr + 8);
                int32_t lim = std::min<int32_t>(n, 64);
                for (int32_t i = 0; i < lim; ++i) {
                    uint64_t c = mem_.u32(it.addr + 12 + static_cast<uint64_t>(i) * 4);
                    if (c >= 0x1000 && seen.insert(c).second) {
                        q.push({c, it.d + 1, it.path + "[" + std::to_string(i) + "]"});
                    }
                }
            }
            continue;
        }

        const auto& fl = fieldLayout(kl);
        for (const auto& f : fl.refFields) {
            if (f.name.empty() || isGraphSkipField(f.name)) continue;
            uint64_t v = mem_.u32(it.addr + f.offset);
            if (v < 0x1000 || !seen.insert(v).second) continue;
            std::string np = it.path.empty() ? f.name : (it.path + "." + f.name);
            q.push({v, it.d + 1, std::move(np)});
        }
    }
    return out;
}

bool ArtRuntime::quickValidate(std::string* reason) {
    uint64_t anc = anchor();
    if (anc == 0) {
        if (reason) *reason = "java.lang.Class anchor not found";
        return false;
    }
    auto ancDesc = descriptor(anc);
    if (!ancDesc || *ancDesc != "Ljava/lang/Class;") {
        if (reason) *reason = "anchor did not resolve to Ljava/lang/Class;";
        return false;
    }
    uint64_t sc = stringClass();
    if (sc == 0) {
        if (reason) *reason = "java.lang.String class not resolved via DexCache";
        return false;
    }
    // Check superclass chain: String -> Object -> 0
    uint64_t sup = mem_.u32(sc + L_.cls_super);
    auto supDesc = descriptor(sup);
    if (!supDesc || *supDesc != "Ljava/lang/Object;" || mem_.u32(sup + L_.cls_super) != 0) {
        if (reason) *reason = "Class.super_class_ mismatch on java.lang.String";
        return false;
    }
    // Check ArtField layout + cross-check String.count offset == str_count
    uint64_t arr = untag(mem_.u64(sc + L_.cls_ifields));
    if (arr < 0x1000 || !mem_.isMapped(arr)) {
        if (reason) *reason = "java.lang.String ifields_ unmapped";
        return false;
    }
    uint32_t n = mem_.u32(arr);
    if (n == 0 || n > 1000) {
        if (reason) *reason = "java.lang.String ifields_ count implausible: " + std::to_string(n);
        return false;
    }
    uint32_t decl = mem_.u32(arr + 4 + L_.af_decl);
    if (decl != static_cast<uint32_t>(sc)) {
        if (reason) *reason = "ArtField[0].declaring_class mismatch";
        return false;
    }
    const auto& fl = fieldLayout(sc);
    auto cit = fl.byName.find("count");
    if (cit == fl.byName.end() || cit->second.type != "I" || cit->second.offset != L_.str_count) {
        if (reason) *reason = "ArtField/str_count cross-check failed on java.lang.String.count";
        return false;
    }
    // Check String decoding on DexCache.location_ (always populated!) and String.name_ (if initialized)
    uint64_t dc = mem_.u32(sc + L_.cls_dex_cache);
    std::string loc = dexLocation(dc);
    if (loc.empty() || (loc[0] != '/' && loc.find(".jar") == std::string::npos && loc.find(".dex") == std::string::npos)) {
        if (reason) *reason = "String decoding failed on DexCache.location_";
        return false;
    }
    uint32_t nameRef = mem_.u32(sc + L_.cls_name);
    if (nameRef != 0) {
        auto s = decodeString(nameRef, true);
        if (!s || (*s != "java.lang.String" && *s != "Ljava/lang/String;")) {
            if (reason) *reason = "String decoding failed on java.lang.String.name_";
            return false;
        }
    }
    return true;
}

// ---------------- RuntimeManager ----------------

void RuntimeManager::setLayout(const ArtLayout& l) {
    layout_ = l;
    if (active_ && active_->rt) {
        active_->rt->setLayout(l);
    }
}

void RuntimeManager::clearAll() {
    active_.reset();
}

std::optional<RuntimeManager::Handle> RuntimeManager::acquire(int pid, std::string* err) {
    auto st = readProcStartTime(pid);
    if (!st) {
        if (err) *err = "process " + std::to_string(pid) + " not found";
        return std::nullopt;
    }
    if (active_ && active_->pid == pid && active_->starttime == *st && active_->mem->isOpen()) {
        if (!active_->rt->beginRequest(err)) {
            active_.reset();
            return std::nullopt;
        }
        bool warm = active_->rt->isCacheWarm();
        return Handle{active_->rt.get(), *st, warm};
    }

    auto entry = std::make_unique<Entry>();
    entry->pid = pid;
    entry->starttime = *st;
    entry->mem = std::make_unique<ProcMem>();
    if (!entry->mem->open(pid, err)) {
        return std::nullopt;
    }
    entry->rt = std::make_unique<ArtRuntime>(*entry->mem, layout_);
    active_ = std::move(entry);
    return Handle{active_->rt.get(), *st, false};
}

} // namespace artseek
