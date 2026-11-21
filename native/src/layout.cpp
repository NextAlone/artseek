#include "layout.hpp"

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>

#ifdef __ANDROID__
#include <sys/system_properties.h>
#endif

namespace artseek {

Json ArtLayout::toJson() const {
    Json j = Json::object();
    j.set("header", obj_header);
    j.set("klass", klass_off);
    j.set("heapref", heap_ref_sz);
    j.set("str_count", str_count);
    j.set("str_hash", str_hash);
    j.set("str_data", str_data);
    j.set("dex_cache", cls_dex_cache);
    j.set("name", cls_name);
    j.set("super", cls_super);
    j.set("ifields", cls_ifields);
    j.set("sfields", cls_sfields);
    j.set("access", cls_access);
    j.set("class_flags", cls_class_flags);
    j.set("class_size", cls_class_size);
    j.set("class_def", cls_dex_class_def);
    j.set("type_idx", cls_dex_type_idx);
    j.set("num_ref_inst", cls_num_ref_inst);
    j.set("obj_size", cls_obj_size);
    j.set("obj_size_fast", cls_obj_size_fast);
    j.set("prim_type", cls_prim_type);
    j.set("status", cls_status);
    j.set("dex_file", dc_dex_file);
    j.set("af_stride", af_stride);
    j.set("af_decl", af_decl);
    j.set("af_dex", af_dex);
    j.set("af_off", af_off);
    j.set("af_access", af_access);
    j.set("inst_size", static_cast<uint64_t>(inst_size));
    j.set("fingerprint", fingerprint);
    j.set("source", source);
    return j;
}

Json ArtLayout::toNumericMap() const {
    Json j = Json::object();
    j.set("header", obj_header);
    j.set("klass", klass_off);
    j.set("heapref", heap_ref_sz);
    j.set("str_count", str_count);
    j.set("str_hash", str_hash);
    j.set("str_data", str_data);
    j.set("dex_cache", cls_dex_cache);
    j.set("name", cls_name);
    j.set("super", cls_super);
    j.set("ifields", cls_ifields);
    j.set("sfields", cls_sfields);
    j.set("access", cls_access);
    j.set("class_flags", cls_class_flags);
    j.set("class_size", cls_class_size);
    j.set("class_def", cls_dex_class_def);
    j.set("type_idx", cls_dex_type_idx);
    j.set("num_ref_inst", cls_num_ref_inst);
    j.set("obj_size", cls_obj_size);
    j.set("obj_size_fast", cls_obj_size_fast);
    j.set("prim_type", cls_prim_type);
    j.set("status", cls_status);
    j.set("dex_file", dc_dex_file);
    j.set("af_stride", af_stride);
    j.set("af_decl", af_decl);
    j.set("af_dex", af_dex);
    j.set("af_off", af_off);
    j.set("af_access", af_access);
    j.set("inst_size", static_cast<uint64_t>(inst_size));
    return j;
}

bool ArtLayout::fromJson(const Json& j, ArtLayout& out) {
    if (!j.isObject()) return false;
    auto reqU64 = [&](std::string_view k, uint64_t& dst) -> bool {
        if (!j.has(k) || !j.get(k).isNumber()) return false;
        int64_t v = j.get(k).asInt(-1);
        if (v < 0) return false;
        dst = static_cast<uint64_t>(v);
        return true;
    };
    auto optU64 = [&](std::string_view k, uint64_t& dst) {
        if (j.has(k) && j.get(k).isNumber()) {
            int64_t v = j.get(k).asInt(-1);
            if (v >= 0) dst = static_cast<uint64_t>(v);
        }
    };

    ArtLayout tmp;
    if (!reqU64("header", tmp.obj_header)) return false;
    if (!reqU64("klass", tmp.klass_off)) return false;
    optU64("heapref", tmp.heap_ref_sz);
    if (!reqU64("str_count", tmp.str_count)) return false;
    optU64("str_hash", tmp.str_hash);
    if (!reqU64("str_data", tmp.str_data)) return false;
    if (!reqU64("dex_cache", tmp.cls_dex_cache)) return false;
    if (!reqU64("dex_file", tmp.dc_dex_file)) return false;
    if (!reqU64("ifields", tmp.cls_ifields)) return false;
    optU64("sfields", tmp.cls_sfields);
    if (!reqU64("super", tmp.cls_super)) return false;
    optU64("name", tmp.cls_name);
    optU64("access", tmp.cls_access);
    optU64("class_flags", tmp.cls_class_flags);
    optU64("class_size", tmp.cls_class_size);
    optU64("class_def", tmp.cls_dex_class_def);
    if (!reqU64("type_idx", tmp.cls_dex_type_idx)) return false;
    optU64("num_ref_inst", tmp.cls_num_ref_inst);
    optU64("obj_size", tmp.cls_obj_size);
    optU64("obj_size_fast", tmp.cls_obj_size_fast);
    optU64("prim_type", tmp.cls_prim_type);
    optU64("status", tmp.cls_status);
    if (!reqU64("af_stride", tmp.af_stride)) return false;
    if (!reqU64("af_decl", tmp.af_decl)) return false;
    if (!reqU64("af_dex", tmp.af_dex)) return false;
    if (!reqU64("af_off", tmp.af_off)) return false;
    optU64("af_access", tmp.af_access);

    uint64_t isz = 0;
    optU64("inst_size", isz);
    tmp.inst_size = static_cast<uint32_t>(isz);
    if (j.has("fingerprint") && j.get("fingerprint").isString()) {
        tmp.fingerprint = j.get("fingerprint").asString();
    }
    if (j.has("source") && j.get("source").isString()) {
        tmp.source = j.get("source").asString();
    } else {
        tmp.source = "calibrated";
    }
    out = std::move(tmp);
    return true;
}

std::string readBuildFingerprint() {
#ifdef __ANDROID__
    char buf[PROP_VALUE_MAX] = {0};
    int n = __system_property_get("ro.build.fingerprint", buf);
    if (n > 0) return std::string(buf, static_cast<size_t>(n));
#endif
    std::ifstream f("/system/build.prop");
    std::string line;
    const std::string prefix = "ro.build.fingerprint=";
    while (std::getline(f, line)) {
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n' || line.back() == ' ')) {
            line.pop_back();
        }
        if (line.rfind(prefix, 0) == 0) {
            return line.substr(prefix.size());
        }
    }
    return "unknown";
}

bool ensureCacheDir(const std::string& dir, std::string* err) {
    if (dir.empty()) {
        if (err) *err = "empty cache dir";
        return false;
    }
    // Create parent components best-effort
    std::string cur;
    for (size_t i = 0; i < dir.size(); ++i) {
        cur.push_back(dir[i]);
        if (dir[i] == '/' && cur.size() > 1) {
            ::mkdir(cur.c_str(), 0700);
        }
    }
    if (::mkdir(dir.c_str(), 0700) != 0 && errno != EEXIST) {
        if (err) *err = std::string("mkdir ") + dir + ": " + std::strerror(errno);
        return false;
    }
    if (::chmod(dir.c_str(), 0700) != 0) {
        if (err) *err = std::string("chmod 0700 ") + dir + ": " + std::strerror(errno);
        return false;
    }
    return true;
}

bool loadLayoutFile(const std::string& path, ArtLayout& out, std::string* err) {
    int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        if (err) *err = std::string("open ") + path + ": " + std::strerror(errno);
        return false;
    }
    std::string content;
    char buf[4096];
    ssize_t n;
    while ((n = ::read(fd, buf, sizeof(buf))) > 0) {
        content.append(buf, static_cast<size_t>(n));
        if (content.size() > 1024 * 1024) break;
    }
    ::close(fd);
    std::string perr;
    auto parsed = Json::parse(content, &perr);
    if (!parsed) {
        if (err) *err = "invalid layout json: " + perr;
        return false;
    }
    if (!ArtLayout::fromJson(*parsed, out)) {
        if (err) *err = "missing required fields in layout json";
        return false;
    }
    out.source = "calibrated(" + path + ")";
    return true;
}

bool saveLayoutFile(const std::string& path, const ArtLayout& layout, std::string* err) {
    std::string tmpPath = path + ".tmp." + std::to_string(::getpid());
    int fd = ::open(tmpPath.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) {
        if (err) *err = std::string("open ") + tmpPath + ": " + std::strerror(errno);
        return false;
    }
    ::fchmod(fd, 0600);
    std::string body = layout.toJson().dumpPretty(2) + "\n";
    size_t written = 0;
    while (written < body.size()) {
        ssize_t w = ::write(fd, body.data() + written, body.size() - written);
        if (w < 0) {
            if (errno == EINTR) continue;
            if (err) *err = std::string("write ") + tmpPath + ": " + std::strerror(errno);
            ::close(fd);
            ::unlink(tmpPath.c_str());
            return false;
        }
        written += static_cast<size_t>(w);
    }
    ::fsync(fd);
    ::close(fd);
    if (::rename(tmpPath.c_str(), path.c_str()) != 0) {
        if (err) *err = std::string("rename to ") + path + ": " + std::strerror(errno);
        ::unlink(tmpPath.c_str());
        return false;
    }
    ::chmod(path.c_str(), 0600);
    return true;
}

} // namespace artseek
