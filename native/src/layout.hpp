#pragma once

#include "json.hpp"
#include <cstdint>
#include <string>

namespace artseek {

struct ArtLayout {
    uint64_t obj_header = 8;
    uint64_t klass_off = 0;
    uint64_t heap_ref_sz = 4;

    uint64_t str_count = 8;
    uint64_t str_hash = 12;
    uint64_t str_data = 16;

    uint64_t cls_dex_cache = 16;
    uint64_t cls_name = 28;
    uint64_t cls_super = 32;
    uint64_t cls_ifields = 40;
    uint64_t cls_sfields = 56;
    uint64_t cls_access = 64;
    uint64_t cls_class_flags = 68;
    uint64_t cls_class_size = 72;
    uint64_t cls_dex_class_def = 80;
    uint64_t cls_dex_type_idx = 84;
    uint64_t cls_num_ref_inst = 88;
    uint64_t cls_obj_size = 96;
    uint64_t cls_obj_size_fast = 100;
    uint64_t cls_prim_type = 104;
    uint64_t cls_status = 112;

    uint64_t dc_dex_file = 16;

    uint64_t af_stride = 16;
    uint64_t af_decl = 0;
    uint64_t af_dex = 8;
    uint64_t af_off = 12;
    uint64_t af_access = 4;

    uint32_t inst_size = 0;
    std::string fingerprint;
    std::string source = "builtin";

    Json toJson() const;
    Json toNumericMap() const;
    static bool fromJson(const Json& j, ArtLayout& out);
};

std::string readBuildFingerprint();
bool ensureCacheDir(const std::string& dir, std::string* err = nullptr);
bool loadLayoutFile(const std::string& path, ArtLayout& out, std::string* err = nullptr);
bool saveLayoutFile(const std::string& path, const ArtLayout& layout, std::string* err = nullptr);

} // namespace artseek
