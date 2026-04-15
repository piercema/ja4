#pragma once

#include <cstring>
#include <cctype>
#include <string>
#include <vector>
#include "zeek/Val.h"

namespace FINGERPRINT {
    std::string vector_of_count_to_str(const std::vector<uint32_t>& input,
        const std::string& format_str = "%04x",
        const std::string& dlimit = ",");
    std::string vector_of_str_to_str(const std::vector<std::string>& input,
        const std::string& format_str = "%s",
        const std::string& dlimit = ",");
    std::vector<uint32_t> order_vector_of_count(const std::vector<uint32_t>& input);
    uint32_t make_quadword(uint8_t byte1, uint8_t byte2);
    std::string sha256_or_null__12(std::string input);
    std::string TableToJSONString(const zeek::TableVal* table);
    std::vector<std::string> convert_string_vector(const zeek::IntrusivePtr<zeek::VectorVal>& vec_val);
    std::vector<uint32_t> convert_count_vector_to_u32(const zeek::IntrusivePtr<zeek::VectorVal>& vec_val);
}
