#include <string>
#include <cctype>
#include <sstream>
#include <vector>
#include "zeek/util.h"
#include "zeek/net_util.h"
#include "zeek/ZeekString.h"
#include "zeek/Val.h"
#include "zeek/ZVal.h"
#include "zeek/Conn.h"
#include "zeek/analyzer/protocol/ssl/SSL.h"


#include "helpers.h"
#include "ja4.h"
#include "ssl-consts.h"

std::vector<std::string> convert_string_vector(const zeek::IntrusivePtr<zeek::VectorVal>& vec_val)
{
    std::vector<std::string> result;
    if ( ! vec_val )
        return result;

    auto length = vec_val->Size();
    result.reserve(length);

    for ( int i = 0; i < length; ++i )
    {
        auto element_val = vec_val->ValAt(i);
        if ( ! element_val )
            continue;

        auto str_val = cast_intrusive<zeek::StringVal>(element_val);
        if ( ! str_val )
            continue;

        result.push_back(str_val->AsString()->ToStdString());
    }

    return result;
}


std::vector<uint32_t> convert_count_vector_to_u32(const zeek::IntrusivePtr<zeek::VectorVal>& vec_val)
{
    std::vector<uint32_t> result;
    if ( ! vec_val )
        return result;

    auto length = vec_val->Size();
    result.reserve(length);

    for ( int i = 0; i < length; ++i )
    {
        auto element_val = vec_val->ValAt(i);
        if ( ! element_val )
            continue;

        auto int_val = cast_intrusive<zeek::IntVal>(element_val);
        if ( ! int_val )
            continue;

        uint64_t full_value = int_val->AsCount();

        // Optional safety check to avoid overflow
        if ( full_value > UINT32_MAX ) {
            fprintf(stderr, "Warning: count %llu too large for uint32_t\n",
                    static_cast<unsigned long long>(full_value));
            continue;
        }

        result.push_back(static_cast<uint32_t>(full_value));
    }

    return result;
}


std::string b_hash(std::vector<uint32_t> input) {
    return FINGERPRINT::sha256_or_null__12(
        FINGERPRINT::vector_of_count_to_str(input)
    );
}

std::string c_hash(std::string input) { 
    return FINGERPRINT::sha256_or_null__12(input);
}

std::string make_a(TransportProto transport_proto, std::string conn_service, std::vector<std::string> sni, std::vector<std::string> alpns, std::vector<uint32_t> cipher_suites,
                    std::vector<uint32_t> extension_codes, int version) {
    // Get SSL protocol type
    std::string proto_for_hash = "0";
    if (transport_proto == TransportProto::TRANSPORT_UDP && 
        conn_service.find("QUIC") != std::string::npos) {
        proto_for_hash = "q";
    } else if (conn_service.find("DTLS") != std::string::npos){
        proto_for_hash = "d";
    } else {
        proto_for_hash = "t"; // Assume TCP
    }

    // TLS version mapping
    std::string version_for_hash = "00";
    auto it = TLS_VERSION_MAPPER.find(version);
    if (it != TLS_VERSION_MAPPER.end()) {
        version_for_hash = it->second;
    }

    // Determine SNI status
    std::string sni_for_hash = "i";
    if (!sni.empty()) {
        sni_for_hash = "d";
    }

    // Cipher suite count, max 99
    std::ostringstream cs_stream;
    int cs_size = static_cast<uint32_t>(cipher_suites.size());
    if (cs_size > 99)
        cs_stream << "99";
    else
        cs_stream << std::setw(2) << std::setfill('0') << cs_size;
    std::string cs_count_for_hash = cs_stream.str();

    // Extension count, max 99
    std::ostringstream ec_stream;
    int ec_size = static_cast<uint32_t>(extension_codes.size());
    if (ec_size > 99)
        ec_stream << "99";
    else
        ec_stream << std::setw(2) << std::setfill('0') << ec_size;
    std::string ec_count_hash = ec_stream.str();


    // Get ALPN first and last character
    std::string alpn_for_hash = "00";
    if (!alpns.empty() && !alpns[0].empty()){
        const std::string& first_alpn = {alpns[0][0]};
        const std::string& last_alpn = {alpns[0].back()};
        alpn_for_hash = first_alpn.substr(0, 1) + last_alpn.substr(last_alpn.size() - 1, 1);
    }

    // Assemble JA4_a string
    std::string a = proto_for_hash + version_for_hash + sni_for_hash + cs_count_for_hash + ec_count_hash + alpn_for_hash;
    return a;
}

zeek::ValPtr do_ja4(zeek::RecordVal* conn_record, zeek::StringVal* delimiter) {

    // JA4Info ja4_return_value;

    const zeek::String* zstr = delimiter->AsStringVal()->AsString();
    std::string delimiter_val(reinterpret_cast<const char*>(zstr->Bytes()), zstr->Len());


    auto ja4_return_value_type = zeek::id::find_type<zeek::RecordType>("FINGERPRINT::JA4::Info");
    auto ja4_return_value = zeek::make_intrusive<zeek::RecordVal>(ja4_return_value_type);

    auto fingerprint = cast_intrusive<zeek::RecordVal>(conn_record->GetField("fp"));

    int sni_exists = fingerprint->HasField("sni");
    std::vector<std::string> sni;
    if (sni_exists == false){
        sni = std::vector<std::string>();
    }
    else {
        auto sni_val = fingerprint->GetField("sni");
        auto sni_vec = cast_intrusive<zeek::VectorVal>(sni_val);
        sni = convert_string_vector(sni_vec);
    }

    std::vector<std::string> alpns;
    auto alpns_exists = fingerprint->HasField("alpns");
    if (alpns_exists == false){
        alpns = std::vector<std::string>();
    }
    else {
        auto alpns_val = fingerprint->GetField("alpns");
        auto alpns_vec = cast_intrusive<zeek::VectorVal>(alpns_val);
        alpns = convert_string_vector(alpns_vec);
    }

    std::vector<uint32_t> cipher_suites;
    auto cipher_suites_exists = fingerprint->HasField("cipher_suites");
    if (cipher_suites_exists == false){
        cipher_suites = std::vector<uint32_t>();
    }
    else {
        auto cipher_suites_val = fingerprint->GetField("cipher_suites");
        auto cipher_suites_vec = cast_intrusive<zeek::VectorVal>(cipher_suites_val);
        cipher_suites = convert_count_vector_to_u32(cipher_suites_vec);
    }

    std::vector<uint32_t> extension_codes;
    auto extension_codes_exists = fingerprint->HasField("cipher_suites");
    if (extension_codes_exists == false){
        extension_codes = std::vector<uint32_t>();
    }
    else {
        auto extension_codes_val = fingerprint->GetField("extension_codes");
        auto extension_codes_vec = cast_intrusive<zeek::VectorVal>(extension_codes_val);
        extension_codes = convert_count_vector_to_u32(extension_codes_vec);
    }

    uint32_t version = 0;
    auto version_exists = fingerprint->HasField("version"); 
    if (version_exists == false){
        version = 0;
    }
    else {
        auto version_val = fingerprint->GetField("version");
        version = static_cast<uint32_t>(zeek::cast_intrusive<zeek::IntVal>(version_val)->AsCount());
    }
   
    std::vector<uint32_t> signature_algos;
    auto signature_algos_exists = fingerprint->HasField("cipher_suites");
    if (signature_algos_exists == false){
        signature_algos = std::vector<uint32_t>();
    }
    else {
        auto signature_algos_val = fingerprint->GetField("signature_algos");
        auto signature_algos_vec = cast_intrusive<zeek::VectorVal>(signature_algos_val);
        auto signature_algos = convert_count_vector_to_u32(signature_algos_vec);
    }

    auto service_str_value = zeek::cast_intrusive<zeek::StringVal>(conn_record->GetField("service"));
    std::string service = service_str_value->AsString()->ToStdString();

    auto protocol_value = conn_record->GetField("proto");
    auto protocol_enum_val = zeek::cast_intrusive<zeek::EnumVal>(protocol_value);
    int tag = static_cast<int>(protocol_enum_val->AsInt());

    TransportProto transport_proto = static_cast<TransportProto>(tag);

        
    std::string ja4_a = make_a(transport_proto, service, sni, alpns, cipher_suites, extension_codes, version);
    std::vector<uint32_t> ja4_b = cipher_suites; 


    // Filtered extensions (excluding SNI and ALPN)
    std::vector<uint32_t> extensions;
    uint32_t code;
    for (int i = 0; i < extension_codes.size(); i++) {
        code = extension_codes[i];
        if (code == SSLExtension::SSL_EXTENSION_SERVER_NAME || code == SSLExtension::SSL_EXTENSION_APPLICATION_LAYER_PROTOCOL_NEGOTIATION) continue;
        extensions.push_back(code);
    }

    std::string ja4_c = FINGERPRINT::vector_of_count_to_str(
        FINGERPRINT::order_vector_of_count(extensions)
    );

    if (!signature_algos.empty()) {
        ja4_c += delimiter_val;
        ja4_c += FINGERPRINT::vector_of_count_to_str(signature_algos);
    }

    // ja4
    std::string ja4_string = ja4_a + delimiter_val +
                             b_hash(FINGERPRINT::order_vector_of_count(ja4_b)) +
                             delimiter_val + c_hash(ja4_c);

    ja4_return_value->Assign(1, zeek::make_intrusive<zeek::StringVal>(ja4_string));

    // ja4_r
    std::string ja4_r = ja4_a + delimiter_val +
                        FINGERPRINT::vector_of_count_to_str(FINGERPRINT::order_vector_of_count(ja4_b)) +
                        delimiter_val + ja4_c;
    
    ja4_return_value->Assign(3, zeek::make_intrusive<zeek::StringVal>(ja4_r));

    // ja4_o
    ja4_c = FINGERPRINT::vector_of_count_to_str(extension_codes);
    if (signature_algos.empty()) {
        ja4_c += delimiter_val;
        ja4_c += FINGERPRINT::vector_of_count_to_str(signature_algos);
    }

    std::string ja4_o = ja4_a + delimiter_val +
                        b_hash(ja4_b) + delimiter_val + c_hash(ja4_c);
    ja4_return_value->Assign(2, zeek::make_intrusive<zeek::StringVal>(ja4_o));

    // ja4_ro
    std::string ro = ja4_a + delimiter_val +
                    FINGERPRINT::vector_of_count_to_str(ja4_b) + delimiter_val + ja4_c;

    ja4_return_value->Assign(4, zeek::make_intrusive<zeek::StringVal>(ro));

    delete zstr;
    delete conn_record;
    delete delimiter;

    return ja4_return_value;
}

    // Optional: logging
    // Log::write(FINGERPRINT::JA4::LOG, c.fp->ja4);