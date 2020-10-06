/* PANDABEGINCOMMENT
 *
 *  Authors:
 *  Tiemoko Ballo           N/A
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 * See the COPYING file in the top-level directory.
 *
PANDAENDCOMMENT */

// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS

#include <map>
#include <unordered_map>
#include <vector>
#include <algorithm>
#include <iostream>
#include <fstream>
#include <string>
#include <jsoncpp/json/json.h>

#include "panda/plugin.h"
#include "panda/common.h"

#include "dwarf_query.h"
#include "dwarf_query_int_fns.h"

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {
    bool init_plugin(void *);
    void uninit_plugin(void *);
}

// Globals -------------------------------------------------------------------------------------------------------------

bool log_verbose;
std::unordered_map<std::string, StructDef> struct_hashtable;
std::map<unsigned, std::string> func_hashtable;

// External API --------------------------------------------------------------------------------------------------------

// TODO: rework to assign to result and free at end!

// Read struct member from memory
// bool indicates read successes (account for paging errors) and type conversion success
// PrimitiveVariant provides a typed copy of the data
std::pair<bool, PrimitiveVariant> read_member(CPUState *env, target_ulong addr, ReadableDataType rdt) {

    std::pair<bool, PrimitiveVariant> result;

    uint8_t* buf = (uint8_t*)malloc(rdt.size_bytes);
    assert(buf != NULL);

    int read_res = panda_virtual_memory_read(env, addr, buf, rdt.size_bytes);
    if (read_res != 0) {
        std::cerr << "[WARNING] dwarf_query: virt read of member \'" << rdt.name << "\' failed!" << std::endl;
        return std::make_pair(false, 0);
    }

    switch (rdt.type) {

        case DataType::VOID:
            std::cerr << "[WARNING] dwarf_query: cannot virt read void member \'" << rdt.name << "\'" << std::endl;
            result = std::make_pair(false, 0);

        case DataType::BOOL:
            bool res = *buf;
            free(buf);
            result = std::make_pair(true, res);

        case DataType::CHAR:
            char res = *buf;
            free(buf);
            result = std::make_pair(true, res);

        case DataType::INT:
            if (rdt.is_signed) {
                switch (rdt.size_bytes) {
                    case sizeof(int):
                        int res = *buf;
                        free(buf);
                        result = std::make_pair(true, res);
                    case sizeof(long int):
                        long int res = *buf;
                        free(buf);
                        result = std::make_pair(true, res);
                    case sizeof(long long int):
                        long long int res = *buf;
                        free(buf);
                        result = std::make_pair(true, res);
                    default:
                        std::cerr << "[WARNING] dwarf_query: cannot virt read int member \'" << rdt.name << "\', bad size!" << std::endl;
                        free(buf);
                        result = std::make_pair(false, 0);
                }
            } else {
                switch (rdt.size_bytes) {
                    case sizeof(unsigned):
                        unsigned rest = *buf;
                        free(buf);
                        result = std::make_pair(true, res);
                    case sizeof(long unsigned):
                        long unsigned rest = *buf;
                        free(buf);
                        result = std::make_pair(true, res);
                    case sizeof(long long unsigned):
                        long long unsigned rest = *buf;
                        free(buf);
                        return std::make_pair(true, res);
                    default:
                        std::cerr << "[WARNING] dwarf_query: cannot virt read unsigned member \'" << rdt.name << "\', bad size!" << std::endl;
                        free(buf);
                        result = std::make_pair(false, 0);
                }
            }

        case DataType::FLOAT:
            switch (rdt.size_bytes) {
                case sizeof(float):
                    float res = *buf;
                    free(buf);
                    result = std::make_pair(true, res);
                case sizeof(double):
                    double res = *buf;
                    free(buf);
                    result = std::make_pair(true, res);
                case sizeof(long double):
                    long double res = *buf;
                    free(buf);
                    result = std::make_pair(true, res);
                default:
                    std::cerr << "[WARNING] dwarf_query: cannot virt read float member \'" << rdt.name << "\', bad size!" << std::endl;
                    free(buf);
                    result = std::make_pair(false, 0);
            }

        case DataType::STRUCT:
            result = std::make_pair(true, res); // Caller must free (gets uint8_t*)

        case DataType::FUNC:
            target_ulong res = *buf;
            free(buf);
            return std::make_pair(true, res);

        case DataType::ARRAY:
            std::cerr << "[WARNING] dwarf_query: virt read of array not yet supported! Cannot read \'" << rdt.name << "\'" << std::endl;
            free(buf);
            return std::make_pair(false, 0);

        case DataType::UNION:
            std::cerr << "[WARNING] dwarf_query: virt read of union not yet supported! Cannot read \'" << rdt.name << "\'" << std::endl;
            free(buf);
            return std::make_pair(false, 0);

        case DataType::ENUM:
            std::cerr << "[WARNING] dwarf_query: virt read of enum not yet supported! Cannot read \'" << rdt.name << "\'" << std::endl;
            free(buf);
            return std::make_pair(false, 0);

        default:
            std::cerr << "[WARNING] dwarf_query: cannot virt read member \'" << rdt.name << "\', unknown type!" << std::endl;
            return std::make_pair(false, 0);
    }

    std::cerr << "[WARNING] dwarf_query: cannot virt read member \'" << rdt.name << "\'" << std::endl;
    free(buf);
    return std::make_pair(false, 0);
}

// Core ----------------------------------------------------------------------------------------------------------------

// TODO: handle UNIONS

DataType str_to_dt(std::string const& kind) {
    if (kind.compare(void_str) == 0) {
        return DataType::VOID;
    } else if (kind.compare(bool_str) == 0) {
        return DataType::BOOL;
    } else if (kind.find(char_str) != std::string::npos) {
        return DataType::CHAR;
    } else if (kind.find(int_str) != std::string::npos) {
        return DataType::INT;
    } else if (kind.find(float_str) != std::string::npos) {
        return DataType::FLOAT;
    } else if (kind.find(double_str) != std::string::npos) {
        return DataType::FLOAT;
    } else if (kind.compare(struct_str) == 0) {
        return DataType::STRUCT;
    } else if (kind.compare(func_str) == 0) {
        return DataType::FUNC;
    } else if (kind.compare(array_str) == 0) {
        return DataType::ARRAY;
    } else if (kind.compare(union_str) == 0) {
        return DataType::UNION;
    } else if (kind.compare(enum_str) == 0) {
        return DataType::ENUM;
    } else {
        std::cerr << "[FATAL ERROR] dwarf_query: Unknown kind \'" << kind << "\', no mapping to DataType!" << std::endl;
        assert(false);
    }
}

// Lift JSON entry to CPP class
ReadableDataType member_to_rdt(const std::string& member_name, const Json::Value& member, const Json::Value& root) {

    ReadableDataType rdt = ReadableDataType(member_name);
    std::string type_category = member["type"]["kind"].asString();
    std::string type_name = member["type"]["name"].asString();
    Json::Value type_info = root["base_types"][type_name];

    // TODO: Cleanup with seperate func and switch statement, doesn not map to DataType exactly
    bool ptr_type = (type_category.compare(ptr_str) == 0);
    bool struct_type = (type_category.compare(struct_str) == 0);
    bool array_type = (type_category.compare(array_str) == 0);
    bool bitfield_type = (type_category.compare(bitfield_str) == 0);
    bool enum_type = (type_category.compare(enum_str) == 0);
    bool union_type = (type_category.compare(union_str) == 0);
    assert((ptr_type + struct_type + array_type + bitfield_type + enum_type + union_type) <= 1);

    // Offset
    rdt.offset_bytes = member["offset"].asUInt();

    // Embedded struct
    if (struct_type) {

        rdt.size_bytes = root["user_types"][member_name]["size"].asUInt();
        rdt.is_le = (root["base_types"]["pointer"]["endian"].asString().compare(little_str) == 0);
        rdt.type = DataType::STRUCT;
        rdt.is_ptr = false;
        rdt.is_double_ptr = false;
        rdt.is_signed = false;
        rdt.is_valid = true;

    // Embedded array
    } else if (array_type) {

        std::string arr_type_kind = member["type"]["subtype"]["kind"].asString();
        std::string arr_type_name = member["type"]["subtype"]["name"].asString();

        // Array of primitives
        if (arr_type_kind.compare(base_str) == 0) {
            rdt.arr_member_type = str_to_dt(arr_type_name);
            rdt.arr_member_size_bytes = root["base_types"][arr_type_name]["size"].asUInt();
            type_info = root["base_types"][arr_type_name];

        // Array of pointers
        } else if (arr_type_kind.compare(ptr_str) == 0) {
            rdt.arr_member_type = str_to_dt("unsigned int");
            rdt.arr_member_size_bytes = root["base_types"][arr_type_kind]["size"].asUInt();
            type_info = root["base_types"][arr_type_kind];

        // Array of arrays
        } else if (arr_type_kind.compare(array_str) == 0) {

            // TODO: add 2D array support
            std::cerr << "[WARNING] dwarf_query: 2D array support not yet implemented, skipping member \'" << member_name << "\'" << std::endl;
            rdt.is_valid = false;
            return rdt;

            /*
            rdt.arr_member_type = str_to_dt(arr_type_kind);
            int first_dimension_size =  member["type"]["count"].asUint();
            int second_dimension_size =  member["type"]["subtype"]["count"].asUint();
            // TODO:
            // 1. Get base elemsize
            // 2. Compute arr_member_size
            // 3. Determine type_info
            */

        // Array of enums
        } else if (arr_type_kind.compare(enum_str) == 0) {

            // TODO: add enum array support
            std::cerr << "[WARNING] dwarf_query: enum array support not yet implemented, skipping member \'" << member_name << "\'" << std::endl;
            rdt.is_valid = false;
            return rdt;

        // Array of structs
        } else {
            rdt.arr_member_type = str_to_dt(arr_type_kind);
            rdt.arr_member_size_bytes = root["user_types"][arr_type_name]["size"].asUInt();
            rdt.arr_member_name.assign(arr_type_name);
            type_info = root["user_types"][arr_type_name];
        }

        rdt.size_bytes = (type_info["size"].asUInt() * member["type"]["count"].asUInt());
        rdt.is_le = (type_info["endian"].asString().compare(little_str) == 0);
        rdt.type = DataType::ARRAY;
        rdt.is_ptr = false;
        rdt.is_double_ptr = false;
        rdt.is_signed = type_info["signed"].asBool();
        rdt.is_valid = true;

        assert(rdt.get_arr_size() == member["type"]["count"].asUInt());

    // Embedded bitfield
    } else if (bitfield_type) {

        // TODO: add bitfield support
        std::cerr << "[WARNING] dwarf_query: bitfield support not yet implemented, skipping member \'" << member_name << "\'" << std::endl;
        rdt.is_valid = false;
        return rdt;

    // Embedded union
    } else if (union_type) {

        // TODO: add enum support
        std::cerr << "[WARNING] dwarf_query: union support not yet implemented, skipping member \'" << member_name << "\'" << std::endl;
        rdt.is_valid = false;
        return rdt;

    // Enum
    } else if (enum_type) {

        // TODO: add union support
        std::cerr << "[WARNING] dwarf_query: enum support not yet implemented, skipping member \'" << member_name << "\'" << std::endl;
        rdt.is_valid = false;
        return rdt;

    // Struct pointer, function pointer, or primitive datatype
    } else {

        // Pointer
        if (ptr_type) {

            std::string subtype_kind = member["type"]["subtype"]["kind"].asString();
            std::string subtype_name = member["type"]["subtype"]["name"].asString();

            // TODO: Cleanup with seperate func and switch statement, doesn not map to DataType exactly
            bool struct_ptr = (subtype_kind.compare(struct_str) == 0);
            bool double_ptr = (subtype_kind.compare(ptr_str) == 0);
            bool func_ptr = (subtype_kind.compare(func_str) == 0);
            bool union_ptr = (subtype_kind.compare(union_str) == 0);
            bool arr_ptr = (subtype_kind.compare(array_str) == 0);

            bool void_ptr = (subtype_kind.compare(base_str) == 0)
                && (subtype_name.compare(void_str) == 0);

            bool prim_ptr = (subtype_kind.compare(base_str) == 0)
                && (!(root["base_types"][subtype_name].isNull()))
                && (subtype_name.compare(void_str) != 0);

            assert((double_ptr + struct_ptr + func_ptr + union_ptr + arr_ptr + void_ptr + prim_ptr) == 1);

            // Pointer to stuct (named)
            if (struct_ptr) {
                rdt.type = DataType::STRUCT;
                rdt.ptr_trgt_name.assign(subtype_name);

            // Pointer to function (named)
            } else if (func_ptr) {
                rdt.type = DataType::FUNC;
                rdt.ptr_trgt_name.assign(subtype_name);

            // Pointer to union (named)
            } else if (union_ptr) {
                rdt.type = DataType::UNION;
                rdt.ptr_trgt_name.assign(subtype_name);

            // Pointer to array (unnamed)
            } else if (arr_ptr) {
                rdt.type = DataType::ARRAY;

            // Void pointer (unnamed)
            } else if (void_ptr) {
                rdt.type = DataType::VOID;

            // Pointer to primitive (unnamed)
            } else if (prim_ptr) {
                rdt.type = str_to_dt(subtype_name);

            // Double pointer to struct/function (named) or primitive (unnamed)
            } else if (double_ptr) {
                std::string trgt_type_kind = member["type"]["subtype"]["subtype"]["kind"].asString();
                std::string trgt_type_name = member["type"]["subtype"]["subtype"]["name"].asString();
                rdt.is_double_ptr = true;
                if (trgt_type_kind.compare(base_str) == 0) {
                    rdt.type = str_to_dt(trgt_type_name);
                } else {
                    rdt.type = str_to_dt(trgt_type_kind);
                    rdt.ptr_trgt_name.assign(trgt_type_name);
                }
            }

            type_info = root["base_types"][type_category];
            rdt.is_ptr = true;

        // Primitive type
        } else {
            std::string kind = type_info["kind"].asString();
            rdt.is_ptr = false;
            rdt.is_double_ptr = false;
            rdt.type = str_to_dt(kind);
        }

        // Metadata for pointers, primitives
        if (!type_info.isNull()) {
            rdt.size_bytes = type_info["size"].asUInt();
            rdt.is_signed = type_info["signed"].asBool();
            rdt.is_le = (type_info["endian"].asString().compare(little_str) == 0);
            rdt.is_valid = true;
        } else {
            std::cerr << "[WARNING] dwarf_query: Cannot parse type info for \'" << member_name << "\'" << std::endl;
            rdt.is_valid = false;
        }
    }

    return rdt;
}

void load_struct(const std::string& struct_name, const Json::Value& struct_entry, const Json::Value& root) {

    // New struct
    StructDef sd = StructDef(struct_name);
    sd.size_bytes = struct_entry["size"].asUInt();

    // Fill struct member information
    for (auto const& member_name : struct_entry["fields"].getMemberNames()) {

        auto rdt = member_to_rdt(member_name, struct_entry["fields"][member_name], root);
        if (rdt.is_valid) {
            sd.members.push_back(rdt);
        }
    }

    // Sort by offset
    std::sort(
        sd.members.begin(),
        sd.members.end(),
        [](const ReadableDataType& x, const ReadableDataType& y) { return x.offset_bytes < y.offset_bytes; }
    );

    if (log_verbose) {
        std::cout << "Loaded " << sd << std::endl;
    }

    // Update global hashtable
    struct_hashtable[sd.name] = sd;
}

void load_func(const std::string& func_name, const Json::Value& func_entry, const Json::Value& root) {

    if ((func_entry["type"]["kind"].asString().compare(base_str) == 0)
        && (func_entry["type"]["name"].asString().compare(void_str) == 0)) {

        unsigned addr = func_entry["address"].asUInt();
        func_hashtable[addr] = func_name;

        if (log_verbose) {
            std::cout << "Loaded func \'" << func_name << "\' @ 0x" << std::hex << addr << std::dec << std::endl;
        }
    }
}

void load_json(const Json::Value& root) {

    unsigned struct_cnt = 0;
    unsigned func_cnt = 0;
    std::string struct_str("struct");

    // Load struct information
    for (auto sym_name : root["user_types"].getMemberNames()) {

        Json::Value sym = root["user_types"][sym_name];

        // Skip any zero-sized types
        if (sym["size"].asInt() > 0) {

            std::string type;

            // TODO: verify this is neccessary/correct?
            if (!sym["kind"].isNull()) {
                type.assign(sym["kind"].asString());
            } else if (!sym["type"]["kind"].isNull()) {
                type.assign(sym["type"]["kind"].asString());
            }

            if (type.compare(struct_str) == 0) {
                load_struct(sym_name, sym, root);
                struct_cnt++;
            }

        } else {
            std::cerr << "[WARNING] dwarf_query: Skipping zero-sized type \'" << sym_name << "\'" << std::endl;
        }
    }

    // Load function information
    for (auto sym_name : root["symbols"].getMemberNames()) {
        Json::Value sym = root["symbols"][sym_name];
        load_func(sym_name, sym, root);
        func_cnt++;
    }

    std::cout << std::endl << "Loaded " << func_cnt << " funcs, " << struct_cnt << " structs." << std::endl;
}

// Setup/Teardown ------------------------------------------------------------------------------------------------------

bool init_plugin(void *_self) {

    panda_arg_list *args = panda_get_args("dwarf_query");
    const char* json_filename = panda_parse_string_req(args, "json", "dwarf2json_output.json");
    log_verbose = panda_parse_bool(args, "verbose");
    std::ifstream ifs(json_filename);

    Json::Reader reader;
    Json::Value obj;

    if (!reader.parse(ifs, obj)) {
        std::cerr << "[ERROR] dwarf_query: invalid JSON!" << std::endl;
        return false;
    } else {
        load_json(obj);
    }

    switch (panda_os_familyno) {

        case OS_LINUX: {
           return true;
        } break;

        default: {
            std::cerr << "[WARNING] dwarf_query: This has never been tested for a non-Linux OS!" << std::endl;
            return true;
        }
    }
}

void uninit_plugin(void *_self) {
    // N/A
}