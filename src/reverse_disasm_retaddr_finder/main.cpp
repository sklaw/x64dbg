#include "cstdio"
#include "disasm_helper.h"
#include "disasm_fast.h"
#include <set>
#define FILEPATH_MAX 1000

struct ret_addr_id_stat
{
    int picked_ret_addr_index_set_predretaddrcount;
    int picked_ret_addr_index_set_size;
    int picked_non_symbo_non_retaddr_index_set_predretaddrcount;
    int picked_non_symbo_non_retaddr_index_set_size;
    int picked_symbol_index_set_predretaddrcount;
    int picked_symbol_index_set_size;
};

void read_txt_file_of_int_array_sep_by_space(const char* path, std::set<int> & s)
{
    FILE* f;
    fopen_s(&f, path, "r");
    assert(f != NULL);

    int tmp;
    while(fscanf_s(f, "%d ", &tmp) != EOF)
    {
        // printf("%d\n", tmp);
        s.insert(tmp);
    };
}

void read_binary_file_into_char_array(const char* path, char** buffer_ptr, int* buffer_size)
{
    FILE* fp;
    long lSize;

    fopen_s(&fp, path, "rb");
    assert(fp != NULL);

    fseek(fp, 0L, SEEK_END);
    lSize = ftell(fp);
    *buffer_size = lSize;

    rewind(fp);

    /* allocate memory for entire content */
    *buffer_ptr = (char*)calloc(1, lSize + 1);
    if(!*buffer_ptr) fclose(fp), fputs("memory alloc fails", stderr), exit(1);

    /* copy the file into the buffer */
    if(1 != fread(*buffer_ptr, lSize, 1, fp))
        fclose(fp), free(*buffer_ptr), fputs("entire read fails", stderr), exit(1);

}


bool is_retaddr(const char* memoy_bytes, int idx)
{
    unsigned char disasmData[256];

    duint base_va = 0;
    duint offset = idx;
    duint va = base_va + offset;


    duint base = base_va;
    duint data = va; // data in stack that is possibly a return address
    duint readStart = data - 16 * 4;
    if(readStart < base)
        readStart = base;

    // Mock: bool succeed = DbgMemRead(readStart, disasmData, sizeof(disasmData));
    for(int i = 0; i < sizeof(disasmData); i++)
    {
        disasmData[i] = memoy_bytes[readStart + i];
    }


    duint prev = disasmback(disasmData, 0, sizeof(disasmData), data - readStart, 1);
    duint previousInstr = readStart + prev;

    BASIC_INSTRUCTION_INFO basicinfo;
    bool valid = disasmfast(disasmData + prev, previousInstr, &basicinfo);
    if(valid && basicinfo.call)
    {
        return true;
    }
    else
    {
        return false;
    }
}


void process_dataset(const char* path, struct ret_addr_id_stat* ret_addr_id_stat_ptr)
{
    char* memoy_bytes;
    int memoy_bytes_length;
    std::set<int> picked_non_symbo_non_retaddr_index_set;
    std::set<int> picked_ret_addr_index_set;
    std::set<int> picked_symbol_index_set;

    char memoy_bytes_file_path[FILEPATH_MAX];
    char picked_non_symbo_non_retaddr_index_set_file_path[FILEPATH_MAX];
    char picked_ret_addr_index_set_file_path[FILEPATH_MAX];
    char picked_symbol_index_set_file_path[FILEPATH_MAX];

    sprintf_s(memoy_bytes_file_path, "%s\\%s\\%s", path, "meta_info", "memory_bytes");
    sprintf_s(picked_non_symbo_non_retaddr_index_set_file_path, "%s\\%s\\%s", path, "meta_info\\validation_set", "picked_non_symbo_non_retaddr_index_set");
    sprintf_s(picked_ret_addr_index_set_file_path, "%s\\%s\\%s", path, "meta_info\\validation_set", "picked_ret_addr_index_set");
    sprintf_s(picked_symbol_index_set_file_path, "%s\\%s\\%s", path, "meta_info\\validation_set", "picked_symbol_index_set");

    printf("%s\n", memoy_bytes_file_path);
    printf("%s\n", picked_non_symbo_non_retaddr_index_set_file_path);
    printf("%s\n", picked_ret_addr_index_set_file_path);
    printf("%s\n", picked_symbol_index_set_file_path);

    read_binary_file_into_char_array(memoy_bytes_file_path, &memoy_bytes, &memoy_bytes_length);
    read_txt_file_of_int_array_sep_by_space(picked_non_symbo_non_retaddr_index_set_file_path, picked_non_symbo_non_retaddr_index_set);
    read_txt_file_of_int_array_sep_by_space(picked_ret_addr_index_set_file_path, picked_ret_addr_index_set);
    read_txt_file_of_int_array_sep_by_space(picked_symbol_index_set_file_path, picked_symbol_index_set);

    printf("memoy_bytes size = %d\n", memoy_bytes_length);
    printf("picked_ret_addr_index_set size = %d\n", picked_ret_addr_index_set.size());
    printf("picked_symbol_index_set size = %d\n", picked_symbol_index_set.size());
    printf("picked_non_symbo_non_retaddr_index_set size = %d\n", picked_non_symbo_non_retaddr_index_set.size());

    int picked_ret_addr_index_set_predretaddrcount = 0;
    for(int idx : picked_ret_addr_index_set)
    {
        if(is_retaddr(memoy_bytes, idx))
        {
            picked_ret_addr_index_set_predretaddrcount++;
        }
    }

    int picked_non_symbo_non_retaddr_index_set_predretaddrcount = 0;
    for(int idx : picked_non_symbo_non_retaddr_index_set)
    {
        if(is_retaddr(memoy_bytes, idx))
        {
            picked_non_symbo_non_retaddr_index_set_predretaddrcount++;
        }
    }


    int picked_symbol_index_set_predretaddrcount = 0;
    for(int idx : picked_symbol_index_set)
    {
        if(is_retaddr(memoy_bytes, idx))
        {
            picked_symbol_index_set_predretaddrcount++;
        }
    }


    printf("picked_ret_addr_index_set_predretaddrcount = %d/%d\n", picked_ret_addr_index_set_predretaddrcount, picked_ret_addr_index_set.size());
    printf("picked_non_symbo_non_retaddr_index_set_predretaddrcount = %d/%d\n", picked_non_symbo_non_retaddr_index_set_predretaddrcount, picked_non_symbo_non_retaddr_index_set.size());
    printf("picked_symbol_index_set_predretaddrcount = %d/%d\n", picked_symbol_index_set_predretaddrcount, picked_symbol_index_set.size());

    ret_addr_id_stat_ptr->picked_ret_addr_index_set_predretaddrcount   +=  picked_ret_addr_index_set_predretaddrcount;
    ret_addr_id_stat_ptr->picked_ret_addr_index_set_size        +=  picked_ret_addr_index_set.size();
    ret_addr_id_stat_ptr->picked_non_symbo_non_retaddr_index_set_predretaddrcount  +=  picked_non_symbo_non_retaddr_index_set_predretaddrcount;
    ret_addr_id_stat_ptr->picked_non_symbo_non_retaddr_index_set_size       +=  picked_non_symbo_non_retaddr_index_set.size();
    ret_addr_id_stat_ptr->picked_symbol_index_set_predretaddrcount     +=  picked_symbol_index_set_predretaddrcount;
    ret_addr_id_stat_ptr->picked_symbol_index_set_size          +=  picked_symbol_index_set.size();
}

int main()
{
    const char* datasets[] =
    {
        "G:\\My Drive\\828w_project_dataset\\real\\16_1234_kernel32.dll_1250",
        "G:\\My Drive\\828w_project_dataset\\real\\16_1234_mscoree.dll_1250",
        "G:\\My Drive\\828w_project_dataset\\real\\16_1234_ntdll.dll_1250"
    };

    struct ret_addr_id_stat s;
    memset(&s, 0, sizeof(s));

    int num_datasets = sizeof(datasets) / sizeof(datasets[0]);
    printf("%d datasets to process:\n", num_datasets);
    for(int i = 0; i < num_datasets; i++)
    {
        printf("%s\n", datasets[i]);
        process_dataset(datasets[i], &s);
    }

    int not_ret_addr_total = s.picked_non_symbo_non_retaddr_index_set_size + s.picked_symbol_index_set_size;
    int not_ret_addr_false_negative = s.picked_non_symbo_non_retaddr_index_set_predretaddrcount + s.picked_symbol_index_set_predretaddrcount;
    int not_ret_addr_true_positive = not_ret_addr_total - not_ret_addr_false_negative;

    int ret_addr_total = s.picked_ret_addr_index_set_size;
    int ret_addr_true_positive = s.picked_ret_addr_index_set_predretaddrcount;
    int ret_addr_false_negative = ret_addr_total - ret_addr_true_positive;

    printf("%5d/%5d\t%5d/%5d\n",
           not_ret_addr_true_positive,
           not_ret_addr_total,
           ret_addr_false_negative,
           ret_addr_total
          );
    printf("%5d/%5d\t%5d/%5d\n",
           not_ret_addr_false_negative,
           not_ret_addr_total,
           ret_addr_true_positive,
           ret_addr_total
          );

    return 0;


}