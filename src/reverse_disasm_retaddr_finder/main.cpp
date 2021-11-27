#include "cstdio"
#include "disasm_helper.h"
#include "disasm_fast.h"
#include <set>
#define FILEPATH_MAX 10000

bool MockDbgMemRead(duint index, void* dest, duint size)
{
    return false;
}

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

void process_dataset(const char* path)
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

    sprintf_s(memoy_bytes_file_path, "%s\\%s\\%s", path, "dataset_for_x64dbg", "memory_bytes");
    sprintf_s(picked_non_symbo_non_retaddr_index_set_file_path, "%s\\%s\\%s", path, "dataset_for_x64dbg", "picked_non_symbo_non_retaddr_index_set");
    sprintf_s(picked_ret_addr_index_set_file_path, "%s\\%s\\%s", path, "dataset_for_x64dbg", "picked_ret_addr_index_set");
    sprintf_s(picked_symbol_index_set_file_path, "%s\\%s\\%s", path, "dataset_for_x64dbg", "picked_symbol_index_set");

    printf("%s\n", memoy_bytes_file_path);
    printf("%s\n", picked_non_symbo_non_retaddr_index_set_file_path);
    printf("%s\n", picked_ret_addr_index_set_file_path);
    printf("%s\n", picked_symbol_index_set_file_path);

    read_binary_file_into_char_array(memoy_bytes_file_path, &memoy_bytes, &memoy_bytes_length);
    read_txt_file_of_int_array_sep_by_space(picked_non_symbo_non_retaddr_index_set_file_path, picked_non_symbo_non_retaddr_index_set);
    read_txt_file_of_int_array_sep_by_space(picked_ret_addr_index_set_file_path, picked_ret_addr_index_set);
    read_txt_file_of_int_array_sep_by_space(picked_symbol_index_set_file_path, picked_symbol_index_set);

    printf("memoy_bytes size = %d\n", memoy_bytes_length);
    printf("picked_non_symbo_non_retaddr_index_set size = %d\n", picked_non_symbo_non_retaddr_index_set.size());
    printf("picked_ret_addr_index_set size = %d\n", picked_ret_addr_index_set.size());
    printf("picked_symbol_index_set size = %d\n", picked_symbol_index_set.size());
}

int main()
{
    const char* datasets[] =
    {
        "C:\\Users\\test\\PycharmProjects\\828w_course_project\\828w_project_dataset\\real\\16_1234_mscorjit.dll_1000",
        "C:\\Users\\test\\PycharmProjects\\828w_course_project\\828w_project_dataset\\real\\16_1234_user32.dll_1000",
        "C:\\Users\\test\\PycharmProjects\\828w_course_project\\828w_project_dataset\\real\\16_1234_vbe7.dll_1000"
    };


    int num_datasets = sizeof(datasets) / sizeof(datasets[0]);
    printf("%d datasets to process:\n", num_datasets);
    for(int i = 0; i < num_datasets; i++)
    {
        printf("%s\n", datasets[i]);
        process_dataset(datasets[i]);
    }

    return 0;

    unsigned char disasmData[256];

    duint base_va = 123;
    duint offset = 345;

    duint va = base_va + offset;


    duint base = base_va;
    duint data = va;
    duint readStart = data - 16 * 4;
    if(readStart < base)
        readStart = base;

    bool succeed = MockDbgMemRead(readStart, disasmData, sizeof(disasmData));

    duint prev = disasmback(disasmData, 0, sizeof(disasmData), data - readStart, 1);
    duint previousInstr = readStart + prev;

    BASIC_INSTRUCTION_INFO basicinfo;
    bool valid = disasmfast(disasmData + prev, previousInstr, &basicinfo);
    if(valid && basicinfo.call)
    {

    }
}