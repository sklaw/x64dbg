#include "cstdio"
#include "disasm_helper.h"
#include "disasm_fast.h"

bool MockDbgMemRead(duint index, void* dest, duint size)
{
    return false;
}

int main()
{
    printf("Hello World!");
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