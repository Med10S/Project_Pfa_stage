// Define _DWORD for Windows compatibility
typedef unsigned int _DWORD;
int __stdcall SrvOs2FeaListSizeToNt(char *a1)
{
    char *v1;        // eax
    unsigned int v2; // edi  64 bits │ Accumulateur principal (8 bytes)
    char *v3;        // esi
    int v4;          // ebx
    int v6;          // [esp+Ch] [ebp-4h] BYREF

    v1 = a1;
    v6 = 0;
    v2 = (unsigned int)&a1[*(_DWORD *)a1];
    v3 = a1 + 4;
    if ((unsigned int)(a1 + 4) < v2)
    {
        while ((unsigned int)(v3 + 4) < v2)
        {
            v4 = *((unsigned __int16 *)v3 + 1) + (unsigned __int8)v3[1];
            if ((unsigned int)&v3[v4 + 5] > v2)
                break;
            if ((int)RtlSizeTAdd(v6, (v4 + 12) & 0xFFFFFFFC, &v6) < 0)
                return 0;
            v3 += v4 + 5;
            if ((unsigned int)v3 >= v2)
                return v6;
            v1 = a1;
        }
        *(_DWORD *)v1 = v3 - v1;
    }
    return v6;
}

int __stdcall RtlSizeTAdd(unsigned int a1, int a2, _DWORD *a3)
{
    if (a1 + a2 < a1)
    {
        *a3 = -1;
        return -1073741675;
    }
    else
    {
        *a3 = a1 + a2;
        return 0;
    }
}