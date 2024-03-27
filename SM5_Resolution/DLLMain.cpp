
#include "ModUtils.h"  // 引入自定义的 ModUtils 模块
#include "safetyhook.hpp"
#include "Detours\include\detours.h"
#include "d3d9.h" 

#define JP 1
#define EN 0


using namespace mINI;

int width = 1920;
int height = 1080;
float aspect = (float)width / (float)height;
float default_aspect = 16.0f / 9.0f;
int version = -1;
std::string final_str;

// 获取当前进程的 ID 和基地址
DWORD processId = GetCurrentProcessId();
uintptr_t BaseAddress = ModUtils::get_ProcessBaseAddress(processId);

typedef int(WINAPI GetSystemMetrics_t)(int nIndex);
GetSystemMetrics_t* Ori_GetSystemMetrics = GetSystemMetrics;
GetSystemMetrics_t Hooked_GetSystemMetrics;


typedef IDirect3D9* (WINAPI Direct3DCreate9_t)(UINT SDKVersion);
Direct3DCreate9_t* Ori_Direct3DCreate9 = (Direct3DCreate9_t*)GetProcAddress(GetModuleHandleA("d3d9.dll"), "Direct3DCreate9");
Direct3DCreate9_t HookedDirect3DCreate9;

int WINAPI Hooked_GetSystemMetrics(int nIndex)
{
    if (nIndex == 0)
    {
        return width;
    }
    else if (nIndex == 1)
    {
        return height;
    }

    return Ori_GetSystemMetrics(nIndex);
}


void ApplyResolution()
{
    ModUtils::Log("Starting resolution modification ...");

    //Pass the resolution check
    ModUtils::write_Bytes(ModUtils::AobScan("0C ?? ?? ?? 41020000 00", L"")[0] + 8, std::vector<BYTE>{0x01});

    //width
    uintptr_t addr1 = ModUtils::AobScan("80070000 ?? 38040000 EB", L"")[0];
    ModUtils::mem_Copy(addr1, (uintptr_t)&width, 4);
    ModUtils::mem_Copy(ModUtils::AobScan("40060000 ???? ?? 80070000 ???? ?? 00040000", L"")[0] + 7, (uintptr_t)&width, 4);
    ModUtils::mem_Copy(ModUtils::AobScan("80070000 C3 ?? 00040000", L"")[0], (uintptr_t)&width, 4);
    //heights
    ModUtils::mem_Copy(addr1 + 5, (uintptr_t)&height, 4);
    ModUtils::mem_Copy(ModUtils::AobScan("38040000 ???? ?? 40020000", L"")[0], (uintptr_t)&height, 4);
    ModUtils::mem_Copy(ModUtils::AobScan("38040000 C3 ?? 40020000", L"")[0], (uintptr_t)&height, 4);
    ModUtils::mem_Copy(ModUtils::AobScan("38040000 C3 ?? 00030000", L"")[0], (uintptr_t)&height, 4);

    uintptr_t aspect_hookaddr1 = ModUtils::AobScan("28 D9 ?? 3C010000 D9 ?? ?? 28", L"")[0] + 1;
    uintptr_t aspect_hookaddr2 = ModUtils::AobScan("8C000000 D9 ?? ?? 04 D9", L"")[0] + 4;

    static SafetyHookMid aspect_hook;
    static SafetyHookMid aspect_hook_map;
    if (aspect != 16.0f / 9.0f)
    {
        aspect_hook = safetyhook::create_mid(aspect_hookaddr1,
            [](SafetyHookContext& ctx)
            {
                if (*reinterpret_cast<float*>(ctx.ebp + 0x13C) == default_aspect)
                {
                    *reinterpret_cast<float*>(ctx.ebp + 0x13C) = aspect;
                }
            });
        aspect_hook_map = safetyhook::create_mid(aspect_hookaddr2,
            [](SafetyHookContext& ctx)
            {
                if (*reinterpret_cast<float*>(ctx.esi + 0x8C) == default_aspect)
                {
                    *reinterpret_cast<float*>(ctx.esi + 0x8C) = aspect;
                }
            });
    }
    ModUtils::write_ByteStr(ModUtils::AobScan("31 39 32 30 78 31 30 38 30 20 2F 20 31 39 32 30 78 31 30 38 30", L"")[0], final_str);
    ModUtils::Log("Modification completed, current resolution is ", width, " * ", height);
    ModUtils::Warn("If you want to set the game to full screen, you must ensure that this resolution is present in the system!");

    ModUtils::close_Log();
}

IDirect3D9* WINAPI HookedDirect3DCreate9(UINT SDKVersion)
{
    ApplyResolution();
    auto rv = Ori_Direct3DCreate9(SDKVersion);
    //if (rv == nullptr)
    //    ; // 如果获取失败，可以添加处理逻辑

    // 使用 Detours 库进行函数钩取
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourDetach(&(PVOID&)Ori_Direct3DCreate9, HookedDirect3DCreate9);
    DetourTransactionCommit();

    return rv;
}



// 读取配置文件
void ReadConfig()
{
    // 从模块路径读取配置文件
    INIFile config(ModUtils::get_ModFolderPath() + "\\config.ini");
    INIStructure ini;

    if (config.read(ini))
    {
        width = std::stoi(ini["Resolution"].get("Width"));
        height = std::stoi(ini["Resolution"].get("Height"));
        aspect = (float)width / (float)height;
    }
    else
    {
        ini["Resolution"]["Width"] = "1920";
        ini["Resolution"]["Height"] = "1080";
        config.write(ini, true);
    }

    ModUtils::Log("Resolution config file: ", ModUtils::get_ModFolderPath(), "\\config.ini");
    ModUtils::Log("Config resolution: ", width, " * ", height);

    // 拼接文件路径
    std::string filePath = ModUtils::get_ModFolderPath() + "\\load.txt";
    // 检查文件是否已经存在
    if (std::filesystem::exists(filePath)) {
        ModUtils::Log("load.txt already exists, skipping creation.");
    }
    else {
        // 尝试打开文件
        std::ofstream outputFile(filePath);
        // 检查文件是否成功打开
        if (outputFile.is_open()) {
            // 写入数字0到文件
            outputFile << "0" << std::endl;
            // 关闭文件
            outputFile.close();
            ModUtils::Log("load.txt creation completed.");
        }
        else {
            std::cerr << "Unable to open the file：" << filePath << std::endl;
        }
    }

}



std::string convert_int_to_targetByte(int num)
{
    std::string inputString = std::to_string(num);
    std::stringstream Stream;
    for (size_t i = 0; i < inputString.length(); ++i) {
        Stream << std::to_string(int(inputString[i]) - 18);
        // 在最后一个字符后不加空格
        if (i < inputString.length() - 1) {
            Stream << ' ';
        }
    }
    return Stream.str();
}

// 修改存档
int write_savedata(size_t offset, std::string hexString)
{

    char* userProfile;
    size_t len;
    if (_dupenv_s(&userProfile, &len, "USERPROFILE") != 0) {
        ModUtils::Log("Failed to get the user profile path.");
        return 1;
    }

    // 构建文件路径
    if (!userProfile) {
        ModUtils::Log("Failed to get the user profile path.");
        return 1;
    }
    std::string filePath = "";
    if (version == JP)
        filePath = std::string(userProfile) + "\\Documents\\KOEI\\Shin Sangokumusou 5\\Savedata\\save.dat";
    else if (version == EN)
        filePath = std::string(userProfile) + "\\Documents\\KOEI\\Dynasty Warriors 6\\Savedata\\save.dat";

    // 打开文件，以二进制方式打开
    std::fstream file(filePath, std::ios::in | std::ios::out | std::ios::binary);

    if (!file.is_open()) {
        ModUtils::Log("Failed to open the savedata. You may need to manually adjust the game resolution to 1080p.");
        return 1;
    }

    // 移动到要修改的位置
    file.seekp(offset, std::ios::beg); // 从文件开头移动字节

    // 使用字符串流解析成二进制数据
    std::istringstream hexStream(hexString);
    unsigned int byteValue;
    while (hexStream >> std::hex >> byteValue) {
        // 写入二进制数据
        file.write(reinterpret_cast<char*>(&byteValue), sizeof(unsigned int));
    }

    // 关闭文件
    file.close();
    free(userProfile);
    // 使用 std::stringstream 进行转换
    std::stringstream ss;
    ss << std::hex << std::setw(2) << std::setfill('0') << offset; // 设置宽度为2，不足两位用0填充
    // 从 stringstream 获取结果字符串
    std::string offset_hex_str = ss.str();
    ModUtils::Log("Savedata modification complete. ", "Offset:", offset_hex_str, " Bytestr:", hexString);
    return 0;
}



//DW6_WIN.exe + 8250 - BE 40060000
//DW6_WIN.exe + 8255 - EB 11


// 主线程函数
DWORD WINAPI MainThread(LPVOID lpParam)
{
    if (ModUtils::AobScan("44 79 6E 61 73 74 79 20 57 61 72 72 69 6F 72 73 20 36", L"") != std::vector<uintptr_t>{})
    {
        version = EN;
        /*ModUtils::Log("Game is EN ...");*/
    }
    else if (ModUtils::AobScan("53 68 69 6E 20 53 61 6E 67 6F 6B 75 6D 75 73 6F 75 20 35", L"") != std::vector<uintptr_t>{})
    {

        version = JP;
        /*ModUtils::Log("Game is JP ...");*/
    }
    else
    {
        ModUtils::Warn("Unknown game version ...");
        return 0;
    }

    ReadConfig();  // 读取配置文件
    /*write_memery(BaseAddress + 0x20EF20, "B8 09 00 00 00 90");
    write_memery(BaseAddress + 0x20EF90, "B8 09 00 00 00 90");*/
    std::string widthString = convert_int_to_targetByte(width);
    std::string heightString = convert_int_to_targetByte(height);
    final_str = widthString + " 78 " + heightString + " 20 2F 20 " + widthString + " 78 " + heightString;

    write_savedata(0xD0, "09");




    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    if (width > GetSystemMetrics(0) || height > GetSystemMetrics(1))
    {
        ModUtils::Warn("Config resolution ", width, " * ", height, " is larger than the screen resolution ", GetSystemMetrics(0), " * ", GetSystemMetrics(1), " ...");
        DetourAttach(&(PVOID&)Ori_GetSystemMetrics, Hooked_GetSystemMetrics);
    }
    DetourAttach(&(PVOID&)Ori_Direct3DCreate9, HookedDirect3DCreate9);

    DetourTransactionCommit();



    return 0;
}

// DLL 入口函数
BOOL WINAPI DllMain(HINSTANCE module, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(module);
        CreateThread(0, 0, &MainThread, 0, 0, NULL);  // 创建主线程
    }
    return 1;
}
