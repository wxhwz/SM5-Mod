#include <Windows.h>
#include <xmmintrin.h>
#include <fstream>
#include "ModUtils.h"  // 引入自定义的 ModUtils 模块
#include "safetyhook.hpp"

#define ZHT 1
#define EN 0

using namespace ModUtils;
using namespace mINI;

int width = 1920;
int height = 1080;
float aspect = (float)width / (float)height;
float default_aspect = 16.0f / 9.0f;
int version = -1;

// 获取当前进程的 ID 和基地址
DWORD processId = GetCurrentProcessId();
uintptr_t BaseAddress = get_ProcessBaseAddress(processId);

// 读取配置文件
void ReadConfig()
{
    // 从模块路径读取配置文件
    INIFile config(get_ModFolderPath() + "\\config.ini");
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

    Log("Resolution config file: ", get_ModFolderPath(), "\\config.ini");
    Log("Config resolution: ", width, " * ", height);

    // 拼接文件路径
    std::string filePath = get_ModFolderPath() + "\\load.txt";
    // 检查文件是否已经存在
    if (std::filesystem::exists(filePath)) {
        Log("load.txt already exists, skipping creation.");
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
            Log("load.txt creation completed.");
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
        Log("Failed to get the user profile path.");
        return 1;
    }

    // 构建文件路径
    if (!userProfile) {
        Log("Failed to get the user profile path.");
        return 1;
    }
    std::string filePath;
    if (version == ZHT)
        filePath = std::string(userProfile) + "\\Documents\\KOEI\\Shin Sangokumusou 5\\Savedata\\save.dat";
    else
        filePath = std::string(userProfile) + "\\Documents\\KOEI\\Dynasty Warriors 6\\Savedata\\save.dat";

    // 打开文件，以二进制方式打开
    std::fstream file(filePath, std::ios::in | std::ios::out | std::ios::binary);

    if (!file.is_open()) {
        Log("Failed to open the savedata.");
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
    Log("Savedata modification complete. ", "Offset:", offset_hex_str, " Bytestr:", hexString);
    return 0;
}



//DW6_WIN.exe + 8250 - BE 40060000
//DW6_WIN.exe + 8255 - EB 11


// 主线程函数
DWORD WINAPI MainThread(LPVOID lpParam)
{
    std::string temp;
    ModUtils::read_BytesReturnStr(temp, BaseAddress + 0x8250, 7);
    if (temp == "BE 40 06 00 00 EB 11")
    {
        version = EN;
        Log("Game is EN ...");
    }
    else if (ModUtils::read_BytesReturnStr(temp, BaseAddress + 0x8210, 7))
    {
        if (temp == "BE 40 06 00 00 EB 11")
            version = ZHT;
        Log("Game is ZHT ...");
    }
    else
    {
        Log("Unknown game version ...");
        return 0;
    }

    ReadConfig();  // 读取配置文件
    /*write_memery(BaseAddress + 0x20EF20, "B8 09 00 00 00 90");
    write_memery(BaseAddress + 0x20EF90, "B8 09 00 00 00 90");*/
    std::string widthString = convert_int_to_targetByte(width);
    std::string heightString = convert_int_to_targetByte(height);
    std::string final_str = widthString + " 78 " + heightString + " 20 2F 20 " + widthString + " 78 " + heightString;
    static SafetyHookMid aspect_hook;
    static SafetyHookMid aspect_hook_map;
    write_savedata(0xD0, "09");
    Log("Starting resolution modification ...");


    if (version == EN)
    {
        mem_Copy(BaseAddress + 0x8258, (uintptr_t)&width, 4);
        mem_Copy(BaseAddress + 0x8863, (uintptr_t)&width, 4);
        mem_Copy(BaseAddress + 0x20D85B, (uintptr_t)&width, 4);

        mem_Copy(BaseAddress + 0x825D, (uintptr_t)&height, 4);
        mem_Copy(BaseAddress + 0x88A6, (uintptr_t)&height, 4);
        mem_Copy(BaseAddress + 0x20D8CB, (uintptr_t)&height, 4);
        mem_Copy(BaseAddress + 0x20D94D, (uintptr_t)&height, 4);
        write_ByteStr(BaseAddress + 0x317770, final_str);

        if (aspect != 16.0f / 9.0f)
        {
            aspect_hook = safetyhook::create_mid(BaseAddress + 0x238049,
                [](SafetyHookContext& ctx)
                {
                    if (*reinterpret_cast<float*>(ctx.ebp + 0x13C) == default_aspect)
                    {
                        *reinterpret_cast<float*>(ctx.ebp + 0x13C) = aspect;
                    }
                });
            aspect_hook_map = safetyhook::create_mid(BaseAddress + 0x26318D,
                [](SafetyHookContext& ctx)
                {
                    if (*reinterpret_cast<float*>(ctx.esi + 0x8C) == default_aspect)
                    {
                        *reinterpret_cast<float*>(ctx.esi + 0x8C) = aspect;
                    }
                });
        }

    }
    else if (version == ZHT)
    {
        mem_Copy(BaseAddress + 0x8218, (uintptr_t)&width, 4);
        mem_Copy(BaseAddress + 0x8823, (uintptr_t)&width, 4);
        mem_Copy(BaseAddress + 0x20EF4B, (uintptr_t)&width, 4);

        mem_Copy(BaseAddress + 0x821D, (uintptr_t)&height, 4);
        mem_Copy(BaseAddress + 0x8866, (uintptr_t)&height, 4);
        mem_Copy(BaseAddress + 0x20f03d, (uintptr_t)&height, 4);
        mem_Copy(BaseAddress + 0x20EFBB, (uintptr_t)&height, 4);
        //aspect
        //mem_Copy(BaseAddress + 0x3268c4, (uintptr_t)&aspect, 4);
        write_ByteStr(BaseAddress + 0x319d40, final_str);

        if (aspect != 16.0f / 9.0f)
        {
            aspect_hook = safetyhook::create_mid(BaseAddress + 0x239799,
                [](SafetyHookContext& ctx)
                {
                    if (*reinterpret_cast<float*>(ctx.ebp + 0x13C) == default_aspect)
                    {
                        *reinterpret_cast<float*>(ctx.ebp + 0x13C) = aspect;
                    }
                });

            aspect_hook_map = safetyhook::create_mid(BaseAddress + 0x2648CD,
                [](SafetyHookContext& ctx)
                {
                    if (*reinterpret_cast<float*>(ctx.esi + 0x8C) == default_aspect)
                    {
                        *reinterpret_cast<float*>(ctx.esi + 0x8C) = aspect;
                    }
                });
        }

    }





    Log("Modification completed, current resolution is ", width, " * ", height);

    close_Log();
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
