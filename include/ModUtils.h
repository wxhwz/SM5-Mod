#pragma once 

#include <Windows.h>
#include <string>
#include <cstdarg>
#include <fileapi.h>
#include <Psapi.h>
#include <iostream>
#include <vector>
#include <xinput.h>
#include <sstream>
#include <map>
#include <chrono>
#include <iomanip>
#include <filesystem>
#include <thread>
#include <future>

#include "ini.h"

namespace ModUtils
{
    static HWND muWindow = NULL;
    static std::string muGameName = "rpcs3";
    static std::string muExpectedWindowName = "";
    static std::ofstream muLogFile;
    static const char* muAobMask = "??";
    bool is_Init = false;

    UINT32 cpu_CoreCount = 0;
    //BYTE* aobscan_cache;
    // 保存地址与之前的内存保护状态的映射
    std::map<uintptr_t, DWORD> protection_History;

    /*const std::unordered_map<std::string, int> optionMap = {
        {"Byte", 1},
        {"2 Bytes", 2},
        {"4 Bytes", 3},
        {"8 Bytes", 4},
        {"Float", 5},
        {"Double", 6},
        {"String", 7},
        {"Array of Bytes", 8},
        {"2 Bytes Big Endian",9},
        {"4 Bytes Big Endian",10},
        {"Float Big Endian",11}
    };*/
    const enum class OptionType : BYTE
    {
        Byte = 1,
        TwoBytes = 2,
        FourBytes = 3,
        EightBytes = 4,
        Float = 5,
        Double = 6,
        String = 7,
        ArrayOfBytes = 8,
        TwoBytesBigEndian = 9,
        FourBytesBigEndian = 10,
        FloatBigEndian = 11
    };

    struct ModuleInfo
    {
        HMODULE hModule = 0;
        HMODULE hModule_end = 0;
        MODULEINFO module_info;
        std::wstring module_name;
    };


    class ModuleInfos {
    public:
        ModuleInfos(HANDLE hd) {
            HMODULE* module_array = nullptr;
            LPBYTE module_array_bytes = 0;
            DWORD bytes_required = 0;
            // 查询进程中模块的数量以获取所需的字节数
            if (EnumProcessModules(hd, NULL, 0, &bytes_required))
            {
                // 分配内存以存储模块信息
                if (bytes_required)
                {
                    module_array_bytes = (LPBYTE)LocalAlloc(LPTR, bytes_required);
                    if (module_array_bytes)
                    {
                        module_count = bytes_required / sizeof(HMODULE);
                        module_array = (HMODULE*)module_array_bytes;
                        module_infos = new ModuleInfo[module_count];

                        // 获取进程的模块信息
                        if (EnumProcessModules(hd, module_array, bytes_required, &bytes_required))
                        {
                            // 获取每个模块的信息
                            for (DWORD i = 0; i < module_count; ++i) {
                                module_infos[i].hModule = module_array[i];
                                // 获取模块信息
                                if (!GetModuleInformation(hd, module_infos[i].hModule, &module_infos[i].module_info, sizeof(module_infos[i].module_info))) {
                                    std::cerr << "GetModuleInformation failed." << std::endl;
                                }
                                module_infos[i].hModule_end = module_infos[i].hModule + module_infos[i].module_info.SizeOfImage / 4;

                                // 获取模块文件名
                                TCHAR module_name_tmp[MAX_PATH];
                                if (GetModuleFileNameEx(hd, module_infos[i].hModule, module_name_tmp, MAX_PATH)) {
                                    module_infos[i].module_name = module_name_tmp;
                                    size_t last_back_slash = module_infos[i].module_name.find_last_of(L'\\');
                                    if (last_back_slash != std::wstring::npos) {
                                        module_infos[i].module_name = module_infos[i].module_name.substr(last_back_slash + 1);
                                    }
                                }
                                else {
                                    std::cerr << "GetModuleFileNameEx failed." << std::endl;
                                }
                            }
                        }
                        LocalFree(module_array_bytes);
                    }
                    else
                    {
                        std::cerr << "LocalAlloc failed." << std::endl;
                    }
                }
            }
            else {
                std::cerr << "EnumProcessModules failed." << std::endl;
            }
        }
        // 析构函数，用于释放动态分配的内存
        ~ModuleInfos() {
            delete[] module_infos;  // 释放结构体数组的内存空间
        }
        UINT32 get_ModuleInfo_index(const WCHAR* str)
        {
            for (UINT32 i = 0; i < module_count; i++)
            {
                if (module_infos[i].module_name == str)
                {
                    return i;
                }
            }
            return -1;
        }
        // 获取模块基址
        inline DWORD_PTR get_BaseAddress(const WCHAR* str)
        {
            UINT32 index = get_ModuleInfo_index(str);
            if (index == -1)
            {
                return 0;
            }
            return (DWORD_PTR)module_infos[index].hModule;
        }
        inline DWORD_PTR get_BaseAddress(UINT32 index)
        {
            if (index >= module_count)
                return 0;
            return (DWORD_PTR)module_infos[index].hModule;
        }
        inline DWORD_PTR get_EndAddress(const WCHAR* str)
        {
            UINT32 index = get_ModuleInfo_index(str);
            if (index == -1)
            {
                return 0;
            }
            return (DWORD_PTR)module_infos[index].hModule_end;
        }
        inline DWORD_PTR get_EndAddress(UINT32 index)
        {
            if (index >= module_count)
                return 0;
            return (DWORD_PTR)module_infos[index].hModule_end;
        }

        // 获取模块大小
        inline SIZE_T get_ModuleSize(const WCHAR* str)
        {
            UINT32 index = get_ModuleInfo_index(str);
            if (index == -1)
            {
                return 0;
            }
            return module_infos[index].module_info.SizeOfImage;
        }
        inline SIZE_T get_ModuleSize(UINT32 index)
        {
            if (index >= module_count)
                return 0;
            return module_infos[index].module_info.SizeOfImage;
        }

        // 获取模块文件名
        inline std::wstring& get_ModuleName(UINT32 index) const {
            if (index >= module_count)
                return module_infos[0].module_name;
            return module_infos[index].module_name;
        }

        inline const UINT32& get_ModuleCount() const {
            return module_count;
        }

    private:
        UINT32 module_count;
        ModuleInfo* module_infos;
    };

    ModuleInfos* module_infos;


    static void get_CpuCoreCount()
    {
        // 获取系统信息
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        // 获取核心数目
        cpu_CoreCount = sysInfo.dwNumberOfProcessors;
    }
    // 初始化模块信息
    inline static void initialize(DWORD processId)
    {
        if (is_Init)
        {
            return;
        }
        // 打开指定进程的句柄
        HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
        // 检查是否成功打开进程句柄
        if (processHandle)
        {
            module_infos = new ModuleInfos(processHandle);
            CloseHandle(processHandle);
            //aobscan_cache = new BYTE[4096];
            is_Init = true;
            //return module_infos;
        }
        else {
            std::cerr << "OpenProcess failed." << std::endl;
        }
        get_CpuCoreCount();

    }

    inline static void uninitialize()
    {
        if (is_Init)
        {
            delete module_infos;
            //delete[] aobscan_cache;
            is_Init = false;
        }
    }

    static std::string wstr_to_str(const TCHAR* wideString) {
        std::string str;
#ifdef _UNICODE
        // 如果项目使用 Unicode 字符集，则进行宽字符到多字节字符的转换
        int size = WideCharToMultiByte(CP_UTF8, 0, wideString, -1, NULL, 0, NULL, NULL);
        char* charString = new char[size];
        WideCharToMultiByte(CP_UTF8, 0, wideString, -1, charString, size, NULL, NULL);
        str = charString;
        // 使用 charString，例如输出
        //std::cout << charString << std::endl;
        // 记得释放内存
        delete[] charString;
#else
        // 如果项目使用 ANSI 字符集，直接进行类型转换
        const char* charString = reinterpret_cast<const char*>(wideString);
        str = charString;
        // 使用 charString，例如输出
        //std::cout << charString << std::endl;
#endif

        return str;
    }

    static bool is_MemReadable(uintptr_t address)
    {
        MEMORY_BASIC_INFORMATION memoryInfo = { 0 };
        if (!VirtualQuery((void*)address, &memoryInfo, sizeof(MEMORY_BASIC_INFORMATION))) {
            /*DWORD error = GetLastError();
            if (error == ERROR_INVALID_PARAMETER) {
                Log("Reached end of scannable memory.");
            }
            else {
                Log("VirtualQuery failed, error code: ", error);
            }*/
            return false;
        }

        return (memoryInfo.Protect == PAGE_EXECUTE_READWRITE
            || memoryInfo.Protect == PAGE_READWRITE
            || memoryInfo.Protect == PAGE_READONLY
            || memoryInfo.Protect == PAGE_WRITECOPY
            || memoryInfo.Protect == PAGE_EXECUTE_READ
            || memoryInfo.Protect == PAGE_EXECUTE_WRITECOPY)
            && memoryInfo.State;
    }

    // 定义一个计时器类 Timer
    class Timer
    {
    public:
        // 构造函数，传入计时器的时间间隔（以毫秒为单位）
        Timer(unsigned int intervalMs)
        {
            this->intervalMs = intervalMs;
        }
        // 检查是否到达指定的时间间隔
        bool Check()
        {
            // 如果是第一次检查，重置计时器并标记为非第一次检查
            if (firstCheck)
            {
                Reset();
                firstCheck = false;
            }
            // 获取当前时间点
            auto now = std::chrono::system_clock::now();
            // 计算与上一次检查时间点的时间差
            auto diff = std::chrono::duration_cast<std::chrono::milliseconds>(now - lastPassedCheckTime);
            // 如果时间差达到设定的时间间隔，更新上一次检查时间并返回 true
            if (diff.count() >= intervalMs)
            {
                lastPassedCheckTime = now;
                return true;
            }
            // 未达到时间间隔，返回 false
            return false;
        }
        // 重置计时器，将上一次检查时间设置为当前时间
        void Reset()
        {
            lastPassedCheckTime = std::chrono::system_clock::now();
        }

    private:
        unsigned int intervalMs = 0;  // 计时器的时间间隔（毫秒）
        bool firstCheck = true;        // 是否是第一次检查
        std::chrono::system_clock::time_point lastPassedCheckTime;  // 上一次检查的时间点
    };


    static std::string _GetModuleName(bool mainProcessModule)
    {
        HMODULE module = NULL;

        // 如果不是主进程模块，获取当前模块的句柄
        if (!mainProcessModule)
        {
            // 创建一个静态的char变量，并使用其地址作为参数获取当前模块的句柄
            static char dummyStaticVarToGetModuleHandle = 'x';
            GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, &dummyStaticVarToGetModuleHandle, &module);
        }

        // 获取当前模块的文件名
        char lpFilename[MAX_PATH];
        GetModuleFileNameA(module, lpFilename, sizeof(lpFilename));

        // 从文件名中提取模块名
        std::string moduleName = strrchr(lpFilename, '\\'); // 在路径中查找最后一个反斜杠
        moduleName = moduleName.substr(1, moduleName.length()); // 去掉反斜杠

        // 如果不是主进程模块，从模块名中去掉 ".dll" 扩展名
        if (!mainProcessModule)
        {
            moduleName.erase(moduleName.find(".dll"), moduleName.length());
        }

        return moduleName;
    }

    static std::string get_CurrentProcessName()
    {
        return _GetModuleName(true);
    }

    static std::string get_CurrentModName()
    {
        static std::string currentModName = "NULL";
        if (currentModName == "NULL")
        {
            currentModName = _GetModuleName(false);
        }
        return currentModName;
    }

    static std::string get_ModFolderPath()
    {
        return std::string("mods\\" + get_CurrentModName());
    }

    static void open_ModLogFile()
    {
        std::string dll_folder = "mods\\" + get_CurrentModName();


        if (std::filesystem::exists(dll_folder) && std::filesystem::is_directory(dll_folder))
        {

        }
        else
        {
            // 如果没有打开，创建模组日志文件目录
            std::filesystem::create_directory(dll_folder);
        }
        if (!std::filesystem::exists(dll_folder + "\\" + "enable.txt"))
        {
            // 创建文件
            std::ofstream mod_enable_File(dll_folder + "\\" + "enable.txt");
            mod_enable_File << "1";
            mod_enable_File.close();
        }
        // 检查日志文件是否已经打开
        if (!muLogFile.is_open())
        {
            // 打开模组日志文件
            muLogFile.open("mods\\" + get_CurrentModName() + "\\log.txt");
        }
    }

    template<typename... Types>
    inline static void Log(Types... args)
    {
        // 打开当前模组的日志文件
        open_ModLogFile();

        // 创建一个字符串流
        std::stringstream stream;

        // 将模组名和消息拼接到字符串流中
        stream << get_CurrentModName() << " > ";
        (stream << ... << args) << std::endl;

        // 输出到控制台
        std::cout << stream.str();

        // 如果日志文件已经打开，将日志写入文件
        if (muLogFile.is_open())
        {
            muLogFile << stream.str();
            muLogFile.flush();
        }
    }

    static void close_Log()
    {
        if (muLogFile.is_open())
        {
            muLogFile.close();
        }
    }

    static void ShowErrorPopup(std::string error)
    {
        get_CurrentModName();
        Log("Error popup: ", error);
        MessageBoxA(NULL, error.c_str(), get_CurrentModName().c_str(), MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
    }

    // 获取第一个模块的基址
    static DWORD_PTR get_ProcessBaseAddress(DWORD processId)
    {
        DWORD_PTR baseAddress = 0;

        // 打开指定进程的句柄
        HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);

        HMODULE* moduleArray = nullptr;
        LPBYTE moduleArrayBytes = 0;
        DWORD bytesRequired = 0;

        // 检查是否成功打开进程句柄
        if (processHandle)
        {
            // 查询进程中模块的数量以获取所需的字节数
            if (EnumProcessModules(processHandle, NULL, 0, &bytesRequired))
            {
                // 分配内存以存储模块信息
                if (bytesRequired)
                {
                    moduleArrayBytes = (LPBYTE)LocalAlloc(LPTR, bytesRequired);
                    if (moduleArrayBytes)
                    {
                        unsigned int moduleCount;
                        moduleCount = bytesRequired / sizeof(HMODULE);
                        moduleArray = (HMODULE*)moduleArrayBytes;

                        // 获取进程的模块信息
                        if (EnumProcessModules(processHandle, moduleArray, bytesRequired, &bytesRequired))
                        {
                            // 获取第一个模块的基址
                            baseAddress = (DWORD_PTR)moduleArray[0];
                        }
                        LocalFree(moduleArrayBytes);
                    }
                }
            }

            // 关闭进程句柄
            CloseHandle(processHandle);
        }

        return baseAddress;
    }

    // 切换内存保护属性
    inline static bool ToggleMemoryProtection(bool protectionEnabled, uintptr_t address, size_t size)
    {
        //// 保存地址与之前的内存保护状态的映射
        //static std::map<uintptr_t, DWORD> protection_History;

        // 如果启用保护，并且该地址在映射中
        if (protectionEnabled && protection_History.find(address) != protection_History.end())
        {
            // 恢复之前的内存保护状态
            VirtualProtect((void*)address, size, protection_History[address], &protection_History[address]);

            // 从映射中移除该地址
            protection_History.erase(address);
        }
        // 如果禁用保护，并且该地址不在映射中
        else if (!protectionEnabled && protection_History.find(address) == protection_History.end())
        {
            // 获取当前内存保护状态并设置为可读写
            DWORD oldProtection = 0;
            if (!VirtualProtect((void*)address, size, PAGE_EXECUTE_READWRITE, &oldProtection))
                if (!VirtualProtect((void*)address, size, PAGE_READWRITE, &oldProtection))
                    return false;
            // 将该地址与之前的内存保护状态存入映射
            protection_History[address] = oldProtection;
        }
        return true;
    }


    inline static bool mem_Copy(uintptr_t destination, uintptr_t source, size_t numBytes) {
        if (!is_MemReadable(destination) || !is_MemReadable(source))
            return false;
        // 执行内存拷贝操作
        ToggleMemoryProtection(false, destination, numBytes);
        memcpy((void*)destination, (void*)source, numBytes);
        ToggleMemoryProtection(true, destination, numBytes);
        return true;
    }


    inline static bool mem_Set(uintptr_t address, unsigned char byte, size_t numBytes) {
        // 关闭目标地址的写保护
        if (!ToggleMemoryProtection(false, address, numBytes))
            return false;
        // 执行内存设置操作
        memset((void*)address, byte, numBytes);
        // 重新启用目标地址的写保护
        ToggleMemoryProtection(true, address, numBytes);
        return true;
    }


    static uintptr_t get_RelativeToAbsoluteAddress(uintptr_t relativeAddressLocation)
    {
        uintptr_t absoluteAddress = 0;
        intptr_t relativeAddress = 0;

        // 从相对地址位置复制 4 字节数据到 relativeAddress 变量中
        mem_Copy((uintptr_t)&relativeAddress, relativeAddressLocation, 4);

        // 计算绝对地址：相对地址位置 + 4 + 相对地址的值
        absoluteAddress = relativeAddressLocation + 4 + relativeAddress;

        return absoluteAddress;
    }
    static void apply_RelativeAddress(uintptr_t dst_Address, uintptr_t src_Address)
    {
        uintptr_t relative_Address = dst_Address - (src_Address + 4);

        // 从相对地址位置复制 4 字节数据到 relativeAddress 变量中
        mem_Copy(src_Address, (uintptr_t)&relative_Address, 4);

    }


    inline static std::vector<std::string> tokenify_AobString(std::string aob)
    {
        std::istringstream iss(aob);
        // 使用流迭代器将字符串分割为标记
        std::vector<std::string> aobTokens{
            std::istream_iterator<std::string>{iss},
            std::istream_iterator<std::string>{}
        };
        return aobTokens;
    }


    inline static bool convert_AobStringToAobRaw(std::string aob, std::vector<BYTE>& aob_raw, std::vector<bool>& aob_mask, bool& no_mask)
    {
        std::vector<std::string>aobTokens = tokenify_AobString(aob);
        // 检查字节是否为有效的十六进制字符
        std::string whitelist = "0123456789ABCDEF";
        for (std::string& byte : aobTokens)
        {
            // 如果当前字节等于掩码，继续下一个字节
            if (byte == muAobMask)
            {
                no_mask = false;
                aob_raw.push_back(0);
                aob_mask.push_back(true);
                continue;
            }
            // 检查字节长度是否为 2
            if (byte.length() != 2)
            {
                goto label;
            }
            for (char& c : byte) {
                c = std::toupper(c);
            }
            if (byte.find_first_not_of(whitelist) != std::string::npos)
            {
                goto label;
            }
            else
            {
                // 将字节转换为十六进制数值
                aob_raw.push_back((BYTE)std::stoul(byte, nullptr, 16));
                aob_mask.push_back(false);
            }
        }
        return true;
    label:
        ShowErrorPopup("AOB is invalid! (" + aob + ")");
        return false;
    }



    //static bool VerifyAob(std::string aob)
    //{
    //    // 将 AOB 字符串分割为标记
    //   // std::vector<std::string> aobTokens = TokenifyAobString(aob);

    //    // 检查 AOB 标记是否有效
    //    if (!IsAobValid(aob))
    //    {
    //        // 显示错误弹窗，并返回 false
    //        ShowErrorPopup("AOB is invalid! (" + aob + ")");
    //        return false;
    //    }

    //    // AOB 有效，返回 true
    //    return true;
    //}static bool VerifyAobs(std::vector<std::string> aobs)
    //{
    //    // 对于每个 AOB，调用 VerifyAob 函数验证其有效性
    //    for (auto aob : aobs)
    //    {
    //        if (!VerifyAob(aob))
    //        {
    //            return false;
    //        }
    //    }

    //    // 所有 AOB 都有效，返回 true
    //    return true;
    //}
    //


    template<typename T>
    inline static std::string convert_NumberToHexString(T number)
    {
        std::stringstream stream;
        stream
            //<< std::setfill('0')
            //<< std::setw(sizeof(T) * 2)
            << std::uppercase
            << std::hex
            << number;
        return "0x" + stream.str();
    }
    /*作用： 将任意整数类型的数字转换为十六进制字符串。

        参数：

        number：要转换的数字。
        返回值： 十六进制表示的字符串。

        步骤：

        创建一个 std::stringstream 对象，用于将数字转换为字符串。
        设置填充字符为 '0'，以确保生成的十六进制字符串具有固定的宽度。
        设置输出宽度为 sizeof(T) * 2，确保十六进制字符串的长度足够表示输入的整数。
        将数字以十六进制格式输出到流中。
        返回转换后的字符串。*/

    inline static std::string convert_NumberToHexString(unsigned char number)
    {
        std::stringstream stream;
        stream
            << std::setw(2)
            << std::setfill('0')
            << std::uppercase
            << std::hex
            << (unsigned int)number; // The << operator overload for unsigned chars screws us over unless this cast is done
        return stream.str();
    }
    /*作用： 将 unsigned char 类型的数字转换为两位的十六进制字符串。

        参数：

        number：要转换的 unsigned char 数字。
        返回值： 两位的十六进制表示的字符串。

        步骤：

        创建一个 std::stringstream 对象，用于将数字转换为字符串。
        设置输出宽度为 2，确保生成的十六进制字符串的长度为两位。
        设置填充字符为 '0'。
        将 unsigned char 数字以十六进制格式输出到流中。注意：由于 << 操作符对于 unsigned char 的重载可能导致问题，因此进行了显式的 unsigned int 强制转换。
        返回转换后的字符串。*/

        // 将字符串形式的 AOB 转换为原始字节序列
    inline static std::vector<BYTE> aobstr_to_aobraw(std::string aob)
    {
        std::vector<BYTE> rawAob;
        std::vector<std::string> tokenifiedAob = tokenify_AobString(aob);

        // 遍历 AOB 字符串的标记
        for (size_t i = 0; i < tokenifiedAob.size(); i++)
        {
            // 如果标记是掩码，则无法转换，显示错误弹窗并返回空向量
            if (tokenifiedAob[i] == muAobMask)
            {
                ShowErrorPopup("Cannot convert AOB with mask to raw AOB");
                return std::vector<BYTE>();
            }
            else
            {
                // 将十六进制字符串转换为字节，并添加到原始字节序列中
                BYTE byte = (BYTE)std::stoul(tokenifiedAob[i], nullptr, 16);
                rawAob.push_back(byte);
            }

        }

        return rawAob;
    }

    // 将原始字节序列转换为字符串形式的 AOB
    inline static std::string convert_AobRawToAobStr(std::vector<BYTE> rawAob)
    {
        std::string aob;

        // 遍历原始字节序列
        for (auto byte : rawAob)
        {
            // 将每个字节转换为十六进制字符串，并添加到 AOB 字符串中
            std::string string = convert_NumberToHexString(byte);
            aob += string + " ";
        }

        // 移除末尾的空格
        aob.pop_back();
        return aob;
    }
    /*StringAobToRawAob 函数：
    作用：将字符串形式的 AOB 转换为原始字节序列。
    参数：aob - 要转换的字符串形式的 AOB。
    返回值：包含原始字节序列的 std::vector<unsigned char>。
    遍历 AOB 字符串的标记，将每个十六进制字符串转换为字节，并添加到原始字节序列中。
    如果 AOB 字符串包含掩码，显示错误弹窗并返回空向量。

    RawAobToStringAob 函数：
    作用：将原始字节序列转换为字符串形式的 AOB。
    参数：rawAob - 包含原始字节序列的 std::vector<unsigned char>。
    返回值：字符串形式的 AOB。
    遍历原始字节序列，将每个字节转换为十六进制字符串，并添加到 AOB 字符串中。
    移除末尾的空格。*/

    //static std::vector<uintptr_t> AobScan(std::string aob, const TCHAR* module_name = L"", size_t result_count = 1)
    //{
    //    DWORD processId = GetCurrentProcessId();
    //    if (!is_init)
    //    {
    //        initialize(processId);
    //    }
    //    UINT32 index = 0;
    //    if (module_name != L"")
    //    {
    //        index = module_infos->get_ModuleInfo_index(module_name);
    //        if (index < 0)
    //        {
    //            std::string error = "Module name: " + wstr_to_str(module_name) + " not found!";
    //            Log(error);
    //            ShowErrorPopup(error);
    //            return {};
    //        }
    //    }
    //    else
    //    {
    //        module_name = module_infos->get_ModuleName(index).c_str();
    //    }
    //    // 获取Aob 的原始字节序列
    //    std::vector<BYTE> aob_raw;
    //    // 获取Aob 的掩码
    //    std::vector<bool> aob_mask;
    //    bool no_mask = true;
    //    // 将 AOB 字符串转换为原始字节序列
    //    if (!aobstring_convert_aobraw(aob, aob_raw, aob_mask, no_mask))
    //    {
    //        return {};
    //    }
    //    size_t aob_raw_size = aob_raw.size();

    //    /*std::cout << aobraw_to_aobstr(aob_raw) << std::endl;

    //    for (int i = 0; i < aob_raw_size; i++)
    //    {
    //        std::cout << aob_mask[i] << ' ';
    //    }
    //    std::cout << std::endl;*/

    //    // 获取当前模块的基址
    //    uintptr_t module_start = module_infos->get_BaseAddress(index);
    //    uintptr_t module_end = module_infos->get_EndAddress(index);

    //    //// 打印进程信息和 AOB
    //    //Log("Module name: ", wstr_to_str(module_name));
    //    //Log("Process ID: ", processId);
    //    //Log("Module base address: ", NumberToHexString(module_start));
    //    //Log("Module end address: ", NumberToHexString(module_end));
    //    //Log("AOB: ", aob);


    //    // 初始化循环变量和常量
    //    std::vector<uintptr_t> result = {};
    //    uintptr_t signature = 0;
    //    size_t numRegionsChecked = 0;
    //    uintptr_t currentAddress = 0;
    //    uintptr_t tmp_address = 0;
    //    uintptr_t regionStart = module_start;
    //    bool is_MemoryReadable;
    //    uintptr_t regionSize;
    //    uintptr_t regionEnd;
    //    uintptr_t protection;
    //    uintptr_t state;
    //    uintptr_t type;

    //    size_t aob_index = 0;

    //    /*bool writable;
    //    bool executable;*/




    //    // 循环扫描内存区域
    //    while (currentAddress <= module_end)
    //    {
    //        MEMORY_BASIC_INFORMATION memoryInfo = { 0 };

    //        // 查询虚拟内存信息
    //        if (!VirtualQuery((void*)regionStart, &memoryInfo, sizeof(MEMORY_BASIC_INFORMATION)))
    //        {
    //            DWORD error = GetLastError();
    //            if (error == ERROR_INVALID_PARAMETER)
    //            {
    //                Log("Reached end of scannable memory.");
    //            }
    //            else
    //            {
    //                Log("VirtualQuery failed, error code: ", error);
    //            }
    //            break;
    //        }

    //        // 获取内存区域信息
    //        regionStart = (uintptr_t)memoryInfo.BaseAddress;
    //        regionSize = (uintptr_t)memoryInfo.RegionSize;
    //        regionEnd = module_end < (regionStart + regionSize) ? module_end : (regionStart + regionSize);
    //        protection = (uintptr_t)memoryInfo.Protect;
    //        state = (uintptr_t)memoryInfo.State;
    //        type = (uintptr_t)memoryInfo.Type;


    //        is_MemoryReadable = (
    //            protection == PAGE_EXECUTE_READWRITE
    //            || protection == PAGE_READWRITE
    //            || protection == PAGE_READONLY
    //            || protection == PAGE_WRITECOPY
    //            || protection == PAGE_EXECUTE_READ
    //            || protection == PAGE_EXECUTE_WRITECOPY)
    //            && state == MEM_COMMIT;
    //        //is_MemoryReadable = true;
    //        //is_MemoryCOMMIT = (state == MEM_COMMIT);

    //        //if ((state == MEM_COMMIT) &&
    //        //    (protection & PAGE_GUARD) == 0 &&
    //        //    (protection & PAGE_NOACCESS) == 0 &&
    //        //    (type == MEM_IMAGE || type == MEM_PRIVATE) &&
    //        //    regionSize < 0x2ffffffff)
    //        //{
    //        //    // follow cheat engine's logic
    //        //    writable = ((protection & PAGE_READWRITE) > 0) ||
    //        //        ((protection & PAGE_WRITECOPY) > 0) ||
    //        //        ((protection & PAGE_EXECUTE_READWRITE) > 0) ||
    //        //        ((protection & PAGE_EXECUTE_WRITECOPY) > 0);

    //        //    // ignore it now
    //        //    executable = ((protection & PAGE_EXECUTE) > 0) ||
    //        //        ((protection & PAGE_EXECUTE_READ) > 0) ||
    //        //        ((protection & PAGE_EXECUTE_READWRITE) > 0) ||
    //        //        ((protection & PAGE_EXECUTE_WRITECOPY) > 0);

    //        //}

    //        if (is_MemoryReadable)
    //        {
    //            //Log("Checking region: ", NumberToHexString(regionStart));
    //            currentAddress = regionStart;

    //            // 在内存区域中循环查找 AOB 签名
    //            while (currentAddress < regionEnd - aob_raw_size) {
    //                tmp_address = currentAddress;
    //                aob_index = 0;
    //                while (aob_index < aob_raw_size) {
    //                    if (!aob_mask[aob_index] && (*(BYTE*)tmp_address != aob_raw[aob_index])) {
    //                        aob_index++;
    //                        tmp_address++;
    //                        break;
    //                    }
    //                    else if (aob_index == aob_raw_size - 1) {
    //                        // 找到 AOB 签名，返回其地址
    //                        signature = tmp_address - aob_raw_size + 1;
    //                        result.push_back(signature);
    //                        /*Log("Found signature at ", NumberToHexString(signature));*/
    //                        if (result.size() == result_count) {
    //                            return result;
    //                        }
    //                    }
    //                    aob_index++;
    //                    tmp_address++;
    //                }
    //                currentAddress++;
    //            }
    //        }
    //        else {
    //            /*Log("Skipped region: ", NumberToHexString(regionStart));*/
    //        }
    //        numRegionsChecked++;
    //        regionStart += memoryInfo.RegionSize;
    //    }
    //    if (result.empty())
    //    {
    //        // 打印停止信息，显示错误弹窗并返回 0
    //        Log("Stopped at: ", NumberToHexString(currentAddress), ", num regions checked: ", numRegionsChecked);
    //        std::string error = "AOB not found! (" + aob + ")";
    //        ShowErrorPopup(error);
    //    }
    //    return result;
    //}
    ///*AobScan 函数用于在当前进程的虚拟内存中扫描 AOB（数组型二进制）签名。
    //通过 TokenifyAobString 函数将 AOB 字符串分割为标记，这些标记将用于扫描内存。
    //获取当前进程的 ID 和基地址，并打印相关信息。
    //验证 AOB 是否有效，如果无效，显示错误弹窗并返回 0。
    //使用 VirtualQuery 函数查询虚拟内存信息，然后遍历内存区域。
    //在可读取的内存区域中查找 AOB 签名，找到后返回签名的地址。
    //如果循环超过最大次数或者查询虚拟内存信息失败，打印相应信息，显示错误弹窗并返回 0。*/

    static std::vector<uintptr_t> scaner(std::vector<BYTE> aob_raw, std::vector<bool> aob_mask
        , uintptr_t start, uintptr_t end, size_t result_max, size_t& result_count, bool& stop_flag, size_t& checked_regions, std::mutex& mutex)
    {
        // 初始化循环变量和常量
        size_t numRegionsChecked = 0;
        size_t aob_raw_size = aob_raw.size();
        uintptr_t currentAddress = 0;
        uintptr_t tmp_address = 0;
        uintptr_t regionStart = start;
        bool is_MemoryReadable;
        uintptr_t regionSize;
        uintptr_t regionEnd;
        uintptr_t protection;
        uintptr_t state;
        uintptr_t type;
        /*bool writable;
        bool executable;*/
        std::vector<uintptr_t> result = {};
        UINT32 aob_index = 0;
        uintptr_t signature = 0;

        // 循环扫描内存区域
        while (currentAddress <= end)
        {
            MEMORY_BASIC_INFORMATION memoryInfo = { 0 };

            // 查询虚拟内存信息
            if (!VirtualQuery((void*)regionStart, &memoryInfo, sizeof(MEMORY_BASIC_INFORMATION)))
            {
                DWORD error = GetLastError();
                if (error == ERROR_INVALID_PARAMETER)
                {
                    Log("Reached end of scannable memory.");
                }
                else
                {
                    Log("VirtualQuery failed, error code: ", error);
                }
                break;
            }

            // 获取内存区域信息
            regionStart = (uintptr_t)memoryInfo.BaseAddress;
            regionSize = (uintptr_t)memoryInfo.RegionSize;
            regionEnd = end < (regionStart + regionSize) ? end : (regionStart + regionSize);
            protection = (uintptr_t)memoryInfo.Protect;
            state = (uintptr_t)memoryInfo.State;
            type = (uintptr_t)memoryInfo.Type;


            is_MemoryReadable = (
                protection == PAGE_EXECUTE_READWRITE
                || protection == PAGE_READWRITE
                || protection == PAGE_READONLY
                || protection == PAGE_WRITECOPY
                || protection == PAGE_EXECUTE_READ
                || protection == PAGE_EXECUTE_WRITECOPY)
                && state == MEM_COMMIT;
            //is_MemoryReadable = true;
            //is_MemoryCOMMIT = (state == MEM_COMMIT);

            //if ((state == MEM_COMMIT) &&
            //    (protection & PAGE_GUARD) == 0 &&
            //    (protection & PAGE_NOACCESS) == 0 &&
            //    (type == MEM_IMAGE || type == MEM_PRIVATE) &&
            //    regionSize < 0x2ffffffff)
            //{
            //    // follow cheat engine's logic
            //    writable = ((protection & PAGE_READWRITE) > 0) ||
            //        ((protection & PAGE_WRITECOPY) > 0) ||
            //        ((protection & PAGE_EXECUTE_READWRITE) > 0) ||
            //        ((protection & PAGE_EXECUTE_WRITECOPY) > 0);

            //    // ignore it now
            //    executable = ((protection & PAGE_EXECUTE) > 0) ||
            //        ((protection & PAGE_EXECUTE_READ) > 0) ||
            //        ((protection & PAGE_EXECUTE_READWRITE) > 0) ||
            //        ((protection & PAGE_EXECUTE_WRITECOPY) > 0);

            //}

            if (is_MemoryReadable)
            {
                //Log("Checking region: ", NumberToHexString(regionStart));
                currentAddress = regionStart;

                // 在内存区域中循环查找 AOB 签名
                while (currentAddress < regionEnd - aob_raw_size && !stop_flag)
                {
                    tmp_address = currentAddress;
                    aob_index = 0;
                    while (aob_index < aob_raw_size)
                    {
                        if (!aob_mask[aob_index] && (*(BYTE*)tmp_address != aob_raw[aob_index]))
                        {
                            aob_index++;
                            tmp_address++;
                            break;
                        }
                        else if (aob_index == aob_raw_size - 1)
                        {
                            // 找到 AOB 签名，返回其地址
                            signature = tmp_address - aob_raw_size + 1;
                            Log("Found signature at ", convert_NumberToHexString(signature));
                            mutex.lock();
                            result.push_back(signature);
                            result_count++;
                            if (result_count == result_max)
                            {
                                stop_flag = true;
                                checked_regions += numRegionsChecked;
                                mutex.unlock();
                                return result;
                            }
                            mutex.unlock();
                        }
                        aob_index++;
                        tmp_address++;
                    }
                    currentAddress++;
                }
            }
            else
            {
                //Log("Skipped region: ", NumberToHexString(regionStart));

            }

            numRegionsChecked++;
            regionStart += memoryInfo.RegionSize;
        }
        mutex.lock();
        checked_regions += numRegionsChecked;
        mutex.unlock();
        return result;
    }
    inline static void build_PMT(const std::vector<BYTE>& pattern, std::vector<UINT32>& pmt, const UINT32& pattern_size)
    {
        pmt.resize(pattern_size);
        UINT32 k = 0; // k 为当前最长的公共前后缀长度
        for (UINT32 i = 1; i < pattern_size; ++i) { // 从 1 开始，因为 pmt[0] = 0
            while (k > 0 && pattern[i] != pattern[k]) { // 递归计算 pmt[i]
                k = pmt[k - 1]; // 从 pmt[k-1] 获取新的 k
            }
            if (pattern[i] == pattern[k]) { // 如果相等，那么 pmt[i] = pmt[k] + 1
                k++; // k 自增一次
            }
            pmt[i] = k; // 更新 pmt[i]
        }
    }
    static std::vector<uintptr_t> scaner_KMP(std::vector<BYTE> aob_raw, std::vector<UINT32> pmt, uintptr_t start,
        uintptr_t end, size_t result_max, size_t& result_count, bool& stop_flag,
        size_t& checked_regions, std::mutex& mutex)
    {
        // 初始化循环变量和常量
        size_t numRegionsChecked = 0;
        size_t aob_raw_size = aob_raw.size();
        uintptr_t region_ptr = 0;
        uintptr_t pattern_ptr = 0;
        uintptr_t regionStart = start;
        bool is_MemoryReadable;
        uintptr_t regionSize;
        uintptr_t regionEnd;
        uintptr_t protection;
        uintptr_t state;
        uintptr_t type;
        /*bool writable;
        bool executable;*/
        std::vector<uintptr_t> result = {};
        uintptr_t signature = 0;



        // 循环扫描内存区域
        while (region_ptr <= end) {
            MEMORY_BASIC_INFORMATION memoryInfo = { 0 };

            // 查询虚拟内存信息
            if (!VirtualQuery((void*)regionStart, &memoryInfo, sizeof(MEMORY_BASIC_INFORMATION))) {
                DWORD error = GetLastError();
                if (error == ERROR_INVALID_PARAMETER) {
                    Log("Reached end of scannable memory.");
                }
                else {
                    Log("VirtualQuery failed, error code: ", error);
                }
                break;
            }

            // 获取内存区域信息
            regionStart = (uintptr_t)memoryInfo.BaseAddress;
            regionSize = (uintptr_t)memoryInfo.RegionSize;
            regionEnd = end < (regionStart + regionSize) ? end : (regionStart + regionSize);
            protection = (uintptr_t)memoryInfo.Protect;
            state = (uintptr_t)memoryInfo.State;
            type = (uintptr_t)memoryInfo.Type;


            is_MemoryReadable = (
                protection == PAGE_EXECUTE_READWRITE
                || protection == PAGE_READWRITE
                || protection == PAGE_READONLY
                || protection == PAGE_WRITECOPY
                || protection == PAGE_EXECUTE_READ
                || protection == PAGE_EXECUTE_WRITECOPY)
                && state == MEM_COMMIT;
            //is_MemoryReadable = true;
            //is_MemoryCOMMIT = (state == MEM_COMMIT);

            //if ((state == MEM_COMMIT) &&
            //    (protection & PAGE_GUARD) == 0 &&
            //    (protection & PAGE_NOACCESS) == 0 &&
            //    (type == MEM_IMAGE || type == MEM_PRIVATE) &&
            //    regionSize < 0x2ffffffff)
            //{
            //    // follow cheat engine's logic
            //    writable = ((protection & PAGE_READWRITE) > 0) ||
            //        ((protection & PAGE_WRITECOPY) > 0) ||
            //        ((protection & PAGE_EXECUTE_READWRITE) > 0) ||
            //        ((protection & PAGE_EXECUTE_WRITECOPY) > 0);

            //    // ignore it now
            //    executable = ((protection & PAGE_EXECUTE) > 0) ||
            //        ((protection & PAGE_EXECUTE_READ) > 0) ||
            //        ((protection & PAGE_EXECUTE_READWRITE) > 0) ||
            //        ((protection & PAGE_EXECUTE_WRITECOPY) > 0);

            //}

            if (is_MemoryReadable) {
                //Log("Checking region: ", NumberToHexString(regionStart));
                region_ptr = regionStart;

                // 在内存区域中循环查找 AOB 签名
                while (region_ptr < regionEnd && !stop_flag) {
                    //std::this_thread::sleep_for(std::chrono::milliseconds(1000));
                    //Log("Region ptr: ", NumberToHexString(region_ptr), " Pattern ptr: ", NumberToHexString(pattern_ptr));
                    if (*(BYTE*)region_ptr == aob_raw[pattern_ptr]) {
                        region_ptr++;
                        pattern_ptr++;
                        if (pattern_ptr == aob_raw_size) {
                            // 匹配成功，返回匹配位置
                            signature = region_ptr - pattern_ptr;
                            Log("Found signature at ", convert_NumberToHexString(signature));
                            mutex.lock();
                            result.push_back(signature);
                            result_count++;
                            if (result_count == result_max)
                            {
                                stop_flag = true;
                                checked_regions += numRegionsChecked;
                                mutex.unlock();
                                return result;
                            }
                            mutex.unlock();
                        }
                    }
                    else {
                        if (pattern_ptr != 0) {
                            // 根据部分匹配表移动模式串
                            pattern_ptr = pmt[pattern_ptr - 1];
                        }
                        else {
                            region_ptr++;
                        }
                    }
                    //current_address = region_ptr;
                    //for (size_t i = 0; i < aob_raw_size; i++)
                    //{
                    //    if (*(BYTE*)current_address != aob_raw[i])
                    //    {
                    //        current_address++;
                    //        break;
                    //    }
                    //    else if (i == aob_raw_size - 1)
                    //    {
                    //        // 找到 AOB 签名，返回其地址
                    //        signature = current_address - aob_raw_size + 1;
                    //        Log("Found signature at ", NumberToHexString(signature));
                    //        mutex.lock();
                    //        result.push_back(signature);
                    //        result_count++;
                    //        if (result_count == result_max)
                    //        {
                    //            stop_flag = true;
                    //            checked_regions += numRegionsChecked;
                    //            mutex.unlock();
                    //            return result;
                    //        }
                    //        mutex.unlock();
                    //    }
                    //    current_address++;
                    //}
                    //region_ptr++;
                }
            }
            else
            {
                //Log("Skipped region: ", NumberToHexString(regionStart));

            }

            numRegionsChecked++;
            regionStart += memoryInfo.RegionSize;
        }
        mutex.lock();
        checked_regions += numRegionsChecked;
        mutex.unlock();
        return result;
    }
    static std::vector<uintptr_t> mergeAndSort_Results(std::vector<std::vector<uintptr_t>> results)
    {
        std::vector<size_t> mergedResults;

        for (const auto& threadResults : results) {
            mergedResults.insert(mergedResults.end(), threadResults.begin(), threadResults.end());
        }

        std::sort(mergedResults.begin(), mergedResults.end());
        return mergedResults;
    }

    static std::vector<uintptr_t> AobScan(std::string aob, const TCHAR* module_name = L"", size_t result_max = 1) {
        DWORD processId = GetCurrentProcessId();
        if (!is_Init) {
            initialize(processId);
        }
        UINT32 index = 0;
        if (module_name != L"") {
            index = module_infos->get_ModuleInfo_index(module_name);
            if (index < 0)
            {
                std::string error = "Module name: " + wstr_to_str(module_name) + " not found!";
                Log(error);
                ShowErrorPopup(error);
                return {};
            }
        }
        else {
            module_name = module_infos->get_ModuleName(index).c_str();
        }
        // 获取Aob 的原始字节序列
        std::vector<BYTE> aob_raw;
        // 获取Aob 的掩码
        std::vector<bool> aob_mask;
        bool no_mask = true;
        // 将 AOB 字符串转换为原始字节序列
        if (!convert_AobStringToAobRaw(aob, aob_raw, aob_mask, no_mask)) {
            return {};
        }
        UINT32 aob_raw_size = aob_raw.size();

        /*std::cout << aobraw_to_aobstr(aob_raw) << std::endl;

        for (int i = 0; i < aob_raw_size; i++)
        {
            std::cout << aob_mask[i] << ' ';
        }
        std::cout << std::endl;*/

        // 获取当前模块的基址
        uintptr_t module_start = module_infos->get_BaseAddress(index);
        uintptr_t module_end = module_infos->get_EndAddress(index);

        //// 打印进程信息和 AOB
        //Log("Module name: ", wstr_to_str(module_name));
        //Log("Process ID: ", processId);
        //Log("Module base address: ", NumberToHexString(module_start));
        //Log("Module end address: ", NumberToHexString(module_end));
        Log("AOB: ", aob);


        // 初始化循环变量和常量
        size_t checked_regions = 0;
        size_t result_count = 0;
        bool stop_flag = false;

        size_t single_thread_module_size = (module_end - module_start) / cpu_CoreCount;
        std::vector<std::future<std::vector<uintptr_t>>> futures;
        std::mutex mutex;

        std::vector<UINT32> pmt = {};
        if (no_mask) {
            build_PMT(aob_raw, pmt, aob_raw_size);
        }
        /*Log("PMT: ");
        for (auto& i : pmt)
        {
            Log(i);
        }
        std::cout << std::endl;*/

        for (int i = 0; i < cpu_CoreCount; i++) {
            uintptr_t start = module_start + i * single_thread_module_size;
            uintptr_t end = start + single_thread_module_size;
            if (i == cpu_CoreCount - 1) {
                end = module_end;
            }
            if (no_mask) {
                futures.emplace_back(std::async(std::launch::async, scaner_KMP, aob_raw, pmt, start,
                    end, result_max, std::ref(result_count), std::ref(stop_flag), std::ref(checked_regions),
                    std::ref(mutex)));
            }
            else {
                futures.emplace_back(std::async(std::launch::async, scaner, aob_raw, aob_mask, start,
                    end, result_max, std::ref(result_count), std::ref(stop_flag), std::ref(checked_regions),
                    std::ref(mutex)));
            }
        }
        // 等待所有线程完成并获取结果
        std::vector<std::vector<uintptr_t>> results;
        for (auto& future : futures) {
            results.push_back(future.get());
        }
        std::vector<uintptr_t> merged_results = mergeAndSort_Results(results);
        if (merged_results.empty()) {
            // 打印停止信息，显示错误弹窗并返回 0
            Log("Stopped at: ", convert_NumberToHexString(module_end), ", num regions checked: ", checked_regions);
            std::string error = "AOB not found! (" + aob + ")";
            ShowErrorPopup(error);
            return {};
        }
        return merged_results;

    }


    //// 检查两个 AOB 是否匹配
    //static bool CheckIfAobsMatch(std::string aob1, std::string aob2)
    //{
    //    // 将两个 AOB 字符串分割为标记
    //    std::vector<std::string> aob1Tokens = TokenifyAobString(aob1);
    //    std::vector<std::string> aob2Tokens = TokenifyAobString(aob2);

    //    // 获取较短的 AOB 字符串长度
    //    size_t shortestAobLength = aob1Tokens.size() < aob2Tokens.size() ? aob1Tokens.size() : aob2Tokens.size();

    //    // 遍历两个 AOB 字符串的标记
    //    for (size_t i = 0; i < shortestAobLength; i++)
    //    {
    //        // 判断标记是否为掩码
    //        bool tokenIsMasked = aob1Tokens[i] == muAobMask || aob2Tokens[i] == muAobMask;

    //        // 如果标记为掩码，则跳过此次循环
    //        if (tokenIsMasked)
    //        {
    //            continue;
    //        }

    //        // 检查两个 AOB 字符串在当前位置的标记是否相等，如果不相等，显示错误弹窗并返回 false
    //        if (aob1Tokens[i] != aob2Tokens[i])
    //        {
    //            ShowErrorPopup("Bytes do not match!");
    //            return false;
    //        }
    //    }

    //    // 如果遍历完成，说明两个 AOB 字符串匹配，返回 true
    //    return true;
    //}
    /*CheckIfAobsMatch 函数：
    作用：检查两个 AOB 是否匹配。
    参数：aob1 和 aob2 - 要比较的两个 AOB 字符串。
    返回值：如果匹配返回 true，否则返回 false。
    将两个 AOB 字符串分割为标记。
    获取较短的 AOB 字符串长度。
    遍历两个 AOB 字符串的标记：
    如果标记是掩码，跳过当前循环。
    如果标记不相等，显示错误弹窗并返回 false。
    如果遍历完成，说明两个 AOB 字符串匹配，返回 true。*/

    //// 替换指定地址的字节序列
    //static bool ReplaceExpectedBytesAtAddress(uintptr_t address, std::string expectedBytes, std::string newBytes)
    //{
    //    // 验证期望的字节和新字节的有效性
    //    if (!VerifyAobs({ expectedBytes, newBytes }))
    //    {
    //        return false;
    //    }

    //    // 将期望的字节和当前地址处的字节拷贝到缓冲区
    //    std::vector<std::string> expectedBytesTokens = TokenifyAobString(expectedBytes);
    //    std::vector<unsigned char> existingBytesBuffer(expectedBytesTokens.size(), 0);
    //    MemCopy((uintptr_t)&existingBytesBuffer[0], address, existingBytesBuffer.size());

    //    // 将缓冲区中的字节转换为字符串形式
    //    std::string existingBytes = RawAobToStringAob(existingBytesBuffer);

    //    // 记录日志：地址处的字节、期望的字节和新字节
    //    Log("Bytes at address: ", existingBytes);
    //    Log("Expected bytes: ", expectedBytes);
    //    Log("New bytes: ", newBytes);

    //    // 检查当前地址处的字节与期望的字节是否匹配
    //    if (CheckIfAobsMatch(existingBytes, expectedBytes))
    //    {
    //        Log("Bytes match");

    //        // 将新字节转换为原始字节序列，并将其拷贝到指定地址
    //        std::vector<unsigned char> rawNewBytes = StringAobToRawAob(newBytes);
    //        MemCopy(address, (uintptr_t)&rawNewBytes[0], rawNewBytes.size());

    //        // 记录日志：应用了补丁
    //        Log("Patch applied");
    //        return true;
    //    }

    //    // 如果字节不匹配，返回 false
    //    return false;
    //}
    /*ReplaceExpectedBytesAtAddress 函数：
    作用：替换指定地址处的字节序列。
    参数：
    address - 要替换字节的地址。
    expectedBytes - 期望的字节序列的字符串表示。
    newBytes - 新的字节序列的字符串表示。
    返回值：如果成功替换返回 true，否则返回 false。
    验证期望的字节和新字节的有效性。
    将期望的字节和当前地址处的字节拷贝到缓冲区。
    将缓冲区中的字节转换为字符串形式，记录日志。
    检查当前地址处的字节与期望的字节是否匹配：
        如果匹配，将新字节转换为原始字节序列，并将其拷贝到指定地址，记录日志，返回 true。
        如果不匹配，返回 false。*/

        // 根据窗口名称获取窗口句柄
    static void get_WindowHandleByName(std::string windowName)
    {
        // 如果窗口句柄为 NULL，进行查找
        if (muWindow == NULL)
        {
            // 循环尝试查找窗口句柄，最多尝试 10000 次
            for (size_t i = 0; i < 10000; i++)
            {
                // 使用 FindWindowExA 查找窗口句柄
                HWND hwnd = FindWindowExA(NULL, NULL, NULL, windowName.c_str());

                // 获取窗口所属进程的 ID
                DWORD processId = 0;
                GetWindowThreadProcessId(hwnd, &processId);

                // 如果窗口所属进程的 ID 与当前进程的 ID 相同，表示找到了目标窗口
                if (processId == GetCurrentProcessId())
                {
                    // 将窗口句柄赋值给 muWindow，记录日志，结束循环
                    muWindow = hwnd;
                    Log("FindWindowExA: found window handle");
                    break;
                }

                // 暂停 1 毫秒，继续下一次尝试
                Sleep(1);
            }
        }
    }
    /*GetWindowHandleByName 函数：
        作用：根据窗口名称获取窗口句柄。
        参数：windowName - 要查找的窗口名称。
        如果窗口句柄为 NULL，进行查找：
            循环尝试查找窗口句柄，最多尝试 10000 次。
            使用 FindWindowExA 查找窗口句柄。
            获取窗口所属进程的 ID。
            如果窗口所属进程的 ID 与当前进程的 ID 相同，表示找到了目标窗口：
                将窗口句柄赋值给 muWindow。
                记录日志。
                结束循环。
            暂停 1 毫秒，继续下一次尝试。*/

            // 枚举窗口句柄的回调函数
    static BOOL CALLBACK enum_WindowHandles(HWND hwnd, LPARAM lParam)
    {
        // 获取窗口所属进程的 ID
        DWORD processId = NULL;
        GetWindowThreadProcessId(hwnd, &processId);

        // 如果窗口所属进程的 ID 与当前进程的 ID 相同
        if (processId == GetCurrentProcessId())
        {
            // 用于存储窗口标题的缓冲区
            char buffer[100];

            // 获取窗口标题
            GetWindowTextA(hwnd, buffer, 100);

            // 记录日志：找到属于当前进程的窗口
            Log("Found window belonging to ER: ", buffer);

            // 如果窗口标题中包含 muGameName
            if (std::string(buffer).find(muGameName) != std::string::npos)
            {
                // 记录日志：选中窗口句柄
                Log(buffer, " handle selected");

                // 将窗口句柄赋值给 muWindow
                muWindow = hwnd;

                // 返回 false，表示找到目标窗口，停止枚举
                return false;
            }
        }

        // 返回 true，继续枚举
        return true;
    }
    /*EnumWindowHandles 回调函数：
        作用：用于 EnumWindows 函数的回调，枚举窗口句柄。
        参数：
            hwnd - 当前枚举到的窗口句柄。
            lParam - 用户定义的参数（未在代码中使用）。
        获取窗口所属进程的 ID。
            如果窗口所属进程的 ID 与当前进程的 ID 相同：
            用于存储窗口标题的缓冲区。
            获取窗口标题。
            记录日志：找到属于当前进程的窗口。
            如果窗口标题中包含 muGameName：
                记录日志：选中窗口句柄。
                将窗口句柄赋值给 muWindow。
                返回 false，表示找到目标窗口，停止枚举。
        返回 true，表示继续枚举。*/


        // 通过枚举获取窗口句柄
    static void get_WindowHandleByEnumeration()
    {
        // 如果窗口句柄为 NULL
        if (muWindow == NULL)
        {
            // 记录日志：正在枚举窗口
            Log("Enumerating windows...");

            // 循环尝试枚举窗口句柄，最多尝试 10000 次
            for (size_t i = 0; i < 10000; i++)
            {
                // 调用 EnumWindows 函数，使用 EnumWindowHandles 回调
                EnumWindows(&enum_WindowHandles, NULL);

                // 如果窗口句柄不为空，表示找到目标窗口，结束循环
                if (muWindow != NULL)
                {
                    break;
                }

                // 暂停 1 毫秒，继续下一次尝试
                Sleep(1);
            }
        }
    }

    // 获取窗口句柄的主函数
    static bool get_WindowHandle()
    {
        // 记录日志：正在查找应用程序窗口
        Log("Finding application window...");

        // 通过窗口名称获取窗口句柄
        get_WindowHandleByName(muExpectedWindowName);

        // 从经验来看，仅使用一种技术可能会难以一致地找到游戏窗口，
        // 所以我们使用额外的备用技术。
        get_WindowHandleByEnumeration();

        // 返回窗口句柄是否成功获取（不为 NULL 表示成功）
        return (muWindow == NULL) ? false : true;
    }

    // 尝试获取窗口句柄
    static void get_WindowHandle_Attempt()
    {
        // 静态变量，标志是否已尝试获取窗口句柄
        static bool hasAttemptedToGetWindowHandle = false;

        // 如果尚未尝试获取窗口句柄
        if (!hasAttemptedToGetWindowHandle)
        {
            // 调用 GetWindowHandle 函数尝试获取窗口句柄
            if (get_WindowHandle())
            {
                // 用于存储窗口标题的缓冲区
                char buffer[100];

                // 获取窗口标题
                GetWindowTextA(muWindow, buffer, 100);

                // 记录日志：找到应用程序窗口
                Log("Found application window: ", buffer);
            }
            else
            {
                // 记录日志：获取窗口句柄失败，输入将在全局范围内被检测
                Log("Failed to get window handle, inputs will be detected globally!");
            }

            // 设置标志，表示已尝试获取窗口句柄
            hasAttemptedToGetWindowHandle = true;
        }
    }


    // 检查键是否被按下
    static bool are_KeysPressed(std::vector<unsigned short> keys, bool trueWhileHolding = false, bool checkController = false)
    {
        // 静态变量，用于存储尚未释放的按键组合
        static std::vector<std::vector<unsigned short>> notReleasedKeys;

        // 尝试获取窗口句柄
        get_WindowHandle_Attempt();

        // 如果窗口不在前台，则忽略输入
        bool ignoreOutOfFocusInput = muWindow != NULL && muWindow != GetForegroundWindow();
        if (ignoreOutOfFocusInput)
        {
            return false;
        }

        // 按键数和当前被按下的按键数
        size_t numKeys = keys.size();
        size_t numKeysBeingPressed = 0;

        // 如果检查控制器
        if (checkController)
        {
            // 遍历所有控制器
            for (DWORD controllerIndex = 0; controllerIndex < XUSER_MAX_COUNT; controllerIndex++)
            {
                XINPUT_STATE state = { 0 };
                DWORD result = XInputGetState(controllerIndex, &state);

                // 如果获取控制器状态成功
                if (result == ERROR_SUCCESS)
                {
                    // 遍历指定的按键
                    for (auto key : keys)
                    {
                        // 如果按键与控制器按下的按键相匹配
                        if ((key & state.Gamepad.wButtons) == key)
                        {
                            numKeysBeingPressed++;
                        }
                    }
                }
            }
        }
        else
        {
            // 遍历指定的按键
            for (auto key : keys)
            {
                // 如果按键被按下
                if (GetAsyncKeyState(key))
                {
                    numKeysBeingPressed++;
                }
            }
        }

        // 查找当前按下的按键组合是否在尚未释放的按键组合中
        auto iterator = std::find(notReleasedKeys.begin(), notReleasedKeys.end(), keys);
        bool keysBeingHeld = iterator != notReleasedKeys.end();

        // 如果所有指定的按键都被按下
        if (numKeysBeingPressed == numKeys)
        {
            // 如果按键组合正在被保持
            if (keysBeingHeld)
            {
                // 如果在按住期间不应返回 true，则返回 false
                if (!trueWhileHolding)
                {
                    return false;
                }
            }
            else
            {
                // 记录按键组合为尚未释放
                notReleasedKeys.push_back(keys);
            }
        }
        else
        {
            // 如果按键组合正在被保持
            if (keysBeingHeld)
            {
                // 从尚未释放的按键组合中移除
                notReleasedKeys.erase(iterator);
            }

            // 返回 false，因为未按下所有指定的按键
            return false;
        }

        // 返回 true，因为所有指定的按键都被按下
        return true;
    }

    // 重载函数，检查单个按键是否被按下
    static bool are_KeysPressed(unsigned short key, bool trueWhileHolding = false, bool checkController = false)
    {
        return are_KeysPressed({ key }, trueWhileHolding, checkController);
    }
    /*AreKeysPressed 函数：
    作用：检查给定的按键组合是否被按下。
    静态变量 notReleasedKeys 用于存储尚未释放的按键组合。
    调用 AttemptToGetWindowHandle 函数尝试获取窗口句柄。
    如果窗口不在前台，则忽略输入。
    参数 keys：要检查的按键组合。
    参数 trueWhileHolding：指定是否在按住期间返回 true。
    参数 checkController：指定是否检查控制器按键。
    遍历按键：
        如果检查控制器，遍历所有控制器，检查按键是否被按下。
        如果不检查控制器，使用 GetAsyncKeyState 函数检查按键是否被按下。
    查找当前按下的按键组合是否在尚未释放的按键组合中。
    如果所有指定的按键都被按下：
        如果按键组合正在被保持：
            如果在按住期间不应返回 true，则返回 false。
        否则，记录按键组合为尚未释放。
    否则，如果按键组合正在被保持，从尚未释放的按键组合中移除。
    返回 true，因为所有指定的按键都被按下。

    AreKeysPressed 重载函数：
    作用：检查单个按键是否被按下。调用上述的主函数并传递单个按键的集合。*/



    //读取指定地址的内存指针
    inline static bool read_Pointer(uintptr_t& address, std::vector<uintptr_t> offsets)
    {
        //uintptr_t ptr1 = address;
        for (const auto& offset : offsets)
        {
            if (!is_MemReadable(address))
                return false;
            address = *(uintptr_t*)address + offset;
            //Log("address ", convert_NumberToHexString(address));
        }

        return true;

    }

    inline static bool read_BytesReturnStr(std::string& result, uintptr_t address, size_t size, std::vector<uintptr_t> offsets = {}) {
        if (!offsets.empty())
            if (!read_Pointer(address, offsets))
                return false;
        if (!is_MemReadable(address))
            return false;
        // 分配足够的内存来存储读取的数据
        char* buffer = new char[size];
        std::vector<char> bytes;
        // 将地址转换为指针类型
        void* ptr = reinterpret_cast<void*>(address);

        // 通过memcpy读取内存数据
        std::memcpy(buffer, ptr, size);

        // 将读取的数据转换为十六进制字符串
        std::ostringstream hexStringStream;
        hexStringStream << std::hex << std::uppercase << std::setfill('0');
        for (size_t i = 0; i < size; ++i) {
            hexStringStream << std::setw(2) << static_cast<int>(static_cast<unsigned char>(buffer[i]));
            if (i != size - 1)
            {
                hexStringStream << " ";
            }
        }
        delete[] buffer;

        result = hexStringStream.str();

        // 返回十六进制字符串
        return true;

    }



    inline static bool read_Bytes(std::vector<byte>& result, uintptr_t address, size_t size, std::vector<uintptr_t> offsets = {})
    {
        if (!offsets.empty())
            if (!read_Pointer(address, offsets))
                return false;
        if (!is_MemReadable(address))
            return false;
        result.resize(size);
        if (!mem_Copy((uintptr_t)&result[0], address, size))
            return false;
        return true;
    }
    inline static bool write_Bytes(uintptr_t address, std::vector<byte> bytes, std::vector<uintptr_t> offsets = {})
    {
        if (!offsets.empty())
            if (!read_Pointer(address, offsets))
                return false;
        if (!is_MemReadable(address))
            return false;
        mem_Copy(address, (uintptr_t)&bytes[0], bytes.size());
        return true;
    }

    inline static bool read_SmallInteger(short& result, uintptr_t address, std::vector<uintptr_t> offsets = {})
    {
        if (!offsets.empty())
            if (!read_Pointer(address, offsets))
                return false;
        if (!is_MemReadable(address))
            return false;
        mem_Copy((uintptr_t)&result, address, sizeof(short));
        return true;
    }

    inline static bool write_SmallInteger(uintptr_t address, short value, std::vector<uintptr_t> offsets = {})
    {
        if (!offsets.empty())
            if (!read_Pointer(address, offsets))
                return false;
        if (!is_MemReadable(address))
            return false;
        mem_Copy(address, (uintptr_t)&value, sizeof(short));
        return true;
    }

    inline static bool read_Integer(int& result, uintptr_t address, std::vector<uintptr_t> offsets = {})
    {
        if (!offsets.empty())
            if (!read_Pointer(address, offsets))
                return false;
        if (!is_MemReadable(address))
            return false;
        mem_Copy((uintptr_t)&result, address, sizeof(int));
        return true;
    }
    inline static bool write_Integer(uintptr_t address, int value, std::vector<uintptr_t> offsets = {})
    {
        if (!offsets.empty())
            if (!read_Pointer(address, offsets))
                return false;
        if (!is_MemReadable(address))
            return false;
        mem_Copy(address, (uintptr_t)&value, sizeof(int));
        return true;
    }
    inline static bool read_Qword(LONGLONG& result, uintptr_t address, std::vector<uintptr_t> offsets = {})
    {
        if (!offsets.empty())
            if (!read_Pointer(address, offsets))
                return false;
        if (!is_MemReadable(address))
            return false;
        mem_Copy((uintptr_t)&result, address, sizeof(LONGLONG));
        return true;
    }
    inline static bool write_Qword(uintptr_t address, long long value, std::vector<uintptr_t> offsets = {})
    {
        if (!offsets.empty())
            if (!read_Pointer(address, offsets))
                return false;
        if (!is_MemReadable(address))
            return false;
        mem_Copy(address, (uintptr_t)&value, sizeof(long long));
        return true;
    }
    inline static bool read_Float(float& result, uintptr_t address, std::vector<uintptr_t> offsets = {})
    {
        if (!offsets.empty())
            if (!read_Pointer(address, offsets))
                return false;
        if (!is_MemReadable(address))
            return false;
        mem_Copy((uintptr_t)&result, address, sizeof(float));
        return true;
    }
    inline static bool write_Float(uintptr_t address, float value, std::vector<uintptr_t> offsets = {})
    {
        if (!offsets.empty())
            if (!read_Pointer(address, offsets))
                return false;
        if (!is_MemReadable(address))
            return false;
        mem_Copy(address, (uintptr_t)&value, sizeof(float));
        return true;
    }
    inline static bool read_Double(double& result, uintptr_t address, std::vector<uintptr_t> offsets = {})
    {
        if (!offsets.empty())
            if (!read_Pointer(address, offsets))
                return false;
        if (!is_MemReadable(address))
            return false;
        mem_Copy((uintptr_t)&result, address, sizeof(double));
        return true;
    }
    inline static bool write_Double(uintptr_t address, double value, std::vector<uintptr_t> offsets = {})
    {
        if (!offsets.empty())
            if (!read_Pointer(address, offsets))
                return false;
        if (!is_MemReadable(address))
            return false;
        mem_Copy(address, (uintptr_t)&value, sizeof(double));
        return true;
    }
    inline static bool read_String(std::string& result, uintptr_t address, size_t size, std::vector<uintptr_t> offsets = {})
    {
        if (!offsets.empty())
            if (!read_Pointer(address, offsets))
                return false;
        if (!is_MemReadable(address))
            return false;
        std::string str((char*)address, size);
        result = str;
        return true;
    }
    inline static bool write_String(uintptr_t address, std::string value, std::vector<uintptr_t> offsets = {})
    {
        if (!offsets.empty())
            if (!read_Pointer(address, offsets))
                return false;
        if (!is_MemReadable(address))
            return false;
        mem_Copy(address, (uintptr_t)value.c_str(), value.size());
        return true;
    }
    /*std::wstring read_wstring(uintptr_t address, size_t size, std::vector<long long> offsets = {})
    {
        if (!offsets.empty())
        {
            address = read_pointer(address, offsets);
        }
        ToggleMemoryProtection(false, address, size);
        std::wstring wstr((wchar_t*)address, size);
        ToggleMemoryProtection(true, address, size);
        return wstr;
    }*/


    inline static uintptr_t align(uintptr_t address, size_t size)
    {
        uintptr_t alignedAddress = address;
        while (alignedAddress % size != 0)
        {
            alignedAddress++;
        }
        return alignedAddress;
    }
    // 从特定内存地址开始分配内存
    static uintptr_t allocate_Memory(uintptr_t address, size_t size)
    {
        uintptr_t specificAddress = align(address, 16);
        LPVOID ptr = nullptr;
        bool plus_or_minus = true;
        // 尝试从指定地址开始查询未使用的内存
        MEMORY_BASIC_INFORMATION memInfo;
        while (VirtualQuery((LPCVOID)specificAddress, &memInfo, sizeof(memInfo)) != 0) {
            if (address + 0x7FFFFFFF < (LONGLONG)memInfo.BaseAddress + memInfo.RegionSize)
            {
                plus_or_minus = false;
                uintptr_t ba = 0x400000;
                specificAddress = (address - 0x80000000) > ba ? (address - 0x80000000) : ba;
                continue;
            }
            else if (address < (LONGLONG)memInfo.BaseAddress + memInfo.RegionSize && !plus_or_minus)
            {
                Log("Failed to allocate memory because it's too far away.");
                return 0;
            }
            if (memInfo.State == MEM_FREE && memInfo.RegionSize > size) {
                uintptr_t regionStart = (uintptr_t)memInfo.BaseAddress;
                while (regionStart < (uintptr_t)memInfo.BaseAddress + memInfo.RegionSize - size)
                {
                    // 找到未使用的内存区域
                    // 使用 VirtualAlloc 在特定地址上分配内存
                    ptr = VirtualAlloc((LPVOID)regionStart, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

                    if (ptr != nullptr) {
                        /*Log("BaseAddress: ", NumberToHexString(memInfo.BaseAddress), " RegionSize: "
                            , memInfo.RegionSize, " State: ", memInfo.State, " Protect: ", memInfo.Protect, " Type: ", memInfo.Type);*/
                        Log("Allocated memory at ", convert_NumberToHexString((uintptr_t)ptr));

                        // 在这里可以使用分配的内存

                        // 释放内存
                        //VirtualFree(ptr, 0, MEM_RELEASE);

                        return (uintptr_t)ptr;
                    }
                    else {
                        /*Log("BaseAddress: ", NumberToHexString(memInfo.BaseAddress), " RegionSize: "
                            , memInfo.RegionSize, " State: ", memInfo.State, " Protect: ", memInfo.Protect, " Type: ", memInfo.Type);*/
                            //Log("Failed to allocate memory at ", NumberToHexString((uintptr_t)specificAddress));
                    }

                    // 检查下一个地址
                    regionStart += 64;
                }
                //Log("Failed to allocate memory at ", convert_NumberToHexString((uintptr_t)specificAddress));
            }

            // 检查下一个地址
            specificAddress = (uintptr_t)memInfo.BaseAddress + memInfo.RegionSize;

        }

        //uintptr_t specificAddress = align(address, 16);
        //while (specificAddress + address < 0xFFFF0000)
        //{
        //	// 找到未使用的内存区域
        //	// 使用 VirtualAlloc 在特定地址上分配内存
        //	LPVOID ptr = VirtualAlloc((LPVOID)specificAddress, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

        //	if (ptr != nullptr) {
        //		/*Log("BaseAddress: ", NumberToHexString(memInfo.BaseAddress), " RegionSize: "
        //			, memInfo.RegionSize, " State: ", memInfo.State, " Protect: ", memInfo.Protect, " Type: ", memInfo.Type);*/
        //		Log("Allocated memory at ", NumberToHexString((uintptr_t)ptr));

        //		// 在这里可以使用分配的内存

        //		// 释放内存
        //		//VirtualFree(ptr, 0, MEM_RELEASE);

        //		return (uintptr_t)ptr;
        //	}
        //	else {
        //		/*Log("BaseAddress: ", NumberToHexString(memInfo.BaseAddress), " RegionSize: "
        //			, memInfo.RegionSize, " State: ", memInfo.State, " Protect: ", memInfo.Protect, " Type: ", memInfo.Type);*/
        //			//Log("Failed to allocate memory at ", NumberToHexString((uintptr_t)specificAddress));
        //	}

        //	// 检查下一个地址
        //	specificAddress += 64;
        //}
        std::string error = "Failed to allocate memory! " + convert_NumberToHexString(address);
        Log(error);
        ShowErrorPopup(error);
        return 0;

    }
    // 从特定内存地址开始分配内存
    static uintptr_t allocate_Memory_Far(uintptr_t address, size_t size)
    {
        bool plus_or_minus = true;
        uintptr_t specificAddress = (uintptr_t)(align(address, 16) + 0x80000000);
        LPVOID ptr = nullptr;
        if (specificAddress < address || specificAddress > 0x7fff00000000) {
            plus_or_minus = false;
            specificAddress = (uintptr_t)(align(address, 16) - 0x80000000);
        }

        // 尝试从指定地址开始查询未使用的内存
        MEMORY_BASIC_INFORMATION memInfo;
        while (VirtualQuery((LPCVOID)specificAddress, &memInfo, sizeof(memInfo)) != 0) {
            /*if (address + 0x7FFFFFFF < (LONGLONG)memInfo.BaseAddress + memInfo.RegionSize)
            {
                plus_or_minus = false;
                uintptr_t ba = 0x400000;
                specificAddress = (address - 0x80000000) > ba ? (address - 0x80000000) : ba;
                continue;
            }
            else if (address < (LONGLONG)memInfo.BaseAddress + memInfo.RegionSize && !plus_or_minus)
            {
                Log("Failed to allocate memory because it's too far away.");
                return 0;
            }*/
            if (memInfo.State == MEM_FREE && memInfo.RegionSize > size) {
                uintptr_t regionStart = (uintptr_t)memInfo.BaseAddress;
                while (regionStart < (uintptr_t)memInfo.BaseAddress + memInfo.RegionSize - size)
                {
                    // 找到未使用的内存区域
                    // 使用 VirtualAlloc 在特定地址上分配内存
                    ptr = VirtualAlloc((LPVOID)regionStart, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

                    if (ptr != nullptr) {
                        /*Log("BaseAddress: ", NumberToHexString(memInfo.BaseAddress), " RegionSize: "
                            , memInfo.RegionSize, " State: ", memInfo.State, " Protect: ", memInfo.Protect, " Type: ", memInfo.Type);*/
                        Log("Allocated memory at ", convert_NumberToHexString((uintptr_t)ptr));

                        // 在这里可以使用分配的内存

                        // 释放内存
                        //VirtualFree(ptr, 0, MEM_RELEASE);

                        return (uintptr_t)ptr;
                    }
                    else {
                        /*Log("BaseAddress: ", NumberToHexString(memInfo.BaseAddress), " RegionSize: "
                            , memInfo.RegionSize, " State: ", memInfo.State, " Protect: ", memInfo.Protect, " Type: ", memInfo.Type);*/
                            //Log("Failed to allocate memory at ", NumberToHexString((uintptr_t)specificAddress));
                    }

                    // 检查下一个地址
                    regionStart += 64;
                }
                //Log("Failed to allocate memory at ", convert_NumberToHexString((uintptr_t)specificAddress));
            }

            // 检查下一个地址
            if (plus_or_minus)
                specificAddress = (uintptr_t)memInfo.BaseAddress + memInfo.RegionSize;
            else
            {
                specificAddress = (uintptr_t)memInfo.BaseAddress - 1;
                if (specificAddress < 0x400000)
                    break;
            }

        }

        std::string error = "Failed to allocate memory! " + convert_NumberToHexString(address);
        Log(error);
        ShowErrorPopup(error);
        return 0;

    }
    static bool free_Memory(uintptr_t ptr)
    {
        if (VirtualFree((LPVOID)ptr, 0, MEM_RELEASE))
        {
            Log("Freed memory at ", convert_NumberToHexString(ptr));
            return true;
        }
        else
        {
            Log("Failed to free memory at ", convert_NumberToHexString(ptr));
            return false;
        }
    }

    //替换指定地址的字节序列
    static std::string replace_PlaceHolder(const std::string& str1, const std::string& str2) {
        if (str1.size() != str2.size()) {
            // 如果两个字符串长度不相等，无法进行替换
            ShowErrorPopup("Strings are not of the same length.");
            return str1;
        }

        std::string result = str1;  // 复制第一个字符串，用作修改
        size_t pos = result.find("??");  // 查找第一个匹配的"??"

        while (pos != std::string::npos) {
            // 将 "?? 替换为 str2 中相同位置的字符
            result.replace(pos, 2, str2.substr(pos, 2));
            pos = result.find("??", pos + 2);  // 继续查找下一个匹配的"??"
        }

        return result;
    }
    inline static void write_ByteStr(uintptr_t address, std::string byte_str, std::vector<uintptr_t> offsets = {})
    {
        size_t n = (byte_str.length()) / 3 + 1;
        if (!offsets.empty())
        {
            address = read_Pointer(address, offsets);
        }
        std::string ori_bytes_str;
        read_BytesReturnStr(ori_bytes_str, address, n);
        Log("Write bytes: ", byte_str);
        //Log("Original mem bytes: ", ori_bytes_str);
        byte_str = replace_PlaceHolder(byte_str, ori_bytes_str);
        //Log("Parsed bytes: ", byte_str);

        auto byte_raw = aobstr_to_aobraw(byte_str);
        size_t size = byte_raw.size();
        //ToggleMemoryProtection(false, address, size);
        mem_Copy(address, (uintptr_t)&byte_raw[0], size);
        //ToggleMemoryProtection(true, address, size);
    }

    // 在指定地址插入跳转钩子
    static bool hook_Far(uintptr_t address, uintptr_t destination, size_t extraClearance = 0)
    {
        // 设置额外的跳转清理间隔，默认为 0
        size_t clearance = 14 + extraClearance;
        ToggleMemoryProtection(false, address, clearance);
        // 使用 0x90（NOP 指令）清空跳转位置的指令
        mem_Set(address, 0x90, clearance);
        ToggleMemoryProtection(true, address, clearance);

        // 插入跳转指令（x86/x64）
        ToggleMemoryProtection(false, address, clearance);
        *(uintptr_t*)address = 0x0000000025ff;
        ToggleMemoryProtection(true, address, clearance);

        // 将跳转目标地址复制到跳转指令后面的位置
        ToggleMemoryProtection(false, address, clearance);
        mem_Copy((address + 6), (uintptr_t)&destination, 8);
        ToggleMemoryProtection(true, address, clearance);

        // 记录钩子的创建
        Log("Created jump from ", convert_NumberToHexString(address), " to ", convert_NumberToHexString(destination), " with a clearance of ", clearance);
        return true;
    }
    // 在指定地址插入跳转钩子
    static bool hook_Near(uintptr_t address, uintptr_t destination, size_t extraClearance = 0)
    {
        // 设置额外的跳转清理间隔，默认为 0
        size_t clearance = 5 + extraClearance;
        uintptr_t relative_address;
        uintptr_t next_address = address + 5;
        if (next_address + 0x7FFFFFFF >= destination)
        {
            relative_address = destination - next_address;
        }
        else if ((long long)next_address - 0x80000000 <= destination && (long long)next_address - 0x80000000 > 0x400000)
        {
            relative_address = 0x100000000 - (next_address - destination);
        }
        else
        {
            Log("Failed to hook_near because it's too far away.");
            return false;
        }

        Log("relative address ", convert_NumberToHexString(relative_address));

        ToggleMemoryProtection(false, address, clearance);
        // 使用 0x90（NOP 指令）清空跳转位置的指令
        mem_Set(address, 0x90, clearance);
        ToggleMemoryProtection(true, address, clearance);

        // 插入跳转指令（x86/x64）
        // ToggleMemoryProtection(false, address, clearance);
        //write_ByteStr(address, "E9 00 00 00 00");
        write_Bytes(address, { 0xE9, 0x00, 0x00, 0x00, 0x00 });
        // ToggleMemoryProtection(true, address, clearance);

        // 将跳转目标地址复制到跳转指令后面的位置
        ToggleMemoryProtection(false, address, clearance);
        mem_Copy((address + 1), (uintptr_t)&relative_address, 4);
        ToggleMemoryProtection(true, address, clearance);

        // 记录钩子的创建
        Log("Created jump from ", convert_NumberToHexString(address), " to ", convert_NumberToHexString(destination), " with a clearance of ", clearance);
        return true;
    }
    //// 在指定地址插入跳转钩子
    //static void Hook_x86(uintptr_t address, uintptr_t destination, size_t extraClearance = 0)
    //{
    //	// 设置额外的跳转清理间隔，默认为 0
    //	size_t clearance = 6 + extraClearance;

    //	ToggleMemoryProtection(false, address, clearance);
    //	// 使用 0x90（NOP 指令）清空跳转位置的指令
    //	MemSet(address, 0x90, clearance);
    //	ToggleMemoryProtection(true, address, clearance);

    //	// 插入跳转指令（x86/x64）
    //	// ToggleMemoryProtection(false, address, clearance);
    //	write_memery(address, "FF 25 00 00 00 00");
    //	// ToggleMemoryProtection(true, address, clearance);

    //	// 将跳转目标地址复制到跳转指令后面的位置
    //	ToggleMemoryProtection(false, address, clearance);
    //	MemCopy((address + 2), (uintptr_t)&destination, 4);
    //	ToggleMemoryProtection(true, address, clearance);

    //	// 记录钩子的创建
    //	Log("Created jump from ", NumberToHexString(address), " to ", NumberToHexString(destination), " with a clearance of ", clearance);
    //}
    /*Hook 函数：
        作用：在指定地址插入跳转钩子，将程序的执行流引导到指定的目标地址。
        参数 address：要插入钩子的地址。
        参数 destination：跳转的目标地址。
        参数 extraClearance：额外的清理间隔，默认为 0。
        clearance 计算了用于插入跳转指令的清理间隔。
        使用 MemSet 函数将跳转位置的指令清空为 NOP（0x90）。
        将跳转指令插入到指定地址（0x25ff）。
        使用 MemCopy 函数将目标地址复制到跳转指令后面的位置。
        记录钩子的创建，包括起始地址、目标地址和清理间隔。*/

        //64位截断
    inline static uint32_t U64_to_U32(uint64_t u64)
    {
        return static_cast<uint32_t>(u64);;
    }


    static uintptr_t convert_BytesToUintptr(const std::vector<BYTE>& bytes) { // 从字节转换为 uintptr_t
        //if (bytes.size() < sizeof(uintptr_t)) {
        //    std::cerr << "Error: Vector size is less than the size of uintptr_t." << std::endl;
        //    return 0;  // Or handle the error in an appropriate way for your application.
        //}
        uintptr_t result = 0;
        for (size_t i = 0; i < bytes.size(); ++i) {
            result |= static_cast<uintptr_t>(bytes[i]) << (8 * i);
        }
        return result;
    }
    static void align_10CC(std::string& str) {
        int len = 16 - (str.length() / 3 + 1) % 16;
        for (int i = 0; i < len; i++) {
            str += " CC";
        }
    }


    //std::vector<uint8_t> parse_hex(const std::string& hex)
    //{
    //	std::istringstream iss(hex);
    //	std::string s;
    //	std::vector<uint8_t> bytes;
    //	while (iss >> s)
    //	{
    //		if (s == "??")
    //		{
    //			bytes.push_back(0);
    //		}
    //		else
    //		{
    //			bytes.push_back((uint8_t)std::stoul(s, nullptr, 16));
    //		}
    //	}
    //	return bytes;
    //}

    //std::string parse_bytes(const uint8_t* bytes, size_t size)
    //{
    //	std::ostringstream oss;
    //	for (auto i = 0; i < size; ++i)
    //	{
    //		oss << std::hex << std::uppercase << std::setfill('0') << std::setw(2) << (int)bytes[i];
    //		if (i != size - 1)
    //		{
    //			oss << " ";
    //		}
    //	}
    //	return oss.str();
    //}
    //std::pair<std::vector<uint8_t>, std::string> parse_hex_mask(const std::string& hex)
    //{
    //	std::istringstream iss(hex);
    //	std::string s;
    //	std::vector<uint8_t> bytes;
    //	std::string mask;
    //	while (iss >> s)
    //	{
    //		if (s == "??")
    //		{
    //			bytes.push_back(0);
    //			mask.push_back('?');
    //		}
    //		else
    //		{
    //			bytes.push_back((uint8_t)std::stoul(s, nullptr, 16));
    //			mask.push_back('x');
    //		}
    //	}
    //	return { bytes, mask };
    //}

}



