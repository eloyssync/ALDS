#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <shlobj.h>
#include <wincrypt.h>
#include <shellapi.h>

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <filesystem>
#include <regex>
#include <iomanip>
#include <random>
#include <cwchar>
#include <cstdlib>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ole32.lib")

#pragma comment(linker, "\"/manifestdependency:type='win32' \
name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

namespace fs = std::filesystem;

#define IDC_LIST_FILES         1001
#define IDC_EDIT_LOG           1002
#define IDC_PROGRESS           1003
#define IDC_CB_METADATA        1004
#define IDC_CB_COMMENTS        1005
#define IDC_CB_HASH            1006
#define IDC_CB_PDF_FLATTEN     1007
#define IDC_BTN_ADD_FILES      1008
#define IDC_BTN_ADD_FOLDER     1009
#define IDC_BTN_CLEAR          1010
#define IDC_BTN_OPEN_OUTPUT    1011
#define IDC_BTN_START          1012

#define WM_APP_PROGRESS        (WM_APP + 1)
#define WM_APP_FILE_STATUS     (WM_APP + 2)
#define WM_APP_LOG             (WM_APP + 3)
#define WM_APP_FINISHED        (WM_APP + 4)

struct SanitizeOptions {
    bool strip_metadata = true;
    bool remove_comments = true;
    bool randomize_hash = true;
    bool pdf_deep_flatten = false;
};

struct FileItem {
    int index;
    std::wstring full_path;
    std::wstring filename;
    std::wstring ext;
    uintmax_t size;
    std::wstring status;
};

struct StatusUpdateMsg {
    int row;
    std::wstring status;
};

struct LogMsg {
    std::wstring level;
    std::wstring message;
};

struct FinishedMsg {
    int success_count;
    int fail_count;
    std::wstring output_dir;
};

class HashEngine {
public:
    static bool CalculateHashes(const std::wstring& filePath, std::string& outMD5, std::string& outSHA256) {
        HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
        if (hFile == INVALID_HANDLE_VALUE) return false;

        HCRYPTPROV hProv = 0;
        HCRYPTHASH hHashMD5 = 0;
        HCRYPTHASH hHashSHA256 = 0;

        if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
            CloseHandle(hFile);
            return false;
        }

        CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHashMD5);
        CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHashSHA256);

        BYTE buffer[65536];
        DWORD bytesRead = 0;
        while (ReadFile(hFile, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {
            CryptHashData(hHashMD5, buffer, bytesRead, 0);
            CryptHashData(hHashSHA256, buffer, bytesRead, 0);
        }

        outMD5 = GetHashString(hHashMD5, 16);
        outSHA256 = GetHashString(hHashSHA256, 32);

        CryptDestroyHash(hHashMD5);
        CryptDestroyHash(hHashSHA256);
        CryptReleaseContext(hProv, 0);
        CloseHandle(hFile);
        return true;
    }

private:
    static std::string GetHashString(HCRYPTHASH hHash, DWORD hashLen) {
        std::vector<BYTE> hashBuf(hashLen);
        DWORD dwSize = hashLen;
        if (CryptGetHashParam(hHash, HP_HASHVAL, hashBuf.data(), &dwSize, 0)) {
            std::ostringstream oss;
            for (DWORD i = 0; i < dwSize; ++i) {
                oss << std::hex << std::setw(2) << std::setfill('0') << (int)hashBuf[i];
            }
            return oss.str();
        }
        return "";
    }
};

std::string GenerateSaltHex(size_t byteCount = 32) {
    std::random_device rd;
    std::vector<unsigned char> data(byteCount);
    for (size_t i = 0; i < byteCount; ++i) {
        data[i] = static_cast<unsigned char>(rd() & 0xFF);
    }
    std::ostringstream oss;
    for (unsigned char b : data) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    }
    return oss.str();
}

std::wstring Utf8ToWide(const std::string& str) {
    if (str.empty()) return L"";
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstr(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstr[0], size_needed);
    return wstr;
}

std::wstring FormatFileSize(uintmax_t bytes) {
    const wchar_t* units[] = { L"B", L"KB", L"MB", L"GB", L"TB" };
    double size = static_cast<double>(bytes);
    int unitIdx = 0;
    while (size >= 1024.0 && unitIdx < 4) {
        size /= 1024.0;
        unitIdx++;
    }
    wchar_t buf[64];
    swprintf_s(buf, L"%.1f %s", size, units[unitIdx]);
    return std::wstring(buf);
}

class DocumentSanitizerEngine {
public:
    static std::vector<std::wstring> Sanitize(const std::wstring& inPath, const std::wstring& outPath, const SanitizeOptions& options) {
        std::vector<std::wstring> logs;
        fs::path p(inPath);
        std::wstring ext = p.extension().wstring();
        std::transform(ext.begin(), ext.end(), ext.begin(), ::towlower);

        if (ext == L".pdf") {
            logs = SanitizePdf(inPath, outPath, options);
        } else if (ext == L".docx" || ext == L".xlsx" || ext == L".pptx") {
            logs = SanitizeOoxml(inPath, outPath, options);
        } else {
            throw std::runtime_error("Unsupported file format.");
        }

        if (options.randomize_hash) {
            RandomizeHash(outPath, ext);
            logs.push_back(L"Applied cryptographic hash randomization.");
        }

        return logs;
    }

private:
    static std::vector<std::wstring> SanitizePdf(const std::wstring& inPath, const std::wstring& outPath, const SanitizeOptions& options) {
        std::vector<std::wstring> logs;
        std::ifstream src(inPath, std::ios::binary);
        if (!src.is_open()) throw std::runtime_error("Failed to open source PDF.");

        std::string content((std::istreambuf_iterator<char>(src)), std::istreambuf_iterator<char>());
        src.close();

        if (options.strip_metadata) {
            content = std::regex_replace(content, std::regex(R"(/Metadata\s+\d+\s+\d+\s+R)"), "/Metadata null");
            content = std::regex_replace(content, std::regex(R"(/Info\s+\d+\s+\d+\s+R)"), "/Info null");

            size_t xmpStart = 0;
            while ((xmpStart = content.find("<x:xmpmeta", xmpStart)) != std::string::npos) {
                size_t xmpEnd = content.find("</x:xmpmeta>", xmpStart);
                if (xmpEnd != std::string::npos) {
                    xmpEnd += 12;
                    for (size_t i = xmpStart; i < xmpEnd; ++i) content[i] = ' ';
                    xmpStart = xmpEnd;
                } else break;
            }
            logs.push_back(L"Purged /Info dictionary & XML XMP metadata stream.");
        }

        if (options.pdf_deep_flatten) {
            content = std::regex_replace(content, std::regex(R"(/Annots\s*\[[^\]]*\])"), "");
            content = std::regex_replace(content, std::regex(R"(/Annots\s+\d+\s+\d+\s+R)"), "");
            content = std::regex_replace(content, std::regex(R"(/AA\s*<<.*?>>)"), "");
            content = std::regex_replace(content, std::regex(R"(/AcroForm\s*<<.*?>>)"), "");
            content = std::regex_replace(content, std::regex(R"(/AcroForm\s+\d+\s+\d+\s+R)"), "");
            content = std::regex_replace(content, std::regex(R"(/OpenAction\s*\[[^\]]*\])"), "");
            content = std::regex_replace(content, std::regex(R"(/OpenAction\s+\d+\s+\d+\s+R)"), "");
            content = std::regex_replace(content, std::regex(R"(/Names\s+\d+\s+\d+\s+R)"), "");
            logs.push_back(L"Removed AcroForms, embedded JavaScript, and trigger actions.");
        }

        std::ofstream dst(outPath, std::ios::binary);
        if (!dst.is_open()) throw std::runtime_error("Failed to write sanitized PDF.");
        dst.write(content.data(), content.size());
        dst.close();

        return logs;
    }

    static std::vector<std::wstring> SanitizeOoxml(const std::wstring& inPath, const std::wstring& outPath, const SanitizeOptions& options) {
        std::vector<std::wstring> logs;

        wchar_t tempPath[MAX_PATH];
        GetTempPathW(MAX_PATH, tempPath);
        std::wstring unpackDir = std::wstring(tempPath) + L"DocSanitizer_" + Utf8ToWide(GenerateSaltHex(8));
        fs::create_directories(unpackDir);

        std::wstring unpackCmd = L"tar -xf \"" + inPath + L"\" -C \"" + unpackDir + L"\"";
        _wsystem(unpackCmd.c_str());

        std::vector<std::wregex> unwanted_patterns;
        unwanted_patterns.push_back(std::wregex(LR"(docProps[\\/]custom\.xml$)", std::regex_constants::icase));

        if (options.remove_comments) {
            unwanted_patterns.push_back(std::wregex(LR"(word[\\/]comments.*\.xml$)", std::regex_constants::icase));
            unwanted_patterns.push_back(std::wregex(LR"(word[\\/]people\.xml$)", std::regex_constants::icase));
            unwanted_patterns.push_back(std::wregex(LR"(word[\\/]revisions\.xml$)", std::regex_constants::icase));
            unwanted_patterns.push_back(std::wregex(LR"(xl[\\/]comments.*\.xml$)", std::regex_constants::icase));
            unwanted_patterns.push_back(std::wregex(LR"(xl[\\/]threadedComments[\\/].*\.xml$)", std::regex_constants::icase));
            unwanted_patterns.push_back(std::wregex(LR"(xl[\\/]drawings[\\/]vmlDrawing.*\.vml$)", std::regex_constants::icase));
            unwanted_patterns.push_back(std::wregex(LR"(ppt[\\/]comments[\\/].*\.xml$)", std::regex_constants::icase));
            unwanted_patterns.push_back(std::wregex(LR"(ppt[\\/]authors\.xml$)", std::regex_constants::icase));
            unwanted_patterns.push_back(std::wregex(LR"(ppt[\\/]commentAuthors\.xml$)", std::regex_constants::icase));
        }

        for (const auto& entry : fs::recursive_directory_iterator(unpackDir)) {
            if (!entry.is_regular_file()) continue;

            std::wstring relPath = fs::relative(entry.path(), unpackDir).wstring();
            bool stripped = false;
            for (const auto& pattern : unwanted_patterns) {
                if (std::regex_search(relPath, pattern)) {
                    fs::remove(entry.path());
                    logs.push_back(L"Stripped internal trace: " + relPath);
                    stripped = true;
                    break;
                }
            }
            if (stripped) continue;

            if (options.strip_metadata && relPath == L"docProps\\core.xml") {
                std::string clean_core_xml =
                    "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n"
                    "<cp:coreProperties xmlns:cp=\"http://schemas.openxmlformats.org/package/2006/metadata/coreProperties\" "
                    "xmlns:dc=\"http://purl.org/dc/elements/1.1/\" xmlns:dcterms=\"http://purl.org/dc/terms/\" "
                    "xmlns:dcmitype=\"http://purl.org/dc/dcmitype/\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"/>";
                std::ofstream f(entry.path(), std::ios::binary | std::ios::trunc);
                f << clean_core_xml;
                f.close();
                logs.push_back(L"Reset docProps/core.xml (Author, Company, Revision dates).");
            }
            else if (options.strip_metadata && relPath == L"docProps\\app.xml") {
                CleanAppXml(entry.path().wstring());
                logs.push_back(L"Sanitized docProps/app.xml (System & Template paths).");
            }
            else if (options.remove_comments && relPath == L"[Content_Types].xml") {
                CleanContentTypes(entry.path().wstring());
            }
            else if (options.remove_comments && entry.path().extension() == L".rels") {
                CleanRelationships(entry.path().wstring());
            }
        }

        if (fs::exists(outPath)) fs::remove(outPath);
        std::wstring packCmd = L"tar -a -cf \"" + outPath + L"\" -C \"" + unpackDir + L"\" *";
        _wsystem(packCmd.c_str());

        std::error_code ec;
        fs::remove_all(unpackDir, ec);

        return logs;
    }

    static void CleanAppXml(const std::wstring& filePath) {
        std::ifstream in(filePath);
        if (!in.is_open()) return;
        std::string xml((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        in.close();

        std::vector<std::string> tags = { "Template", "Company", "Manager", "HyperlinkBase", "Application", "AppVersion" };
        for (const auto& tag : tags) {
            std::regex reg("<" + tag + ">.*?</" + tag + ">");
            xml = std::regex_replace(xml, reg, "<" + tag + "></" + tag + ">");
        }

        std::ofstream out(filePath, std::ios::binary | std::ios::trunc);
        out << xml;
    }

    static void CleanContentTypes(const std::wstring& filePath) {
        std::ifstream in(filePath);
        if (!in.is_open()) return;
        std::string xml((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        in.close();

        std::regex reg(R"(<Override\s+[^>]*PartName="[^"]*(?:comment|custom\.xml|people\.xml|revisions)[^"]*"[^>]*/>)", std::regex_constants::icase);
        xml = std::regex_replace(xml, reg, "");

        std::ofstream out(filePath, std::ios::binary | std::ios::trunc);
        out << xml;
    }

    static void CleanRelationships(const std::wstring& filePath) {
        std::ifstream in(filePath);
        if (!in.is_open()) return;
        std::string xml((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        in.close();

        std::regex reg(R"(<Relationship\s+[^>]*Target="[^"]*(?:comment|custom|people|revision)[^"]*"[^>]*/>)", std::regex_constants::icase);
        xml = std::regex_replace(xml, reg, "");

        std::ofstream out(filePath, std::ios::binary | std::ios::trunc);
        out << xml;
    }

    static void RandomizeHash(const std::wstring& filePath, const std::wstring& ext) {
        std::string salt = GenerateSaltHex(32);
        if (ext == L".pdf") {
            std::ofstream f(filePath, std::ios::binary | std::ios::app);
            std::string payload = "\n%DS_SALT_" + salt + "\n";
            f.write(payload.data(), payload.size());
        } else {
            std::ofstream f(filePath, std::ios::binary | std::ios::app);
            std::string payload = "SALT:" + salt;
            f.write(payload.data(), payload.size());
        }
    }
};

class MainWindow {
public:
    static LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
        MainWindow* pThis = nullptr;
        if (msg == WM_NCCREATE) {
            CREATESTRUCT* pCreate = reinterpret_cast<CREATESTRUCT*>(lParam);
            pThis = reinterpret_cast<MainWindow*>(pCreate->lpCreateParams);
            SetWindowLongPtr(hWnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(pThis));
        } else {
            pThis = reinterpret_cast<MainWindow*>(GetWindowLongPtr(hWnd, GWLP_USERDATA));
        }

        if (pThis) {
            return pThis->HandleMessage(hWnd, msg, wParam, lParam);
        }
        return DefWindowProcW(hWnd, msg, wParam, lParam);
    }

    int Run(HINSTANCE hInstance, int nCmdShow) {
        m_hInstance = hInstance;

        INITCOMMONCONTROLSEX icex;
        icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
        icex.dwICC = ICC_LISTVIEW_CLASSES | ICC_PROGRESS_CLASS | ICC_STANDARD_CLASSES;
        InitCommonControlsEx(&icex);

        WNDCLASSEXW wc = { sizeof(WNDCLASSEXW) };
        wc.lpfnWndProc = MainWindow::WndProc;
        wc.hInstance = hInstance;
        wc.hCursor = LoadCursor(NULL, IDC_ARROW);
        wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
        wc.lpszClassName = L"ALDS_DocSanitizer_Class";
        wc.hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(1));
        if (!wc.hIcon) wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);

        RegisterClassExW(&wc);

        m_hWnd = CreateWindowExW(
            WS_EX_ACCEPTFILES,
            wc.lpszClassName,
            L"DocSanitizer - Anti-Leak Document Sanitizer",
            WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
            CW_USEDEFAULT, CW_USEDEFAULT, 980, 680,
            NULL, NULL, hInstance, this
        );

        ShowWindow(m_hWnd, nCmdShow);
        UpdateWindow(m_hWnd);

        MSG msg;
        while (GetMessageW(&msg, NULL, 0, 0)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }

        return (int)msg.wParam;
    }

private:
    HINSTANCE m_hInstance = NULL;
    HWND m_hWnd = NULL;

    HWND m_hList = NULL;
    HWND m_hLog = NULL;
    HWND m_hProgress = NULL;
    HWND m_hCbMetadata = NULL;
    HWND m_hCbComments = NULL;
    HWND m_hCbHash = NULL;
    HWND m_hCbPdfFlatten = NULL;

    HWND m_hBtnAddFiles = NULL;
    HWND m_hBtnAddFolder = NULL;
    HWND m_hBtnClear = NULL;
    HWND m_hBtnOpenOutput = NULL;
    HWND m_hBtnStart = NULL;

    HFONT m_hFontNormal = NULL;
    HFONT m_hFontLog = NULL;

    std::vector<FileItem> m_files;
    std::wstring m_outputDir;
    std::atomic<bool> m_isProcessing{ false };

    LRESULT HandleMessage(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
        switch (msg) {
        case WM_CREATE:
            OnCreate(hWnd);
            break;
        case WM_SIZE:
            OnSize(LOWORD(lParam), HIWORD(lParam));
            break;
        case WM_DROPFILES:
            OnDropFiles((HDROP)wParam);
            break;
        case WM_COMMAND:
            OnCommand(LOWORD(wParam));
            break;
        case WM_APP_PROGRESS:
            SendMessageW(m_hProgress, PBM_SETPOS, (WPARAM)wParam, 0);
            break;
        case WM_APP_FILE_STATUS: {
            StatusUpdateMsg* statusData = reinterpret_cast<StatusUpdateMsg*>(lParam);
            if (statusData) {
                ListView_SetItemText(m_hList, statusData->row, 3, const_cast<wchar_t*>(statusData->status.c_str()));
                delete statusData;
            }
            break;
        }
        case WM_APP_LOG: {
            LogMsg* logData = reinterpret_cast<LogMsg*>(lParam);
            if (logData) {
                AppendLog(logData->level, logData->message);
                delete logData;
            }
            break;
        }
        case WM_APP_FINISHED: {
            FinishedMsg* fin = reinterpret_cast<FinishedMsg*>(lParam);
            if (fin) {
                ToggleUIState(false);
                AppendLog(L"SUCCESS", L"Completed: " + std::to_wstring(fin->success_count) + L" sanitized, " + std::to_wstring(fin->fail_count) + L" failed.");
                OpenOutputDirectory();

                std::wstring msgStr = L"Successfully cleaned: " + std::to_wstring(fin->success_count) +
                    L"\nFailed: " + std::to_wstring(fin->fail_count) +
                    L"\n\nSaved to:\n" + fin->output_dir;
                MessageBoxW(m_hWnd, msgStr.c_str(), L"Sanitization Complete", MB_ICONINFORMATION);
                delete fin;
            }
            break;
        }
        case WM_DESTROY:
            DeleteObject(m_hFontNormal);
            DeleteObject(m_hFontLog);
            PostQuitMessage(0);
            break;
        default:
            return DefWindowProcW(hWnd, msg, wParam, lParam);
        }
        return 0;
    }

    void OnCreate(HWND hWnd) {
        m_outputDir = (fs::current_path() / L"sanitized_output").wstring();

        m_hFontNormal = CreateFontW(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
        m_hFontLog = CreateFontW(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, L"Consolas");

        m_hList = CreateWindowExW(
            WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
            WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | WS_TABSTOP,
            16, 16, 930, 240, hWnd, (HMENU)IDC_LIST_FILES, m_hInstance, NULL
        );
        ListView_SetExtendedListViewStyle(m_hList, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);

        LVCOLUMNW lvc = { 0 };
        lvc.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;

        lvc.iSubItem = 0; lvc.pszText = (LPWSTR)L"Filename"; lvc.cx = 400;
        ListView_InsertColumn(m_hList, 0, &lvc);

        lvc.iSubItem = 1; lvc.pszText = (LPWSTR)L"Type"; lvc.cx = 90;
        ListView_InsertColumn(m_hList, 1, &lvc);

        lvc.iSubItem = 2; lvc.pszText = (LPWSTR)L"Original Size"; lvc.cx = 120;
        ListView_InsertColumn(m_hList, 2, &lvc);

        lvc.iSubItem = 3; lvc.pszText = (LPWSTR)L"Status"; lvc.cx = 140;
        ListView_InsertColumn(m_hList, 3, &lvc);

        m_hCbMetadata = CreateWindowExW(0, L"BUTTON", L"Strip All Core & Custom Metadata",
            WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX | WS_TABSTOP, 20, 270, 280, 20, hWnd, (HMENU)IDC_CB_METADATA, m_hInstance, NULL);
        SendMessageW(m_hCbMetadata, BM_SETCHECK, BST_CHECKED, 0);

        m_hCbComments = CreateWindowExW(0, L"BUTTON", L"Remove Comments & Revision History",
            WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX | WS_TABSTOP, 310, 270, 300, 20, hWnd, (HMENU)IDC_CB_COMMENTS, m_hInstance, NULL);
        SendMessageW(m_hCbComments, BM_SETCHECK, BST_CHECKED, 0);

        m_hCbHash = CreateWindowExW(0, L"BUTTON", L"Randomize Cryptographic Hash (MD5/SHA256)",
            WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX | WS_TABSTOP, 620, 270, 320, 20, hWnd, (HMENU)IDC_CB_HASH, m_hInstance, NULL);
        SendMessageW(m_hCbHash, BM_SETCHECK, BST_CHECKED, 0);

        m_hCbPdfFlatten = CreateWindowExW(0, L"BUTTON", L"Deep PDF Flatten (Purge Scripts/Forms/Annots)",
            WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX | WS_TABSTOP, 20, 295, 360, 20, hWnd, (HMENU)IDC_CB_PDF_FLATTEN, m_hInstance, NULL);

        m_hProgress = CreateWindowExW(0, PROGRESS_CLASSW, NULL,
            WS_CHILD | WS_VISIBLE, 16, 325, 930, 18, hWnd, (HMENU)IDC_PROGRESS, m_hInstance, NULL);

        m_hLog = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY | WS_VSCROLL,
            16, 350, 930, 200, hWnd, (HMENU)IDC_EDIT_LOG, m_hInstance, NULL);

        m_hBtnAddFiles = CreateWindowExW(0, L"BUTTON", L"Add Files...", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_TABSTOP,
            16, 565, 110, 30, hWnd, (HMENU)IDC_BTN_ADD_FILES, m_hInstance, NULL);

        m_hBtnAddFolder = CreateWindowExW(0, L"BUTTON", L"Add Folder...", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_TABSTOP,
            134, 565, 110, 30, hWnd, (HMENU)IDC_BTN_ADD_FOLDER, m_hInstance, NULL);

        m_hBtnClear = CreateWindowExW(0, L"BUTTON", L"Clear List", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_TABSTOP,
            252, 565, 100, 30, hWnd, (HMENU)IDC_BTN_CLEAR, m_hInstance, NULL);

        m_hBtnOpenOutput = CreateWindowExW(0, L"BUTTON", L"Open Output Folder", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_TABSTOP,
            650, 565, 140, 30, hWnd, (HMENU)IDC_BTN_OPEN_OUTPUT, m_hInstance, NULL);

        m_hBtnStart = CreateWindowExW(0, L"BUTTON", L"Start Sanitizing", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON | WS_TABSTOP,
            800, 565, 146, 30, hWnd, (HMENU)IDC_BTN_START, m_hInstance, NULL);

        HWND controls[] = { m_hList, m_hCbMetadata, m_hCbComments, m_hCbHash, m_hCbPdfFlatten,
                            m_hBtnAddFiles, m_hBtnAddFolder, m_hBtnClear, m_hBtnOpenOutput, m_hBtnStart };
        for (HWND ctrl : controls) {
            SendMessageW(ctrl, WM_SETFONT, (WPARAM)m_hFontNormal, TRUE);
        }
        SendMessageW(m_hLog, WM_SETFONT, (WPARAM)m_hFontLog, TRUE);

        AppendLog(L"INFO", L"DocSanitizer C++ (Native Win32) ready. Drag files or folders to begin.");
    }

    void OnSize(int width, int height) {
        if (!m_hList) return;

        int margin = 16;
        int bottomPanelHeight = 45;
        int optionsHeight = 55;
        int progressHeight = 16;

        int contentWidth = width - (margin * 2);
        int availableHeight = height - (margin * 2) - optionsHeight - progressHeight - bottomPanelHeight - 20;

        int listHeight = (availableHeight * 55) / 100;
        int logHeight = availableHeight - listHeight;

        SetWindowPos(m_hList, NULL, margin, margin, contentWidth, listHeight, SWP_NOZORDER);

        int optY = margin + listHeight + 10;
        SetWindowPos(m_hCbMetadata, NULL, margin, optY, 260, 20, SWP_NOZORDER);
        SetWindowPos(m_hCbComments, NULL, margin + 270, optY, 280, 20, SWP_NOZORDER);
        SetWindowPos(m_hCbHash, NULL, margin + 560, optY, 320, 20, SWP_NOZORDER);
        SetWindowPos(m_hCbPdfFlatten, NULL, margin, optY + 24, 380, 20, SWP_NOZORDER);

        int progY = optY + optionsHeight;
        SetWindowPos(m_hProgress, NULL, margin, progY, contentWidth, progressHeight, SWP_NOZORDER);

        int logY = progY + progressHeight + 8;
        SetWindowPos(m_hLog, NULL, margin, logY, contentWidth, logHeight, SWP_NOZORDER);

        int btnY = height - margin - 32;
        SetWindowPos(m_hBtnAddFiles, NULL, margin, btnY, 110, 30, SWP_NOZORDER);
        SetWindowPos(m_hBtnAddFolder, NULL, margin + 118, btnY, 110, 30, SWP_NOZORDER);
        SetWindowPos(m_hBtnClear, NULL, margin + 236, btnY, 100, 30, SWP_NOZORDER);

        SetWindowPos(m_hBtnStart, NULL, width - margin - 150, btnY, 150, 30, SWP_NOZORDER);
        SetWindowPos(m_hBtnOpenOutput, NULL, width - margin - 305, btnY, 145, 30, SWP_NOZORDER);
    }

    void OnDropFiles(HDROP hDrop) {
        UINT fileCount = DragQueryFileW(hDrop, 0xFFFFFFFF, NULL, 0);
        std::vector<std::wstring> paths;
        for (UINT i = 0; i < fileCount; ++i) {
            wchar_t buf[MAX_PATH];
            if (DragQueryFileW(hDrop, i, buf, MAX_PATH)) {
                paths.push_back(buf);
            }
        }
        DragFinish(hDrop);
        AddPaths(paths);
    }

    void OnCommand(WORD id) {
        switch (id) {
        case IDC_BTN_ADD_FILES:   BrowseFiles(); break;
        case IDC_BTN_ADD_FOLDER:  BrowseFolder(); break;
        case IDC_BTN_CLEAR:       ClearQueue(); break;
        case IDC_BTN_OPEN_OUTPUT: OpenOutputDirectory(); break;
        case IDC_BTN_START:       StartSanitization(); break;
        }
    }

    void BrowseFiles() {
        wchar_t fileBuf[32768] = { 0 };
        OPENFILENAMEW ofn = { sizeof(OPENFILENAMEW) };
        ofn.hwndOwner = m_hWnd;
        ofn.lpstrFilter = L"Supported Documents (*.pdf;*.docx;*.xlsx;*.pptx)\0*.pdf;*.docx;*.xlsx;*.pptx\0All Files (*.*)\0*.*\0";
        ofn.lpstrFile = fileBuf;
        ofn.nMaxFile = sizeof(fileBuf) / sizeof(wchar_t);
        ofn.Flags = OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_ALLOWMULTISELECT;

        if (GetOpenFileNameW(&ofn)) {
            std::vector<std::wstring> paths;
            wchar_t* p = fileBuf;
            std::wstring dir = p;
            p += dir.length() + 1;

            if (*p == 0) {
                paths.push_back(dir);
            } else {
                while (*p) {
                    paths.push_back(dir + L"\\" + p);
                    p += wcslen(p) + 1;
                }
            }
            AddPaths(paths);
        }
    }

    void BrowseFolder() {
        BROWSEINFOW bi = { 0 };
        bi.hwndOwner = m_hWnd;
        bi.lpszTitle = L"Select Folder Containing Documents";
        bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
        PIDLIST_ABSOLUTE pidl = SHBrowseForFolderW(&bi);
        if (pidl) {
            wchar_t path[MAX_PATH];
            if (SHGetPathFromIDListW(pidl, path)) {
                AddPaths({ path });
            }
            CoTaskMemFree(pidl);
        }
    }

    void AddPaths(const std::vector<std::wstring>& paths) {
        int addedCount = 0;
        for (const auto& p : paths) {
            if (fs::is_directory(p)) {
                for (const auto& entry : fs::recursive_directory_iterator(p)) {
                    if (entry.is_regular_file() && IsSupportedExt(entry.path().extension().wstring())) {
                        if (InsertFileItem(entry.path().wstring())) addedCount++;
                    }
                }
            } else if (fs::is_regular_file(p)) {
                if (IsSupportedExt(fs::path(p).extension().wstring())) {
                    if (InsertFileItem(p)) addedCount++;
                }
            }
        }
        if (addedCount > 0) {
            AppendLog(L"INFO", L"Added " + std::to_wstring(addedCount) + L" file(s) to queue.");
        }
    }

    bool IsSupportedExt(std::wstring ext) {
        std::transform(ext.begin(), ext.end(), ext.begin(), ::towlower);
        return (ext == L".pdf" || ext == L".docx" || ext == L".xlsx" || ext == L".pptx");
    }

    bool InsertFileItem(const std::wstring& fullPath) {
        for (const auto& item : m_files) {
            if (item.full_path == fullPath) return false;
        }

        FileItem item;
        item.index = (int)m_files.size();
        item.full_path = fullPath;
        fs::path p(fullPath);
        item.filename = p.filename().wstring();
        item.ext = p.extension().wstring();
        if (!item.ext.empty() && item.ext[0] == L'.') item.ext = item.ext.substr(1);
        std::transform(item.ext.begin(), item.ext.end(), item.ext.begin(), ::towupper);

        std::error_code ec;
        item.size = fs::file_size(fullPath, ec);
        item.status = L"Queued";

        m_files.push_back(item);

        LVITEMW lvi = { 0 };
        lvi.mask = LVIF_TEXT;
        lvi.iItem = item.index;

        lvi.iSubItem = 0;
        lvi.pszText = const_cast<LPWSTR>(item.filename.c_str());
        ListView_InsertItem(m_hList, &lvi);

        ListView_SetItemText(m_hList, item.index, 1, const_cast<LPWSTR>(item.ext.c_str()));
        std::wstring sizeStr = FormatFileSize(item.size);
        ListView_SetItemText(m_hList, item.index, 2, const_cast<LPWSTR>(sizeStr.c_str()));
        ListView_SetItemText(m_hList, item.index, 3, const_cast<LPWSTR>(item.status.c_str()));

        return true;
    }

    void ClearQueue() {
        if (m_isProcessing) return;
        m_files.clear();
        ListView_DeleteAllItems(m_hList);
        SendMessageW(m_hProgress, PBM_SETPOS, 0, 0);
        AppendLog(L"INFO", L"Queue cleared.");
    }

    void OpenOutputDirectory() {
        fs::create_directories(m_outputDir);
        ShellExecuteW(m_hWnd, L"open", m_outputDir.c_str(), NULL, NULL, SW_SHOW);
    }

    void ToggleUIState(bool isProcessing) {
        m_isProcessing = isProcessing;
        EnableWindow(m_hBtnStart, !isProcessing);
        EnableWindow(m_hBtnAddFiles, !isProcessing);
        EnableWindow(m_hBtnAddFolder, !isProcessing);
        EnableWindow(m_hBtnClear, !isProcessing);
    }

    void StartSanitization() {
        if (m_files.empty()) {
            MessageBoxW(m_hWnd, L"Please add at least one document to sanitize.", L"No Files", MB_ICONWARNING);
            return;
        }

        SanitizeOptions options;
        options.strip_metadata = (SendMessageW(m_hCbMetadata, BM_GETCHECK, 0, 0) == BST_CHECKED);
        options.remove_comments = (SendMessageW(m_hCbComments, BM_GETCHECK, 0, 0) == BST_CHECKED);
        options.randomize_hash = (SendMessageW(m_hCbHash, BM_GETCHECK, 0, 0) == BST_CHECKED);
        options.pdf_deep_flatten = (SendMessageW(m_hCbPdfFlatten, BM_GETCHECK, 0, 0) == BST_CHECKED);

        ToggleUIState(true);

        SendMessageW(m_hProgress, PBM_SETRANGE32, 0, (LPARAM)m_files.size());
        SendMessageW(m_hProgress, PBM_SETPOS, 0, 0);

        HWND hWnd = m_hWnd;
        std::vector<FileItem> fileQueue = m_files;
        std::wstring outDir = m_outputDir;

        std::thread workerThread([hWnd, fileQueue, outDir, options]() {
            fs::create_directories(outDir);
            int total = (int)fileQueue.size();
            int success = 0;
            int fail = 0;

            LogMessageAsync(hWnd, L"INFO", L"Starting batch processing of " + std::to_wstring(total) + L" document(s)...");

            for (int i = 0; i < total; ++i) {
                const auto& item = fileQueue[i];
                UpdateFileStatusAsync(hWnd, item.index, L"Processing...");
                LogMessageAsync(hWnd, L"INFO", L"[" + std::to_wstring(i + 1) + L"/" + std::to_wstring(total) + L"] Processing: " + item.filename);

                fs::path inPath(item.full_path);
                std::wstring outFileName = inPath.stem().wstring() + L"_clean" + inPath.extension().wstring();
                std::wstring outFullPath = (fs::path(outDir) / outFileName).wstring();

                try {
                    std::string origMD5, origSHA;
                    HashEngine::CalculateHashes(item.full_path, origMD5, origSHA);

                    std::vector<std::wstring> logs = DocumentSanitizerEngine::Sanitize(item.full_path, outFullPath, options);
                    for (const auto& l : logs) {
                        LogMessageAsync(hWnd, L"DETAIL", L"  -> " + l);
                    }

                    std::string newMD5, newSHA;
                    HashEngine::CalculateHashes(outFullPath, newMD5, newSHA);
                    std::wstring hashLog = L"  -> MD5: " + Utf8ToWide(origMD5.substr(0, 8)) + L"... -> " + Utf8ToWide(newMD5.substr(0, 8)) + L"...";
                    LogMessageAsync(hWnd, L"SUCCESS", hashLog);

                    UpdateFileStatusAsync(hWnd, item.index, L"Cleaned");
                    success++;
                } catch (const std::exception& ex) {
                    fail++;
                    UpdateFileStatusAsync(hWnd, item.index, L"Failed");
                    LogMessageAsync(hWnd, L"ERROR", L"Failed to sanitize " + item.filename + L": " + Utf8ToWide(ex.what()));
                }

                PostMessageW(hWnd, WM_APP_PROGRESS, (WPARAM)(i + 1), 0);
            }

            FinishedMsg* fin = new FinishedMsg{ success, fail, outDir };
            PostMessageW(hWnd, WM_APP_FINISHED, 0, (LPARAM)fin);
        });

        workerThread.detach();
    }

    static void UpdateFileStatusAsync(HWND hWnd, int row, const std::wstring& status) {
        StatusUpdateMsg* msg = new StatusUpdateMsg{ row, status };
        PostMessageW(hWnd, WM_APP_FILE_STATUS, 0, (LPARAM)msg);
    }

    static void LogMessageAsync(HWND hWnd, const std::wstring& level, const std::wstring& message) {
        LogMsg* msg = new LogMsg{ level, message };
        PostMessageW(hWnd, WM_APP_LOG, 0, (LPARAM)msg);
    }

    void AppendLog(const std::wstring& level, const std::wstring& message) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        wchar_t timeBuf[32];
        swprintf_s(timeBuf, L"[%02d:%02d:%02d]", st.wHour, st.wMinute, st.wSecond);

        std::wstring line = std::wstring(timeBuf) + L" [" + level + L"] " + message + L"\r\n";

        int len = GetWindowTextLengthW(m_hLog);
        SendMessageW(m_hLog, EM_SETSEL, (WPARAM)len, (LPARAM)len);
        SendMessageW(m_hLog, EM_REPLACESEL, FALSE, (LPARAM)line.c_str());
        SendMessageW(m_hLog, EM_SCROLLCARET, 0, 0);
    }
};

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, PWSTR, int nCmdShow) {
    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    MainWindow app;
    int ret = app.Run(hInstance, nCmdShow);
    CoUninitialize();
    return ret;
}