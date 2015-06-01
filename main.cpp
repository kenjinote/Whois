#define UNICODE
#pragma comment(lib,"wsock32")
#include <windows.h>
#include <winsock.h>
#include "resource.h"

TCHAR szClassName[] = TEXT("Whois");

// 文字列中の改行文字LF(単一)をCR+LFに変換する
// ※新たにバッファを確保しているのでGlobalFree関数で開放する必要がある
LPTSTR TextConvertCRtoLFCR(IN LPTSTR pszTextIn)
{
	DWORD dwSize = 0;
	if (!pszTextIn) return 0;
	LPTSTR p = pszTextIn;
	while (*p)
	{
		if (*p == TEXT('\n') && p != pszTextIn &&*(p - 1) != TEXT('\r'))
		{
			dwSize++;
		}
		dwSize++;
		p++;
	}
	LPTSTR pszTextOut = (LPTSTR)GlobalAlloc(0, sizeof(TCHAR)*(dwSize + 1));
	p = pszTextIn;
	LPTSTR q = pszTextOut;
	while (*p)
	{
		if (*p == TEXT('\n') && p != pszTextIn && *(p - 1) != TEXT('\r'))
		{
			*q = TEXT('\r');
			q++;
		}
		*q++ = *p++;
	}
	*q = 0;
	return pszTextOut;
}

// 文字列lpszTextに'.'が含まれているかどうか
BOOL IsIncludingDot(IN LPCSTR lpszText)
{
	if (!lpszText) return FALSE;
	const int nSize = lstrlenA(lpszText);
	for (int i = 0; i < nSize; i++)
		if (lpszText[i] == '.')
			return TRUE;
	return FALSE;
}

// 文字列lpszTextがホスト名を表しているかどうか
// ホスト名→TRUE IPアドレス→FALSE
BOOL IsHostName(IN LPCSTR lpszText)
{
	if (!lpszText) return FALSE;
	if (!IsIncludingDot(lpszText))return TRUE;
	const int nSize = lstrlenA(lpszText);
	for (int i = 0; i < nSize; i++)
		if (IsCharAlphaA(lpszText[i]))
			return TRUE;
	return FALSE;
}

// 入力ホスト名から問い合わせするWhoisサーバー名を返す
BOOL GetWhoisServerName(IN LPCSTR lpszHostName, OUT LPSTR lpszWhoisServerName)
{
	if (!lpszHostName) return FALSE;
	const int nLen = lstrlenA(lpszHostName);
	if (!nLen) return FALSE;
	LPSTR p = (LPSTR)(&(lpszHostName[nLen - 1]));
	while (p != lpszHostName)
	{
		if (*p == TEXT('.'))
		{
			lstrcpyA(lpszWhoisServerName, p + 1);
			CharLowerA(lpszWhoisServerName);
			lstrcatA(lpszWhoisServerName, ".whois-servers.net");
			return TRUE;
		}
		p--;
	}
	return FALSE;
}

// ホスト名からWhois情報を取得する
// ※新たにバッファを確保しているのでGlobalFree関数で開放する必要がある
LPWSTR GetWhoisText(IN LPCWSTR lpszHostName)
{
	char* lpszSrc = 0;
	SOCKET sock;
	if (!lpszHostName || !lstrlen(lpszHostName)) return 0;
	char szBuf[1024];
	WideCharToMultiByte(CP_ACP, 0, lpszHostName, -1, szBuf, 1024, 0, 0);
	const BOOL bIsHostName = IsHostName(szBuf);
	// トップレベルドメインが指定されていない場合は.jpを付加する
	if (bIsHostName && !IsIncludingDot(szBuf))
	{
		lstrcatA(szBuf, ".jp");
	}
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) != INVALID_SOCKET)
	{
		struct sockaddr_in address = { 0 };
		struct hostent * host = 0;

		address.sin_family = AF_INET;
		address.sin_port = htons(43);

		if (bIsHostName)
		{
			CHAR szWhoisServerName[MAX_PATH];
			if (GetWhoisServerName(szBuf, szWhoisServerName))
			{
				host = gethostbyname(szWhoisServerName);
			}
		}
		else
		{
			host = gethostbyname("whois.nic.ad.jp");
		}

		if (host)
		{
			address.sin_addr.s_addr = *((unsigned long *)host->h_addr);
			if (connect(sock, (struct sockaddr *)&address, sizeof(address)) == 0)
			{
				lstrcatA(szBuf, "\r\n");
				send(sock, szBuf, lstrlenA(szBuf), 0);
				lpszSrc = (char*)GlobalAlloc(0, 0);
				int nTotal = 0;
				for (;;)
				{
					const int dwRead = recv(sock, szBuf, sizeof(szBuf), 0);
					if (dwRead <= 0)
					{
						break;
					}
					char*lpTmp = (char*)GlobalReAlloc(
						lpszSrc, nTotal + dwRead + 1, GMEM_MOVEABLE);
					if (lpTmp == NULL)
					{
						break;
					}
					lpszSrc = lpTmp;
					CopyMemory(lpszSrc + nTotal, szBuf, dwRead);
					nTotal += dwRead;
				}
				if (nTotal)lpszSrc[nTotal] = 0;
			}
		}
		closesocket(sock);
	}
	if (lpszSrc)
	{
		// ISO-2022-JP を UNICODE に変換する
		const DWORD dwSize = MultiByteToWideChar(50220, 0, lpszSrc, -1, 0, 0);
		LPWSTR pwsz = (LPWSTR)GlobalAlloc(0, sizeof(WCHAR)*dwSize);
		MultiByteToWideChar(50220, 0, lpszSrc, -1, pwsz, dwSize);
		GlobalFree(lpszSrc);
		// 改行文字 LF を CR+LF に変換する
		LPTSTR p = TextConvertCRtoLFCR(pwsz);
		GlobalFree(pwsz);
		return p;
	}
	return 0;
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	static HWND hEdit;
	static HWND hEdit2;
	static HWND hButton;
	static HFONT hFont;
	switch (msg)
	{
	case WM_CREATE:
		hFont = CreateFont(-16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, TEXT("ＭＳ ゴシック"));
		hEdit = CreateWindowEx(WS_EX_CLIENTEDGE, TEXT("EDIT"), TEXT("BLOG.JP"),
			WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_UPPERCASE, 0, 0, 0, 0,
			hWnd, 0, ((LPCREATESTRUCT)(lParam))->hInstance, 0);
		hButton = CreateWindow(TEXT("BUTTON"), TEXT("Whois"),
			WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON, 0, 0, 0, 0,
			hWnd, (HMENU)IDOK, ((LPCREATESTRUCT)(lParam))->hInstance, 0);
		hEdit2 = CreateWindowEx(WS_EX_CLIENTEDGE, TEXT("EDIT"), 0,
			WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_TABSTOP | ES_AUTOVSCROLL |
			ES_AUTOHSCROLL | ES_READONLY | ES_MULTILINE,
			0, 0, 0, 0, hWnd, 0, ((LPCREATESTRUCT)(lParam))->hInstance, 0);
		SendMessage(hEdit, WM_SETFONT, (WPARAM)hFont, 0);
		SendMessage(hButton, WM_SETFONT, (WPARAM)hFont, 0);
		SendMessage(hEdit2, WM_SETFONT, (WPARAM)hFont, 0);
		break;
	case WM_COMMAND:
		if (LOWORD(wParam) == IDOK)
		{
			const DWORD dwSize = GetWindowTextLength(hEdit);
			LPTSTR lpszHost = (LPTSTR)GlobalAlloc(0, sizeof(TCHAR)*(dwSize + 1));
			GetWindowText(hEdit, lpszHost, dwSize + 1);
			LPTSTR lpszReturn = GetWhoisText(lpszHost);
			GlobalFree(lpszHost);
			SetWindowText(hEdit2, lpszReturn);
			GlobalFree(lpszReturn);
			SendMessage(hEdit, EM_SETSEL, 0, -1);
		}
		break;
	case WM_SIZE:
		MoveWindow(hEdit, 10, 10, 256, 32, 1);
		MoveWindow(hButton, 276, 10, 64, 32, 1);
		MoveWindow(hEdit2, 10, 50, LOWORD(lParam) - 20, HIWORD(lParam) - 60, 1);
		break;
	case WM_CLOSE:
		DestroyWindow(hWnd);
		break;
	case WM_DESTROY:
		DeleteObject(hFont);
		PostQuitMessage(0);
		break;
	default:
		return DefDlgProc(hWnd, msg, wParam, lParam);
	}
	return 0;
}


int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPreInst, LPSTR pCmdLine, int nCmdShow)
{
	WORD wVersionRequested = MAKEWORD(1, 1);
	WSADATA wsaData;
	MSG msg = { 0 };
	if (WSAStartup(wVersionRequested, &wsaData) != SOCKET_ERROR)
	{
		WNDCLASS wndclass = {
			0,
			WndProc,
			0,
			DLGWINDOWEXTRA,
			hInstance,
			LoadIcon(hInstance, (LPCTSTR)IDI_ICON1),
			0,
			0,
			0,
			szClassName
		};
		RegisterClass(&wndclass);
		HWND hWnd = CreateWindow(
			szClassName,
			TEXT("Whois"),
			WS_OVERLAPPEDWINDOW,
			CW_USEDEFAULT,
			0,
			CW_USEDEFAULT,
			0,
			0,
			0,
			hInstance,
			0
			);
		ShowWindow(hWnd, SW_SHOWDEFAULT);
		UpdateWindow(hWnd);
		while (GetMessage(&msg, 0, 0, 0))
		{
			if (!IsDialogMessage(hWnd, &msg))
			{
				TranslateMessage(&msg);
				DispatchMessage(&msg);
			}
		}
		WSACleanup();
	}
	return msg.wParam;
}
