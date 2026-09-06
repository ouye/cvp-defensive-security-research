# 一款 Windows DLL 注入工具的三个 Bug：源码分析与修复

最近在读一款 Windows 下的 DLL 注入工具的源码，顺手把它几个能稳定复现的问题跟了一遍。这工具支持四种注入策略、两种目标获取模式，代码量不大，但三个 Bug 的成因很有代表性——两个其实出在配套的测试 DLL 上，一个才是工具本身的逻辑漏洞。这里按我排查的顺序记录下来，工具具体是哪款就不点名了。

涉及的知识点：`CreateRemoteThread` · `QueueUserAPC` · `SetWindowsHookEx` · `Manual Map` · `Loader Lock` · Windows PE 加载器。

---

## 先厘清一个前提：四种策略的注册差异

排查之前得先搞清楚一件事，否则会一直被现象带偏：**为什么同样的测试 DLL，用 Manual Map 注入一切正常，换成另外三种就出问题。**

前三种策略（CreateRemoteThread、QueueUserAPC、SetWindowsHookEx）本质都是让目标进程去调 `LoadLibraryW`，DLL 会被 Windows 加载器**正式注册**进模块链表。Manual Map 则是自己把 PE 节区映射进去、手动调 DllMain，DLL **不经过加载器**。差别就落在这张表上：

| 特性 | CRT / APC / Hook | Manual Map |
|------|------------------|------------|
| 加载方式 | LoadLibraryW（加载器注册） | 手动映射（不注册） |
| DLL_PROCESS_ATTACH | ✅ 触发 | ✅ 触发（手动调用） |
| DLL_THREAD_ATTACH/DETACH | ❌ 触发（问题就出在这） | ✅ 不触发 |
| DLL_PROCESS_DETACH | ✅ 触发 | ⚠️ 视实现而定 |

`DLL_THREAD_ATTACH/DETACH` 这一行的差异，基本就是后面两个 Bug 的全部答案。手动映射的 DLL 不在加载器的模块链表里，线程创建/退出时系统不会挨个通知它，也就绕过了雷区。

---

## Bug 1：挂起拉起目标后，DLL 窗口刚弹出就自己关了

> **严重** · 影响 CreateRemoteThread / QueueUserAPC 策略 · Spawn（挂起拉起）模式 · x64 和 x86 目标均可复现

现象是：以挂起方式拉起目标进程再注入，测试 DLL 的对话框一闪就没了。一开始怀疑是工具的注入时机有问题，跟下来才发现根因在**测试 DLL 自己**，而且是两个缺陷叠加出来的。

### 缺陷 A：WM_INITDIALOG 漏了 break

对话框回调里，`WM_INITDIALOG` 分支结尾没写 `break`，直接 fall-through 进了 `WM_COMMAND`。对话框一创建完就顺势执行了 `MessageBoxA` + `EndDialog`：

```cpp
// 测试 DLL 原始代码（DialogProc）
case WM_INITDIALOG:
{
    HICON hIcon = LoadIcon(hMainInst, MAKEINTRESOURCE(IDI_SmallICON));
    SendMessage(hDlg, WM_SETICON, ICON_BIG, (LPARAM)hIcon);
    hDllHwnd = hDlg;
}
// ← 这里没有 break! 直接落进 WM_COMMAND
case WM_COMMAND:
{
    if (LOWORD(wParam) == IDC_btnExit)
    {
        MessageBoxA(hDlg, str, str1, MB_OK);
        EndDialog(hDlg, LOWORD(wParam));
    }
    break;
}
```

### 缺陷 B：DLL_THREAD_DETACH 里干了不该干的事

DllMain 中 `DLL_THREAD_ATTACH`、`DLL_THREAD_DETACH`、`DLL_PROCESS_DETACH` 三个 case 共用一段代码，而这段代码在弹 MessageBox、关对话框：

```cpp
// 测试 DLL 原始代码（DllMain）
case DLL_THREAD_ATTACH:
case DLL_THREAD_DETACH:
case DLL_PROCESS_DETACH:
{
    if (hDllHwnd)
    {
        MessageBoxA(hDllHwnd, str1, str, MB_OK);  // 还是在 Loader Lock 里
        EndDialog(hDllHwnd, FALSE);
    }
    break;
}
```

### 两者怎么串成事故的

```
远程线程调 LoadLibraryW   DLL_PROCESS_ATTACH        对话框创建完          远程线程退出              MessageBox + EndDialog
(CRT 策略)          →     启动 ShowDialog 线程  →   hDllHwnd 已赋值   →   触发 DLL_THREAD_DETACH →  对话框被直接关掉
```

Spawn 模式下时序特别不巧：挂起的主线程恢复后初始化偏慢，ShowDialog 线程有足够时间把对话框建好、`hDllHwnd` 也已赋值；这时那个执行 `LoadLibraryW` 的远程线程一退出，触发 `DLL_THREAD_DETACH`，看到非空的 `hDllHwnd`，于是 `EndDialog` 把刚弹出来的窗口关了。

换 Manual Map 之所以没事，就是前面那张表的结论——手动映射的 DLL 收不到 `DLL_THREAD_DETACH`，这条链根本起不来。

---

## Bug 2：附加模式下关掉 DLL 窗口，整个 UI 卡死

> **严重** · 影响 CreateRemoteThread / QueueUserAPC / SetWindowsHookEx 策略 · Attach（附加）模式

这个更狠，直接死锁。复现路径：

用户点按钮 → `MessageBoxA` 弹出 → 点确定后 `EndDialog` 关对话框 → ShowDialog 线程退出 → 触发 `DLL_THREAD_DETACH`（此时人在 Loader Lock 里）→ 代码又去调 `MessageBoxA`。

问题就在最后一步：`MessageBoxA` 要创建窗口、跑消息循环，而**创建窗口需要拿 Loader Lock**——可 `DllMain` 回调本身正持着这把锁。自己等自己，经典的 Loader Lock **自死锁**。

> Windows 的 DllMain 有一条铁律：**别在里面调 User32/GDI32 的函数**（MessageBox、CreateWindow 这类），也别调 LoadLibrary/LoadLibraryEx、CreateProcess、Shell 系列。微软文档写得很清楚，这些都可能引发 Loader Lock 死锁或循环依赖。这份测试 DLL 把该踩的坑踩了个遍。

```
点按钮                    ShowDialog 线程退出    系统拿 Loader Lock        DLL_THREAD_DETACH        MessageBox 又要
MessageBox + EndDialog →                     →  回调 DllMain          →  调 MessageBoxA       →   Loader Lock → 死锁
```

---

## Bug 3：十字瞄准抓不到刚启动的进程

> **中等** · 影响主窗口的十字瞄准控件、PID 输入框、以及后续注入操作

前两个都在测试 DLL，这个才是**工具本身**的逻辑问题。十字瞄准明明正确拿到了目标窗口的 PID，可后续流程去查的是内存里那份进程缓存列表（`m_processList`），而不是实时问系统。

### 顺一遍问题链

`MainSelectProcessByWindow` 通过 `GetWindowThreadProcessId` 拿到了正确 PID，接着 `OnProcessSelected(pid)` 把各 Tab 的目标 PID 设好，再调 `UpdateTargetStatusBar()`。状态栏这个函数用 `FindProcessByPid` 去缓存列表里找——新起的进程压根不在列表里，找不到，于是状态栏显示「未选择目标进程」，还顺手**把 PID 输入框清空了**。

更麻烦的是 `DllInjectTab::GetSelectedProcess` 也吃这同一份缓存。哪怕 `m_targetPid` 已经设对，真要注入时因为在列表里查不到进程信息（尤其是架构 x86/x64），会弹「请在进程面板中选择一个目标进程」把你挡回去。

而自动刷新只在进程面板**可见**时才走（靠 `ProcessPanel::SelectProcessByPid` 的 pending 机制），默认隐藏的面板不触发刷新；就算刷新完成了，`WM_REFRESH_PROCS` 的处理器也不会回头把状态栏更新一下。几个环节叠一块儿，新进程就这么被卡在门外。

---

## 修复一：测试 DLL（对应 Bug 1 和 Bug 2）

测试 DLL 这边三处改动就够了，思路是「别让线程通知有机会作乱，也别在 DllMain 里碰 UI」：

**DialogProc：给 WM_INITDIALOG 补上返回，堵住 fall-through**

```diff
  case WM_INITDIALOG:
  {
      HICON hIcon = LoadIcon(...);
      SendMessage(hDlg, WM_SETICON, ...);
      hDllHwnd = hDlg;
+     return (INT_PTR)TRUE;  // 别再往下漏到 WM_COMMAND
  }
```

**DllMain：ATTACH 时直接关掉线程通知**

```diff
  case DLL_PROCESS_ATTACH:
  {
      hMainInst = hModule;
+     DisableThreadLibraryCalls(hModule);  // 从此不再收到 THREAD_ATTACH/DETACH
      HANDLE hThread = CreateThread(...);
      ...
```

一句 `DisableThreadLibraryCalls` 就从根上掐掉了 Bug 1 和 Bug 2 共同依赖的那条线程通知链。

**DllMain：真正要收尾时改用 PostMessage，别在锁里碰 UI**

```diff
- case DLL_THREAD_ATTACH:
- case DLL_THREAD_DETACH:
  case DLL_PROCESS_DETACH:
  {
-     if (hDllHwnd) {
-         MessageBoxA(hDllHwnd, str1, str, MB_OK);
-         EndDialog(hDllHwnd, FALSE);
-     }
+     if (hDllHwnd && IsWindow(hDllHwnd)) {
+         PostMessage(hDllHwnd, WM_CLOSE, 0, 0);  // 异步投递，不在 Loader Lock 里同步弹窗
+         hDllHwnd = nullptr;
+     }
      break;
  }
```

`PostMessage` 只是把消息投进队列就返回，不会在持锁状态下去创建窗口，死锁自然就没了。

---

## 修复二：工具本体（对应 Bug 3）

改动集中在三个文件，核心思路是**缓存查不到就实时问系统**，而不是直接判死：

- 🔧 `src/ui/MainWindow.h`
- 🔧 `src/ui/MainWindow.cpp`
- 🔧 `src/ui/DllInjectTab.cpp`

### 1. MainWindow.h：加一个 pending PID 字段

记下十字瞄准选中、但还没在进程列表里匹配上的 PID，等后台刷新完再回来重试。

```diff
  bool  m_enumInProgress   = false;
  bool  m_updatingPidEdit  = false;
+ DWORD m_pendingSelectPid = 0;  // 待匹配的进程 PID
```

### 2. UpdateTargetStatusBar：查不到就实时查，别清空

PID 不在缓存里时，用 `ProcessManager::GetProcessArch` / `GetProcessPath` 直接问系统，而不是显示「未选择」再把 PID 抹掉。

```diff
  bool found = FindProcessByPid(tabPid, info);
+ if (!found) {
+     info.pid  = tabPid;
+     info.arch = ProcessManager::GetProcessArch(tabPid);
+     info.fullPath = ProcessManager::GetProcessPath(tabPid);
+     if (!info.fullPath.empty()) {
+         auto pos = info.fullPath.find_last_of(L"\\/");   // 从路径取进程名
+         info.name = (pos != npos) ? ... : info.fullPath;
+         found = true;
+     } else {
+         // 进程不可访问，也至少保留 PID 显示
+     }
+ }
```

### 3. MainSelectProcessByWindow：不在缓存就顺手触发一次后台刷新

```diff
  OnProcessSelected(pid);
+ ProcessInfo tmpInfo;
+ if (!FindProcessByPid(pid, tmpInfo)) {
+     m_pendingSelectPid = pid;
+     RefreshProcessList();
+ }
```

### 4. WM_REFRESH_PROCS：刷新完回填 pending PID

后台枚举一结束，就检查 `m_pendingSelectPid`，新列表里有就重走一遍选中流程，把状态栏和面板都对上。

```diff
  m_pProcessPanel->RefreshProcessListView(m_processList);
+ if (m_pendingSelectPid != 0) {
+     DWORD pid = m_pendingSelectPid;
+     m_pendingSelectPid = 0;
+     ProcessInfo info;
+     if (FindProcessByPid(pid, info)) {
+         OnProcessSelected(pid);
+         if (panel visible) SelectProcessByPid(pid);
+     } else {
+         UpdateTargetStatusBar();  // 还是没有，就交给上面的实时查询兜底
+     }
+ }
```

### 5. DllInjectTab::GetSelectedProcess：注入前也做一次实时兜底

缓存里找不到就直接问系统拿架构和路径，别因为缓存过期把注入给拒了。

```diff
  // 原有的缓存列表查找...
+ // 缓存未命中，实时查一次
+ out.pid  = m_targetPid;
+ out.arch = ProcessManager::GetProcessArch(m_targetPid);
+ out.fullPath = ProcessManager::GetProcessPath(m_targetPid);
+ if (!out.fullPath.empty()) {
+     out.name = 提取文件名(out.fullPath);
+     return true;
+ }
  return false;
```

---

## 修完之后的对照

| 场景 | 修复前 | 修复后 |
|------|--------|--------|
| Spawn + CRT/APC 注入 | ❌ 对话框一闪就关 | ✅ 对话框正常保持 |
| Attach + CRT/APC/Hook 关窗口 | ❌ UI 死锁卡死 | ✅ 正常关闭 |
| 十字瞄准新进程 | ❌ 显示「未选择」 | ✅ 立刻显示进程信息 |
| PID 输入框输入新进程 | ⚠️ 只显示 PID，未匹配 | ✅ 实时查询并补全信息 |
| 注入不在列表里的进程 | ❌ 被拒绝执行 | ✅ 实时查询后正常注入 |

---

*小结：Bug 1、Bug 2 的锅在配套测试 DLL——一个漏 `break`，一个在 DllMain 里碰 UI 撞上 Loader Lock，跟注入工具本身无关；Bug 3 才是工具的逻辑缺陷，本质是「拿缓存当唯一真相」，改成缓存未命中即实时查询系统，顺带把缓存过期这一类场景的鲁棒性也补上了。*
