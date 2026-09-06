# 一枚把九连环藏进注册码的 CrackMe

拿到这个 CrackMe 时先看了下体积：1904 字节，PE32 GUI，MSVC 6.0 编译，没壳、没反调试、导入表就 5 个函数。本以为是十分钟的活儿，真正跟进去才发现作者把一整套九连环的机械约束塞进了注册码校验里——想过，唯一的办法是在纸面上把九个环全解开。

这篇记录一下我从入口跟到 keygen 的完整过程。

| | |
|------|-----|
| 文件 | 1,904 字节 PE32 GUI |
| 编译器 | MSVC 6.0 · 无壳 |
| 导入函数 | 5 个 |
| 注册码长度 | 256 – 511 位数字 |

---

## 先摸清骨架

入口非常干净，`0x00400522` 处一个 `DialogBoxParamA` 把 ID 101 的对话框拉起来就完事了，窗口过程在 `0x00400437`。没有额外线程，没有 TLS 回调，所有逻辑都收在这个窗口过程里，跟起来省心。

对话框过程里只处理了 `WM_COMMAND`：

```asm
; DlgProc @ 0x400437 —— 只处理 WM_COMMAND (0x111)
00400462  cmp  dword ptr [ebp+0Ch], 111h   ; WM_COMMAND
0040047C  movzx eax, word ptr [ebp+10h]    ; LOWORD(wParam) = 控件 ID
00400480  dec  eax / dec eax               ; ID == 2 (取消) → EndDialog
00400488  sub  eax, 3E6h                   ; ID == 3E8h (注册按钮) → 开始校验
00400499  ... GetDlgItemTextA(hDlg, 3E9h, name,   10h)    ; 用户名，最多 15 字节
004004B3  ... GetDlgItemTextA(hDlg, 3EAh, serial, 1000h)  ; 注册码，缓冲区 4 KB
```

这里第一个让我停下来的地方，是注册码缓冲区开了 4 KB。用户名才 16 字节，注册码却预留 4096——作者显然不打算让你输入十几位的短码，而是**几百位**。这个直觉后面被证实了。

---

## 用户名怎么变成一个 key

点注册后，程序先把用户名压成一个 32 位整数，之后的校验全部只认这个 key，用户名本身再也不出现。这段循环有两个坑，一不小心就会算错：取字符用的是 `movsx`（**有符号**字节），收尾的右移是 `sar`（**算术**右移）——所以它看着像循环移位，其实不是。

```asm
0040046F  mov   ebx, 13572468h             ; key 初值
004004DA  movsx eax, byte ptr [ebp+edx-14h] ; c = (signed char)name[i]
004004DF  add   eax, ebx
004004E1  imul  eax, eax, 3721273h
004004E7  add   eax, 24681357h
004004EC  mov   esi, eax
004004EE  shl   esi, 19h                    ; t << 25
004004F1  sar   eax, 7                      ; t >> 7 (算术!)
004004F4  or    esi, eax
004004F9  mov   ebx, esi                    ; key = 结果，进入下一轮
```

算出 key 之后，`0x004002CC` 被调用，参数只有两个：key 和注册码字符串。核心都在这个函数里。

---

## 校验函数到底在校验什么

跟进 `0x004002CC`，一开头它在栈上开了个 10 字节的数组（`ebp-24h`，我记作 `a[0..9]`），按 key 的比特位给它铺初值：

```asm
00400367  mov  eax, [ebp+8]        ; key
0040036A  mov  ecx, edi            ; edi = 1..8
0040036C  shr  eax, cl
0040036E  and  al, bl              ; bl = 1
00400370  mov  [ebp+edi-24h], al   ; a[i] = (key >> i) & 1
0040037C  mov  [ebp-1Bh], bl       ; a[9] = 1  ← 恒为 1
```

注意最后一行，`a[9]` 被硬编码成 1，这个细节待会儿会解释注册码为什么下不去 256 位。

接下来是逐字符处理注册码。每个字符必须落在 `'0'`–`'9'`，然后被换算成一个 0–9 的动作值 `d`：

```asm
0040039C  eax = i; idiv 31          ; edx = i % 31
004003AD  eax = key >> (i % 31)
004003B0  div 10                    ; edx = (key >> (i%31)) % 10
004003B6  eax = edx + (serial[i]-'0')
004003BC  div 10                    ; edx = d = 上式 % 10
```

也就是说，注册码第 `i` 位不过是把动作值 `d` 用 key 派生的偏移「加密」了一层，反推 `serial[i]` 是平凡的。真正卡人的是紧接着对 `d` 的那段合法性检查：

```asm
004003BE  cmp  edx, ebx            ; d == 1 ?
004003C2  xor  byte ptr [ebp-23h], bl   ; → a[1] ^= 1，无条件放行

004003C7  cmp  byte ptr [ebp+edx-25h], bl  ; a[d-1] 必须 == 1，否则 Fail
004003CD  lea  eax, [edx-2]
004003D6  cmp  byte ptr [ebp+ecx-24h], bl  ; a[1..d-2] 必须全为 0，否则 Fail
004003E1  xor  byte ptr [ebp+edx-24h], bl  ; → a[d] ^= 1
```

全部字符跑完后是终局判定：

```asm
004003F0  cmp  byte ptr [ebp+eax-24h], bl  ; a[1..9] 中只要还有一个 == 1
004003F4  je   fail                         ; 就 Fail
```

盯着这段看了一会儿，规则就浮出来了：**第 1 个环随时能翻；第 *d* 个环只有在第 *d−1* 个环立着、并且它前面的环全放倒时才能翻。** 这就是**九连环**（Baguenaudier / Chinese Rings）的机械约束，而「所有位归零」正是把九个环全部摘下来的终态。作者没有把这层意思写在任何字符串里，全靠这几条 `cmp`/`xor` 隐式表达。

---

## 为什么不用爆破，直接算就行

意识到是九连环之后，就没必要一步步搜索了——它的状态和格雷码是一一对应的。把环的状态位记作 `a`（bit0 = 环 1 … bit8 = 环 9），定义：

```
v = a ^ (a>>1) ^ (a>>2) ^ ...  ; 格雷码逆变换
a = v ^ (v>>1)                 ; 正变换
```

关键性质是：**每一次合法翻环，恰好让 v 加一或减一**；而全部摘下（`a = 0`）对应 `v = 0`。于是最短解就是把 v 从当前值一路减到 0，第 `t → t−1` 步该翻哪个环，就看 `gray(t) ^ gray(t−1)` 里唯一那个 1 落在第几位。

回头看前面那个 `a[9]` 恒为 1 的细节：它保证了初始 `v ≥ 256`，所以最短注册码也得 256 位起步，长度落在 256–511 之间——**这个 CrackMe 根本不存在短注册码**，之前 4 KB 缓冲区的直觉到这里闭环了。

各环的初值与可翻条件整理如下：

| 环 | 初值来源 | 可翻转条件 |
|----|----------|-----------|
| 1 | `(key >> 1) & 1` | 任意时刻 |
| 2 – 8 | `(key >> d) & 1` | a[d−1] = 1 且 a[1..d−2] = 0 |
| 9 | 恒为 1 | a[8] = 1 且 a[1..7] = 0 |
| 0 | — | 越界读到已清零的缓冲区 → 必定 Fail |

---

## 写注册机

思路清楚后，keygen 就是「用户名 → key → 初始环态 → 解九连环 → 把动作序列反算回数字」这么一条流水线。下面两份实现等价，逻辑完全一致。

### JavaScript

```javascript
function nameHash(bytes) {
  let key = 0x13572468 | 0;
  for (let i = 0; i < bytes.length; i++) {
    const c = bytes[i] > 127 ? bytes[i] - 256 : bytes[i];   // movsx
    let t = (key + c) | 0;
    t = Math.imul(t, 0x03721273) | 0;
    t = (t + 0x24681357) | 0;
    key = ((t << 25) | (t >> 7)) | 0;                        // shl 25 | sar 7
  }
  return key >>> 0;
}

const gray   = v => v ^ (v >>> 1);
function ungray(a) { let v = a; while (a) { a >>>= 1; v ^= a; } return v >>> 0; }
const initState = key => ((key >>> 1) & 0xFF) | 0x100;

function solve(state) {
  let v = ungray(state); const moves = [];
  while (v > 0) { const diff = gray(v) ^ gray(v - 1); moves.push(32 - Math.clz32(diff)); v--; }
  return moves;
}

function keygen(name) {
  const bytes = Array.from(Buffer.from(name, 'utf8'));       // 中文见下方注意
  const key = nameHash(bytes);
  const moves = solve(initState(key));
  let out = '';
  for (let i = 0; i < moves.length; i++) {
    const k = (key >>> (i % 31)) % 10;
    out += String.fromCharCode(48 + (((moves[i] - k) % 10) + 10) % 10);
  }
  return out;
}

console.log(keygen('pediy'));
```

### Python

```python
def name_hash(data: bytes) -> int:
    key = 0x13572468
    for b in data:
        c = b - 256 if b > 127 else b            # movsx (signed char)
        t = (key + c) & 0xFFFFFFFF
        t = (t * 0x03721273) & 0xFFFFFFFF
        t = (t + 0x24681357) & 0xFFFFFFFF
        # shl 25 | sar 7  —— sar 是算术右移
        low = (t << 25) & 0xFFFFFFFF
        sar = (t if t < 0x80000000 else t - 0x100000000) >> 7
        key = (low | (sar & 0xFFFFFFFF)) & 0xFFFFFFFF
    return key

def ungray(a: int) -> int:
    v = a
    while a:
        a >>= 1
        v ^= a
    return v

gray = lambda v: v ^ (v >> 1)

def keygen(name: str, encoding: str = "gbk") -> str:
    # 程序对话框按 GBK 取字节；ASCII 用户名两种编码结果一致
    key = name_hash(name.encode(encoding))
    state = ((key >> 1) & 0xFF) | 0x100
    v = ungray(state)
    moves = []
    while v > 0:
        diff = gray(v) ^ gray(v - 1)
        moves.append(diff.bit_length())          # 唯一置位的位序 + 1
        v -= 1
    out = []
    for i, m in enumerate(moves):
        k = (key >> (i % 31)) % 10
        out.append(str((m - k) % 10))
    return "".join(out)

if __name__ == "__main__":
    print(keygen("pediy"))
```

> **一个编码上的坑**：程序对话框按 **GBK** 取字节，所以中文用户名要用 Python 版并保持 `encoding="gbk"`，否则算出来的 key 不对。纯 ASCII 用户名下 UTF-8 与 GBK 字节一致，两份实现结果相同。

---

## 怎么确认自己没跟错

推理归推理，还是得验一遍。我用了两条路互相印证。

### x64dbg 手动跟一遍

- `bp 0x004004DA` —— 看用户名 hash 每一轮，`ebx` 就是当前 key。
- `bp 0x004003BC` —— 每次断下 `edx` 就是这一位解出的动作值 `d`，跟 keygen 里算的对一下。
- 内存窗口盯住 `ebp-24h` 那 10 个字节，能实时看到九个环一位一位被翻，很直观。
- `bp 0x004003F0` 是终局判定；`bp 0x0040041E` 是全程唯一的 `MessageBoxA`，成功和失败共用这一处。

### Unicorn 直接跑原始机器码

嫌手动跟麻烦，更省事的是把 PE 映射进 Unicorn，挂钩 `GetDlgItemTextA` 喂进用户名和注册码，挂钩 `MessageBoxA` 读回结果，然后直接执行 `0x00400437` 的真实代码。拿随机用户名批量跑，keygen 出的码全部返回 `OK!!`，随手改一位就变 `Fail!`——结论站得住。

补一句：`OK!!` 和 `Fail!` 这两个串在文件里是加密的，`0x00400240` 用固定 10 字节密钥 `25 9A F3 6F 82 DA 72 FE C9 B7` 异或还原，所以想靠直接搜字符串定位成功分支是白费劲。

---

## 关键地址速查

| 地址 | 作用 |
|------|------|
| `0x00400240` | 字符串解密（首字节 0xFF 则异或 10 字节密钥，否则原样拷贝） |
| `0x004002CC` | 注册码校验主体（九连环模拟 + 终局判定） |
| `0x00400437` | DlgProc |
| `0x004004DA` | 用户名 hash 循环 |
| `0x00400522` | 入口 / DialogBoxParamA |
| ID 1000 / 1001 / 1002 | 注册按钮 / 用户名输入框 / 注册码输入框 |

---

*分析对象：CrackMe.exe（1,904 字节）。全部结论经 Unicorn 全流程模拟验证。*
