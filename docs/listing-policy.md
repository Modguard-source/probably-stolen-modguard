# Listing policy / 收录规则

[English](#english) · [中文](#中文)

## English

The list can stop other people's work from being activated, and putting someone on it amounts to saying in public that they did something wrong. So the rules matter more than convenience.

### Two levels

| Level | Condition | What Mod Guard does |
|---|---|---|
| `confirmed` | There is a sample, static analysis found malicious behavior, and the record can say exactly which code does what | Blocks activation |
| `suspect` | Only publicly verifiable facts, such as bulk uploads or borrowed names | Warns before activation; the player can continue |

**An accusation alone never puts anything on the list.** Comments, the number of reports, an author's nationality or whether they write code with AI are not evidence.

`suspect` entries can only be made by item or by version, never by publisher or by file. It is an intermediate state waiting for analysis: within 30 days the entry is either confirmed or removed, and after that the tests fail.

A confirmed record states how a second person can reproduce the judgment (for example "open X in ILSpy and look at method Y"). A record is not downgraded while an appeal is open, or appealing would become a way around the list. Mistakes are fixed by correcting the list. Mod Guard never relaxes on its own, because anything that can relax it automatically can also be triggered on purpose by a malicious author.

### What can be matched

| Used | Not used |
|---|---|
| Workshop item ID (issued by Steam) | The author name in the manifest |
| Publisher SteamID (issued by Steam), `confirmed` only | The mod ID in the manifest |
| Hash of a whole version (the manifest plus every DLL) | Title |
| File hash of **the malicious component itself**, `confirmed` only | Hashes of files by legitimate authors |

Everything in the right-hand column is either filled in by the uploader or can be bundled. A malicious author who fills in someone else's name, or ships someone else's DLL, could get the victim blocked too. This is not hypothetical: the malicious items in [2026-0001](../cases/2026-0001.md) borrowed real authors' names and mod IDs.

Author names and mod IDs are only used for "this may be a copy" warnings, only when the publisher differs, and they never go on the list.

What file hashes are for: when a malicious author re-uploads the same file from a new account, the item ID and the publisher change but the file stays the same. Only a file whose code has been read and confirmed malicious can be listed, and the record says what it does. Anyone shipping that file really is shipping malicious code, so nobody innocent is caught.

Every known item is also listed by its own item ID, not only through a publisher entry: a publisher entry needs an answer from Steam, and does nothing while Steam has not answered.

### Rules that do not use the list

These rules only look at a mod's files. They name nobody and never go on the list.

**Blocks activation:**

- Imports network functions (urlmon, wininet, winhttp, ws2_32, wsock32) together with functions that start programs or inject code into other programs.
- Imports network functions together with run-time lookup (`LoadLibrary`, `GetProcAddress`) or COM (`CoCreateInstance` and similar).
- The manifest declares `network` and the DLL imports functions that start programs.

**Warns only; the player can continue:**

- Any one of the groups above on its own, for example only `ShellExecute`, only run-time lookup, or only COM.
- Imports WinRT activation functions (`RoGetActivationFactory` and similar). Ordinary uses such as playing video need them too.
- The item contains more than one mod entry point. A loader packed beside a normal mod looks like this, and so do some large mods.
- The item calls itself Mod Guard (its name contains 模组守卫, 模组卫士 or ModGuard, or its mod ID starts with `modguard`) but is neither the official item nor from the official publisher. Forks and translations are allowed by the MIT license, so this is only a warning; such an item is listed as `confirmed` only once it is confirmed to carry malicious code.

Legitimate mods can be caught too, for example an online mod that uses `ShellExecute` to open a web page or a folder. If that happens, please open an Issue. Authors can also switch to the official `Application.OpenURL`.

**Known ways around these rules:** they look at declarations, not at what the code actually does. Hiding the payload in an image, writing it to disk with `files` and starting it from there only earns one warning. A malicious mod written in purely managed code (`WebClient`, `Process`) is invisible to the import rules and has to be refused by the game's own scanner.

### Compromised accounts

A malicious version pushed from a stolen author account is **listed by version hash only, never by publisher**, and marked `compromised_version`. Once the author recovers the account, new versions are not affected.

### Every record

- `cases/<number>.md` states the facts and the evidence. It says what was done, not "this person is bad".
- Every item number a case lists goes into one line, `- **收录的条目：**` ("listed items"), and the tests check that this line and the list agree. Other numbers, such as the item of an author who was imitated, are written elsewhere, stay off that line and are not required to be listed.
- No malicious samples and no steps that can be reproduced as they stand. Samples are kept as hashes only.
- The game only shows the fixed text for a reason code and the record number, never a link.

### Appeals

- Appeals go through this repository's Issues only, and the outcome is public.
- **The maintainer never starts private conversations with anyone on Steam or Discord.** Anyone who messages you claiming to be the maintainer and asks you to click a link or download a file is a scammer.
- A record confirmed to be wrong is deleted, and the reason is written into the original record.

### Who can change the list

- Only the maintainer. External pull requests do not go into the list directly. To report something, open an Issue with the item ID and your evidence.
- CI does not run jobs with secrets on external pull requests.
- Do not open executables or zipped logs attached to reports. Samples are only read statically in an isolated environment, never loaded or run, and never kept alongside an account that is logged in to Steam.

### What this tool cannot do

Mod Guard only knows what is on its list and the few rules above. No warning does not mean a mod is safe. A malicious mod that is already running has the same access as Mod Guard and can simply switch it off. **Any mod that asks you to turn off Mod Guard to use it is a red flag.**

## 中文

名单能让别人的作品无法启用，也等于公开说一个人有问题。所以规则比方便更重要。

### 两个级别

| 级别 | 条件 | 守卫怎么做 |
|---|---|---|
| `confirmed` 已确认 | 有样本，静态分析找到恶意行为，能写清楚是哪段代码做了什么 | 阻止启用 |
| `suspect` 可疑 | 只有公开可核实的事实，比如集中上传、冒用名称 | 启用前提醒，玩家可以继续 |

**只有指控不能入名单。** 评论、举报数量、作者的国籍或是否用 AI 写代码都不算证据。

`suspect` 只能按条目或版本收录，不能按发布者，也不能按文件。它是等待分析的中间状态：30 天内要么确认，要么删除，过期后测试会失败。

已确认的记录要写明第二个人能怎样复现这个判断（比如「用 ILSpy 打开 X，看 Y 方法」）。申诉期间记录不降级，否则申诉就成了绕过手段。名单出错时靠更正名单解决，守卫不会自动放松，因为任何能自动触发的放松，恶意作者也能故意触发。

### 能用什么来匹配

| 用 | 不用 |
|---|---|
| 工坊条目 ID（Steam 发放） | manifest 里的作者名 |
| 发布者 SteamID（Steam 发放），只限已确认 | manifest 里的模组 ID |
| 整个版本的哈希（manifest 加全部 DLL） | 标题 |
| **恶意组件本身**的文件哈希，只限已确认 | 正常作者的文件的哈希 |

右边这些要么由上传者自己填写，要么可以被夹带。恶意作者填上别人的名字，或者带上别人的 DLL，就能让受害者被连带封禁。这不是假设：[2026-0001](../cases/2026-0001.md) 的恶意条目就冒用了真实作者的名字和 mod ID。

作者名和 mod ID 只用于「可能是仿冒」的提醒，而且只在发布者不同时才提醒，永远不进名单。

文件哈希的作用是：恶意作者换账号重传同一个文件时，条目 ID 和发布者都变了，只有它不变。只能收已经读过代码、确认恶意的那个文件，记录里要写清它做了什么。谁的包里带着这个文件，谁就确实带着恶意代码，所以不会误伤。

每个已知条目也要单独收录条目 ID，不能只靠发布者记录：发布者要问 Steam，Steam 没回答时那条记录不起作用。

### 不靠名单的规则

这些规则只看 mod 的文件，不点名任何人，也不进入名单。

**阻止启用：**

- 导入网络函数（urlmon、wininet、winhttp、ws2_32、wsock32），同时导入启动程序或向其他程序注入代码的函数。
- 导入网络函数，同时用运行时查找（`LoadLibrary`、`GetProcAddress`）或 COM（`CoCreateInstance` 等）。
- manifest 声明了 `network`，同时导入启动程序的函数。

**只提醒，玩家可以继续：**

- 只有上面任何一类，比如只导入 `ShellExecute`、只用运行时查找、只用 COM。
- 导入 WinRT 激活函数（`RoGetActivationFactory` 等）。播放视频这类正常用途也会用到。
- 条目含多个模组入口。把加载器和正常模组打包在一起就是这样，有些大型模组也会这样。
- 条目自称模组守卫（名字含「模组守卫」「模组卫士」或 ModGuard，或 mod ID 以 `modguard` 开头），但不是官方条目或官方发布者。分支和汉化是 MIT 许可允许的，所以只提醒；确认夹带恶意代码后才按 `confirmed` 收录。

正常模组也可能被误伤，比如联网 mod 用 `ShellExecute` 打开网页或文件夹。遇到这种情况请提交 Issue。作者也可以改用官方的 `Application.OpenURL`。

**已知绕不过去的：** 这些规则只看声明，不看实际行为。把载荷藏在图片里，用 `files` 写到磁盘再启动，只会得到一次提醒。用纯托管代码（`WebClient`、`Process`）的恶意 mod，导入规则看不到，要靠游戏自己的扫描器拒绝。

### 被盗账号

作者账号被盗后推送的恶意版本，**只封版本哈希，不封发布者**，并标为 `compromised_version`。作者恢复账号后，新版本不受影响。

### 每条记录

- `cases/<编号>.md` 写明事实和依据，写「做了什么」，不写「这个人是坏人」。
- 收录的条目编号全部写在一行 `- **收录的条目：**` 里，测试会核对这一行和名单是否一致。被冒用的原作者条目等别的编号写在别处，不进这一行，也不会被要求收录。
- 不放恶意样本，不放可直接复现的利用步骤。样本只留哈希。
- 游戏里只显示理由代码对应的固定文字和编号，不显示链接。

### 申诉

- 只通过本仓库的 Issue 申诉，处理结果公开。
- **维护者不会在 Steam 或 Discord 上主动私聊任何人。** 自称维护者私聊你、让你点链接或下载文件的，都是骗子。
- 确认错了就删除记录，并在原记录写明原因。

### 谁能改名单

- 只有维护者能改。外部的 PR 不会直接进名单，举报请提交 Issue，附上条目 ID 和依据。
- CI 不在外部 PR 上运行带密钥的任务。
- 不要打开举报里附带的可执行文件或日志压缩包。样本只在隔离环境里做静态读取，绝不加载或运行，不和登录 Steam 的账号放在一起。

### 这个工具做不到的

守卫只认识名单上的东西和上面那几条规则。没有警告不代表安全。如果恶意模组已经在运行，它和守卫权限相同，可以直接关掉守卫。**任何要求你关闭守卫才能使用的模组，都是危险信号。**
