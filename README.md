# Mod Guard / 模组守卫

[English](#english) · [中文](#中文)

## English

An open-source mod for Probably Stolen (深空当铺): it stops you from activating Workshop items listed as confirmed malicious, and warns about suspicious ones.

> **Current version: 0.1.0.** Workshop item: <https://steamcommunity.com/sharedfiles/filedetails/?id=3835781654>

### What it does

- **Blocks activation:** items on the list that are confirmed malicious are stopped when you click Activate, before the mod's code runs for the first time.
- **Blocks without the list too:** if a DLL imports both the Windows functions for downloading files and those for starting programs, activation is blocked as well, even after a re-upload from another account. This is what the real malicious mods on the Workshop did, see [cases/2026-0001.md](cases/2026-0001.md). Importing only one of the two gets a warning.
- **Warns before activation:** suspicious items, items reusing the mod ID of an item you already approved, items imitating well-known mods, and items with more than one mod entry point all need the player's confirmation.
- **Startup report:** if an active mod is listed as malicious, it tells you to deactivate it and suggests an antivirus scan and a password change.
- **Subscription alert:** subscribe to a listed item while the game is running, and you are warned as soon as it finishes downloading.
- **Spots fake copies of Mod Guard:** other items calling themselves 模组守卫, 模组卫士 or ModGuard get a warning before activation, repacks in a local folder included.
- **Self-check:** see "Make sure you have the official copy" below.

It declares no capabilities, does not go online, and its list is updated through the Workshop. It reads the manifest and the listed DLLs of subscribed items: all DLLs of a mod when you click Activate, and at startup only those of mods that declare `native` or list more than one DLL. Reading only parses file metadata and computes hashes. It never loads or runs their code, and it never modifies any other mod.

### What it cannot do

- **It is not an antivirus.** It only knows what is on its list, and **no warning does not mean a mod is safe**. That is why it has no "safe" or "verified" label.
- **It cannot stop a malicious mod that is already running.** Both have the same access: that mod can switch it off, or even approve other mods on your behalf.
- **It cannot stop a malicious update to a mod you approved.** If its author (or someone who stole the account) turns an approved mod into a malicious version that asks for no new capabilities, the game loads it at startup and Mod Guard can only report it afterwards.
- **It does not deactivate mods for you.** It only holds back activation; deactivating is up to you, in the mod menu. It does not change the game's loader or its approval records.
- **A re-upload from a new account with a new technique has to wait for a list update.** The rules read declarations, not behavior, and are not hard to get around: looking functions up at run time, or hiding the payload in an image and writing it to disk, only earns a warning. Purely managed code (`WebClient`, `Process`) has to be refused by the game's own scanner.

**Any mod that asks you to turn off Mod Guard to use it is a red flag.**

### Make sure you have the official copy

Mod Guard is open source: anyone can copy it, slip something in and upload it again. Players trust it, so imitating it pays off more than imitating other mods.

- **Official item:** Workshop item [`3835781654`](https://steamcommunity.com/sharedfiles/filedetails/?id=3835781654), publisher `76561199484674335`. Subscribe to this one only. The footer of every Mod Guard window shows this number.
- **DLL hash:** the SHA-256 of `ModGuard.dll` for every version is on the Workshop page and in this repository's Releases. The build is deterministic: the same source (line endings pinned by `.gitattributes`), the same official item number, the same .NET SDK and the same game version give a byte-identical file, whichever directory you build in.
- **Do not use a "Mod Guard" from file-sharing sites or chat groups**, or any "translated", "enhanced" or "no subscription needed" edition.

Mod Guard checks itself at startup:

| Check | Catches | Misses |
|---|---|---|
| File hashes: the hashes of the manifest, the list, the imitation reference table and the language files are built into the DLL | The original DLL with changed files: an emptied list, a list that adds innocent mods, messages turned into ads or scams, extra language files, other DLLs added to the manifest | A modified DLL |
| Identity: the DLL carries the official item number | An unchanged re-upload to another item, or a repack as a local folder | A modified DLL |

When it finds a problem it warns at every launch, using text built into the DLL. A changed list is never used. If language files were changed, every message falls back to the built-in text, and the changed text is never shown. An incomplete download triggers this warning too; unsubscribe in Steam and subscribe again.

If Steam updates Mod Guard while the game is running, the old DLL that is running sees the new files. Mod Guard compares the DLL on disk with the one the game loaded at startup: if they differ, this is an update and not tampering, so it does not warn and works with the new list on disk until a restart. At the next launch the new DLL checks again. Anything that can change Mod Guard's folder while the game runs is already running on your computer; Mod Guard cannot defend against that and does not try to.

**Limits of the self-check:** a modified DLL can remove the self-check entirely, so the absence of a self-check warning does not prove a copy is official. Only the official item number and the DLL hash can.

The listing rules and how to appeal are in [docs/listing-policy.md](docs/listing-policy.md), and the evidence behind every record is in [cases/](cases/). The maintainer never starts private conversations with anyone.

### Development

Requires the .NET 8 SDK and a copy of the game: the build references the game's DLLs, which this repository does not contain. If the game is not in the default location, add `-p:GameDir=<game folder>` to the build.

```
dotnet build src/ModGuard/ModGuard.csproj -c Release -p:DeployDir=../../build/content
dotnet run --project tests/CoreTests -c Release
dotnet run --project tests/CoreTests -c Release -- patch build/content/ModGuard.dll
```

Without `DeployDir`, nothing is copied. To test locally in the game use `tests/GameTest/deploy.ps1`, and `tests/GameTest/remove.ps1` to remove it again.

#### Release

The release package is only made with `tools/build-release.ps1`. It empties `build/release`, builds from scratch, runs every test, and finally checks the folder with `CoreTests release`:

- The official item number and the publisher in the DLL match the csproj and are not 0, and the README names that item number.
- The hash of every data file matches the one recorded in the DLL.
- The folder holds no extra files, and the manifest lists only `ModGuard.dll`.

When everything passes, upload `build/release` exactly as it is and do not touch it afterwards. Put the DLL SHA-256 and the commit printed by the script into the release notes. The `release` check runs a small piece of initialization code from the DLL it checks, so only use it on a DLL you have just built yourself, never on one downloaded from elsewhere.

Order:

1. The first upload uses `tools/build-release.ps1 -FirstUpload`. The item number is still 0 then; every other check still applies. Upload it as **private**. This version has no identity check and must never be made public.
2. Put the item number you get into `OfficialItem` in `ModGuard.csproj` and into "Official item" in this README.
3. Run `tools/build-release.ps1` again without parameters and update the item with the new folder.
4. First run `tests/GameTest/remove.ps1` to delete the local test copy: a local copy loads first and the subscribed one is skipped, which would make this step pointless. Mod Guard's row in the mod menu should not show a local override. Then subscribe to the item yourself and check in game that there is no self-check warning. This verifies that Steam's upload and download did not change the files.
5. Make it public.

After changing data files (the list, language files and so on) the DLL must be rebuilt, or the self-check reports mismatched files. This is deliberate, and the `release` check stops a package where the rebuild was forgotten.

`src/ModGuard/Core` does not depend on the game and can be tested offline.

### Do not commit

Game code, decompiled code, game assets, malicious samples. All of them are in `.gitignore`, but look again before committing.

### License

MIT

## 中文

《深空当铺》(Probably Stolen) 的开源 mod：阻止启用名单上已确认恶意的工坊条目，对可疑条目发出警告。

> **当前版本：0.1.0。** 工坊条目：<https://steamcommunity.com/sharedfiles/filedetails/?id=3835781654>

### 它做什么

- **阻止启用：** 名单上已确认恶意的条目，点启用时会被拦下。这一步发生在 mod 的代码第一次运行之前。
- **不靠名单也能拦：** DLL 同时导入下载文件和启动程序的 Windows 函数时，同样阻止启用，换账号重传也一样。这是工坊上真实恶意 mod 的做法，见 [cases/2026-0001.md](cases/2026-0001.md)。只导入其中一类时会提醒。
- **启用前提醒：** 可疑条目、冒用已批准条目 ID 的条目、仿冒知名 mod 的条目、含多个模组入口的条目，都要玩家确认后才能继续。
- **启动报告：** 发现已启用的恶意 mod 时会提示你停用，并建议杀毒和改密码。
- **订阅提醒：** 游戏开着时订阅了名单上的条目，下载完就警告。
- **认出仿冒的模组守卫：** 其他条目自称「模组守卫」「模组卫士」或 ModGuard 时，启用前提醒，本地文件夹里的重打包也算。
- **自检：** 见下面「确认你装的是官方版」。

不声明任何能力，不联网，名单随工坊更新。它会读取已订阅条目的 manifest 和列出的 DLL：点启用时读这个 mod 的全部 DLL，启动时只读声明了 `native` 或列出多个 DLL 的。读取只解析文件的元数据和计算哈希，不加载、不运行其中的代码。它不修改任何其他 mod。

### 它做不到

- **不是杀毒软件。** 只认识名单上的东西，**没有警告不代表安全**。所以它没有「安全」或「已验证」标签。
- **挡不住已经在运行的恶意 mod。** 两者权限相同，对方可以直接关掉它，甚至替你批准别的 mod。
- **挡不住已批准 mod 的恶意更新。** 你批准过的 mod 被作者（或盗号者）更新成恶意版本时，只要它不要求新能力，游戏会在启动时直接加载，守卫只能事后报告。
- **不会替你停用 mod。** 它只拦启用，停用要你在模组菜单里自己点。它不修改游戏的加载器和批准记录。
- **换账号重传并且换了写法时，要等名单更新。** 规则只看声明不看行为，不难绕过：运行时才查找函数，或把载荷藏进图片再写到磁盘，都只会得到一次提醒。纯托管写法（`WebClient`、`Process`）要靠游戏自己的扫描器拒绝。

**任何要求你关闭守卫才能使用的 mod，都是危险信号。**

### 确认你装的是官方版

模组守卫是开源的，任何人都能复制一份，夹带东西后重新上传。玩家信任它，所以仿冒它比仿冒别的 mod 更有用。

- **官方条目：** 工坊条目编号 [`3835781654`](https://steamcommunity.com/sharedfiles/filedetails/?id=3835781654)，发布者 `76561199484674335`。只订阅这一个。守卫弹窗的页脚会显示这个编号。
- **DLL 哈希：** 每个版本的 `ModGuard.dll` 的 SHA-256 写在工坊页面和本仓库的 Releases 里。构建是确定性的：同一份源码（行尾由 `.gitattributes` 固定）、同一个官方条目编号、同一版 .NET SDK、同一版游戏，构建出的文件逐字节相同，放在哪个目录构建都一样。
- **不要用网盘、群文件里的「模组守卫」**，也不要用「汉化版」「增强版」「免订阅版」。

守卫启动时会检查自己：

| 检查 | 能抓住 | 抓不住 |
|---|---|---|
| 文件哈希：manifest、名单、仿冒参照表、语言文件的哈希在构建时写进了 DLL | 原版 DLL 配上改过的文件：清空的名单、塞进无辜 mod 的名单、改成广告或诈骗的提示文字、多加的语言文件、加进 manifest 的其他 DLL | 改过的 DLL |
| 身份：DLL 里写着官方条目编号 | 原样重新上传到别的条目，或打包成本地文件夹 | 改过的 DLL |

发现问题时，每次启动都会警告，用的是写死在 DLL 里的文字。改过的名单一律不用；语言文件被改过时，所有提示都改用内置文字，不显示被改过的原文。下载不完整也会触发这个警告，这时在 Steam 里取消订阅后重新订阅即可。

游戏运行中 Steam 更新了守卫时，正在运行的旧 DLL 会看到新文件。守卫会比较磁盘上的 DLL 和游戏启动时载入的那份：不一样就说明是更新，不是被改，这次不报警，并按磁盘上的新名单工作到重启为止；下次启动由新 DLL 重新检查。能在游戏运行中改守卫文件夹的东西，本来就已经在你电脑上运行，这种情况守卫防不住，也不打算防。

**自检的边界：** 改过的 DLL 可以把自检整个删掉，所以「没有自检警告」不能证明是官方版。能证明的只有官方条目编号和 DLL 哈希。

收录标准和申诉方式见 [docs/listing-policy.md](docs/listing-policy.md)，每条记录的依据在 [cases/](cases/)。维护者不会主动私聊任何人。

### 开发

需要 .NET SDK 8 和一份游戏（构建要引用游戏的 DLL，本仓库不包含）。游戏不在默认路径时，构建加 `-p:GameDir=<游戏目录>`。

```
dotnet build src/ModGuard/ModGuard.csproj -c Release -p:DeployDir=../../build/content
dotnet run --project tests/CoreTests -c Release
dotnet run --project tests/CoreTests -c Release -- patch build/content/ModGuard.dll
```

`DeployDir` 不设就不复制文件。本地进游戏测试用 `tests/GameTest/deploy.ps1`，移除用 `tests/GameTest/remove.ps1`。

#### 发布

发布包只用 `tools/build-release.ps1` 生成。它清空 `build/release`，从零构建，跑全部测试，最后用 `CoreTests release` 核对这个目录：

- DLL 里的官方条目编号和发布者要和 csproj 一致，并且不为 0；README 里也要写有这个条目编号。
- 每个数据文件的哈希要和 DLL 里记的一致。
- 目录里不能有多余的文件，manifest 只能列 `ModGuard.dll`。

全部通过后，原样上传 `build/release`，之后不要再改动它；脚本打印的 DLL SHA-256 和提交号写进发布说明。`release` 检查会运行被检查 DLL 里的一小段初始化代码，所以只用在自己刚构建的 DLL 上，不要拿它检查别处下载的 DLL。

顺序：

1. 第一次上传用 `tools/build-release.ps1 -FirstUpload`，这时条目编号还是 0，其他检查照做。上传时设为**不公开**。这个版本没有身份检查，绝不能公开。
2. 把拿到的条目编号填进 `ModGuard.csproj` 的 `OfficialItem` 和本 README 的「官方条目」。
3. 不带参数再运行一次 `tools/build-release.ps1`，用新生成的目录更新条目。
4. 先运行 `tests/GameTest/remove.ps1` 删掉本地测试副本（本地副本会优先加载，订阅的那份会被跳过，这一步就白测了），模组菜单里守卫那一行不应显示本地覆盖。然后自己订阅这个条目，进游戏确认没有自检警告，以此验证 Steam 的上传和下载没有改动文件。
5. 公开。

数据文件（名单、语言文件等）改了之后必须重新构建 DLL，否则自检会报文件不一致。这是故意的，`release` 检查会拦住忘了重新构建的包。

`src/ModGuard/Core` 不依赖游戏，可以离线测试。

### 不要提交

游戏代码、反编译结果、游戏素材、恶意样本。这些都已写进 `.gitignore`，但提交前还是要看一眼。

### 许可证

MIT
