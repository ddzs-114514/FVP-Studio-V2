# 私人本机配置

所有实际配置保留在本机。`*.local.json` 已被 Git 忽略；不要提交来源路径、接入位置、引擎签名或原作数据。

## 来源登记

复制 `sources.example.json` 为自己的 `sources.local.json`，在 `sources` 中明确登记：

- `id`：稳定技术 ID，如 `hoshi`、`sakura`；不要改变原作文件名来匹配显示标题。
- `name`：显示名。sakura 使用“樱花萌放”。
- `root`：你有权使用的本机原作目录的绝对路径。
- `archive`：当前立绘载体的 `graph_bs.bin` 或 `graph.bin`。
- 可选 `target_script` / `target_executable`：根目录直属 HCB/BCH/EXE 文件名；多入口游戏必须明确选择，不能猜配对。
- 可选 `target_encoding` / `target_analysis_encoding` / `target_hook_offset`：已独立核对的编码与接入位置，不接受浏览器提交文件系统路径。

不会把登记复制到 GitHub，也不会扫描开发者目录代替登记。

## 引擎识别绑定

`examples/engine_patterns.example.json` 是空模板。为避免分发原作 EXE 指令片段，18 项既有读取器签名只保留身份摘要。尺寸算法和接受条件没有改写；缺签名时不猜测尺寸。

拥有自己的已审核私有读取器源码时，可显式生成本机配置（下列尖括号仅为说明，须替换成你的路径）：

```sh
python -m fvp_studio.prepare_local --patterns-from "<私有已审核的读取器目录>" --output "<本机配置目录>/engine_patterns.local.json"
```

工具只读取指定三份 Python 文件的 AST 字节常量，不执行这些脚本；只接受与原审核签名完全相同的摘要。也可自行提供已核查、相同摘要的私人签名配置。仓库自身没有这些指令片段，空模板不能直接启用原生尺寸发现。

## 星空接入绑定

填充 `hoshi_binding.example.json` 的本机母本与四个已核对偏移，保存为 `hoshi_binding.local.json`。接入字节不写入配置：运行时从只读原作读取。母本/分析脚本/启动程序、接入布局摘要、指令指纹与边界均须匹配既有已审核版本；任一漂移都会拒绝，不能对任意游戏自动信任。

若保留了原有私有审核版 `performance_compile.py`，可显式读取其偏移元数据并校验本机原作：

```sh
python -m fvp_studio.prepare_local --hoshi-from "<私有审核版 performance_compile.py>" --source-root "<本机原作目录>" --output "<本机配置目录>/hoshi_binding.local.json"
python -m fvp_studio.prepare_local --check-hoshi-binding "<本机配置目录>/hoshi_binding.local.json"
```

没有这些本机审核资料时，星空专用输出暂不可用；不把另一个脚本/类似入口当替代版本。

## 接入服务

```sh
python -m fvp_studio --sources "<私人 sources.local.json>" --engine-patterns "<私人 engine_patterns.local.json>" --hoshi-binding "<私人 hoshi_binding.local.json>" --test-root "<独立测试副本根>" --port 18826
```

只用其他目标时可省略星空绑定；它们仍需各自登记、引擎签名和已经匹配的原生调用链。也可使用 `FVP_STUDIO_ENGINE_PATTERNS`、`FVP_STUDIO_HOSHI_BINDING`、`FVP_STUDIO_TEST_ROOT` 环境变量。

工作根不能与任何原作目录重叠。独立副本必须为指定测试根下的新目录；已有目录、链接/联接、进程状态无法确认、身份漂移均拒绝。不会覆盖原作或已有测试副本，也不会自动启动游戏。
