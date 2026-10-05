"""Visible, linear multi-scene authoring contract (not original-line rewriting).

Every editable value is a normal node widget. No arbitrary HCB addresses or
executable snippets are accepted. The terminal may opt into an audited new-copy
install; other Queue paths remain candidate-only.
"""
from __future__ import annotations

import copy
import hashlib
import json

from .performance_portrait_limits import HEIGHT_MIN, HEIGHT_MAX

SCHEMA = "fvp-studio.performance.v1"
PREFIX = "FVPV2_Performance"
RUN_MODE_CHECK = "仅自检（生成候选）"
RUN_MODE_WRITE = "自检后写入全新测试副本"
EXPRESSION_DEFAULT_DURATION_MS = 200


def field(name, label, default, low=None, high=None, options=None):
    return dict(name=name, label=label, default=default, low=low, high=high, options=options)


# This table is shared by the node schemas, graph exporter and offline compiler.
DEFINITIONS = {
    "Project": ("综合演出工程", [field("source_root", "原游戏目录（只读）", ""),
        field("title", "工程名称", "多场景综合测试")]),
    "Scene": ("场景入口", [field("scene_id", "场景 ID", "A"), field("title", "场景说明", "")]),
    "Background": ("背景（支持其他 FVP 游戏）", [field("source_game", "素材来源游戏", ""),
        field("archive", "素材 BIN 路径", ""), field("resource", "背景资源名", ""),
        field("fit", "适配画面", "cover", options=["cover", "contain", "stretch"])]),
    "Portrait": ("立绘（支持其他 FVP 游戏）", [field("actor", "舞台位置（同时显示位置）", 1, 1, 4),
        field("source_game", "素材来源游戏", ""), field("archive", "立绘 BIN（graph_bs / graph）", ""),
        field("body", "身体资源名（自动配对表情）", ""), field("expression", "表情帧", 0, 0, 999),
        field("stage_x", "舞台横坐标（1280宽）", 640, -640, 1920),
        field("bottom_y", "素材下缘锚点 Y（可超出画面）", 710, -720, 1800),
        field("height", "立绘显示高度（原生RS校验）", 600, HEIGHT_MIN, HEIGHT_MAX),
        field("depth", "原作深度 Z", 1600, 1000, 2400),
        field("alpha", "初始不透明度", 255, 0, 255)]),
    "PortraitNative": ("立绘 · 旧版原点兼容（非完整M档）", [field("actor", "舞台位置（同时显示位置）", 1, 1, 4),
        field("source_game", "素材来源游戏", ""), field("archive", "立绘 BIN（graph_bs / graph）", ""),
        field("body", "身体资源名（自动配对表情）", ""), field("expression", "表情帧", 0, 0, 999),
        field("native_x", "原作 X（不是裁切图中心）", 0, -800, 800),
        field("native_y", "来源原作 Y（各游戏不同）", 340, -300, 900),
        field("depth", "原作 Z（旧版参考1200）", 1200, 1000, 2400),
        field("alpha", "初始不透明度", 255, 0, 255)]),
    "PortraitFraming": ("立绘 · 可视构图与来源景别", [field("actor", "舞台位置（同时显示位置）", 1, 1, 4),
        field("source_game", "素材来源游戏", ""), field("archive", "立绘 BIN（graph_bs / graph）", ""),
        field("body", "基础身体名（景别后缀自动绑定）", ""), field("expression", "表情帧", 0, 0, 999),
        field("framing", "景别策略（auto按来源选择）", "auto", options=["auto","M","L","reference"]),
        field("stage_x", "舞台锚点 X（1280宽，可拖动）", 640, -640, 1920),
        field("offset_y", "相对来源基准上下移动（舞台像素）", 0, -720, 1080),
        field("size_percent", "创作倍率（100保留所选景别）", 100, 25, 250),
        field("alpha", "初始不透明度", 255, 0, 255)]),
    "CG": ("CG · 原作包装加载与转场", [field("resource", "原作CG资源", "MARE_e01a",
        options=["MARE_e01a", "MARE_e01b", "MARE_e01c"]),
        field("x", "原作CG初始 X", 0, -300, 300), field("y", "原作CG初始 Y", 0, -200, 200),
        field("depth", "CG初始 Z", 2000, 1400, 2600), field("rotation", "原生 R（非度）", 0, -500, 500),
        field("duration_ms", "原作转场时长（0=原作默认）", 0, 0, 3000)]),
    "CGVariant": ("CG差分 · 保留构图与镜头", [field("resource", "目标差分", "MARE_e01b",
        options=["MARE_e01a", "MARE_e01b", "MARE_e01c"]),
        field("mode", "继承方式", "keep_v3d", options=["keep_v3d", "native_local"]),
        field("duration_ms", "转场时长（0=原作默认）", 0, 0, 3000)]),
    "CGImported": ("CG · 导入游戏资源（独立候选）", [
        field("source_game", "素材来源游戏", ""),
        field("archive", "来源 graph_vis BIN 路径", ""),
        field("resource", "CG 资源名", ""),
        field("x", "CG 初始 X", 0, -300, 300),
        field("y", "CG 初始 Y", 0, -200, 200),
        field("depth", "CG 初始 Z", 2000, 1400, 2600),
        field("rotation", "原生 R（非度）", 0, -500, 500),
        field("scale_percent", "适配画面后的大小（%）", 100, 50, 150),
        field("duration_ms", "原作转场时长（0=原作默认）", 0, 0, 3000)]),
    "CGAction": ("高级 · CG多通道组合动作", [field("channels", "动作通道", "z", options=["z", "r", "xy", "xy+z+r"]),
        field("x", "目标原作CG X", 0, -300, 300), field("y", "目标原作CG Y", 0, -200, 200),
        field("depth", "目标CG Z", 2000, 1400, 2600), field("rotation", "目标原生 R（非度）", 0, -500, 500),
        field("duration_ms", "运动时长（毫秒）", 2600, 200, 6000), field("curve", "运动节奏（2慢起步／3慢收尾）", 3, 2, 3)]),
    "CGExit": ("CG退场 · 原作整场清理", [field("colour", "退场纯色", "white", options=["white", "black"]),
        field("duration_ms", "原作转场时长", 800, 600, 3000)]),
    "Action": ("高级 · 立绘多通道组合动作", [field("actor", "舞台位置（同时显示位置）", 1, 1, 4),
        field("channels", "动作通道", "xy", options=["xy", "z", "r", "s2", "alpha", "parts", "xy+z+r", "xy+alpha", "xy+s2"]),
        field("dx", "相对 X（原作单位）", 0, -800, 800), field("dy", "相对 Y（原作单位）", 0, -500, 500),
        field("depth", "目标深度 Z", 1600, 500, 2400),
        field("rotation", "目标旋转（原生单位，非度）", 0, -1000, 1000),
        field("scale_x", "横向尺寸（初始为100%）", 100, 50, 150),
        field("scale_y", "纵向尺寸（初始为100%）", 100, 50, 150),
        field("alpha", "目标不透明度", 255, 0, 255), field("expression", "目标表情帧", 1, 0, 999),
        field("duration_ms", "动作时长（毫秒；表情0=直接切换）", 2400, 0, 6000),
        field("curve", "运动节奏（2慢起步／3慢收尾）", 3, 2, 3)]),
    "Camera": ("镜头移动 / 推拉（共享 V3D）", [field("x", "原作镜头 X", 0, -120, 120),
        field("y", "原作镜头 Y", 0, -80, 80), field("zoom", "相对本场BG/CG基准取景（%）", 100, 80, 150),
        field("duration_ms", "运动时长（毫秒）", 2800, 200, 6000), field("curve", "原生曲线", 3, 2, 3)]),
    "CameraNative": ("镜头 · 原作XYZ组合复现", [field("x", "原作镜头 X", 0, -240, 240),
        field("y", "原作镜头 Y", 0, -120, 120), field("z", "原作镜头 Z（非百分比）", 0, -800, 850),
        field("duration_ms", "运动时长（毫秒）", 2800, 200, 6000), field("curve", "原生曲线", 3, 2, 3)]),
    "CameraShot": ("镜头 · 可视取景（共享V3D）", [field("center_x", "取景中心 X（基准舞台，可拖框）", 640, 0, 1280),
        field("center_y", "取景中心 Y（基准舞台，可拖框）", 360, 0, 720),
        field("zoom", "BG/CG参考平面倍率（%）", 100, 80, 150),
        field("duration_ms", "名义时长（毫秒）", 1200, 200, 6000), field("curve", "曲线：2慢到快／3快到慢", 3, 2, 3)]),
    "Dialogue": ("台词 / 观察点（与动作同时）", [field("case_id", "测试编号", "A01"),
        field("text", "游戏内台词 / 观察说明", ""), field("expected", "验收要点（不写入游戏）", "")]),
    "Text": ("台词 · 正文（与动作同时）", [field("line_id", "台词 ID（不显示在游戏中）", "line_1"),
        field("text", "台词正文", "在这里输入台词。")]),
    "Speech": ("台词 · 说话人与 B.LOG", [field("line_id", "台词 ID（不显示在游戏中）", "line_1"),
        field("text", "台词正文", "在这里输入台词。"),
        field("speaker_mode", "说话人方式", "narration", options=["narration", "character", "custom", "unknown"]),
        field("speaker_id", "来源角色标识", ""), field("display_name", "自定义显示名", ""),
        field("source_game", "说话人来源（配色待接入）", ""),
        field("blog_mode", "B.LOG 头像", "follow", options=["follow", "manual", "none"]),
        field("blog_speaker_id", "手动头像角色标识", "")]),
    "PortraitSwap": ("立绘 · 在此处换角色 / 服装", [field("actor", "舞台位置（同时显示位置）", 1, 1, 4),
        field("source_game", "素材来源游戏", ""), field("archive", "立绘 BIN（graph_bs / graph）", ""),
        field("body", "身体资源名（自动配对表情）", ""), field("expression", "表情帧", 0, 0, 999),
        field("framing_policy", "换角构图", "keep", options=["keep", "source"])]),
    "Choice": ("选项 · 原作选择菜单", [field("choice_id", "选项 ID", "choice_1"),
        field("prompt", "选择提示", "接下来要怎么做？"),
        field("option_1", "选项 1", "选项一"), field("option_2", "选项 2", "选项二"),
        field("option_3", "选项 3（可留空）", ""), field("option_4", "选项 4（可留空）", "")]),
    "ChoiceCase": ("选项 · 分支入口", [field("choice_id", "所属选项 ID", "choice_1"),
        field("option_index", "选项序号（1开始）", 1, 1, 4)]),
    "ChoiceEnd": ("选项 · 分支汇合", [field("choice_id", "所属选项 ID", "choice_1")]),
    "Wait": ("等待动作汇合", []),
    "Hide": ("立绘原地消失 / 清除", [field("actor", "舞台位置（同时显示位置）", 1, 1, 4)]),
    "Transition": ("整幕转场", [field("method", "转场方式", "black_out", options=["black_out", "white_out", "reveal", "black_return", "white_return", "dissolve"]),
        field("duration_ms", "单程时长（毫秒）", 1000, 100, 3000)]),
    "Jump": ("场景跳转", [field("target", "目标场景 ID", "B")]),
    "End": ("结束并恢复原作", []),
    "Build": ("运行：自检 / 写入独立副本", [field("run_mode", "运行完成后", RUN_MODE_CHECK,
        options=[RUN_MODE_CHECK, RUN_MODE_WRITE])]),
}

# Each ordinary action is its own searchable node. The old multi-channel
# nodes remain readable for V17 workflows; the compiler receives the same
# validated native action contract from either representation.
ACTION_PRESETS = {
    "ActionMove": ("立绘 · 平移", "Action", "xy", ("actor", "dx", "dy", "duration_ms", "curve")),
    "ActionDepth": ("立绘 · 前后景深", "Action", "z", ("actor", "depth", "duration_ms", "curve")),
    "ActionTilt": ("立绘 · 倾斜旋转", "Action", "r", ("actor", "rotation", "duration_ms", "curve")),
    "ActionSize": ("立绘 · 局部尺寸", "Action", "s2", ("actor", "scale_x", "scale_y", "duration_ms", "curve")),
    "ActionFade": ("立绘 · 淡入淡出", "Action", "alpha", ("actor", "alpha", "duration_ms")),
    "ActionExpression": ("立绘 · 表情差分", "Action", "parts", ("actor", "expression", "duration_ms")),
    "CGMove": ("CG · 平移", "CGAction", "xy", ("x", "y", "duration_ms", "curve")),
    "CGDepth": ("CG · 前后景深", "CGAction", "z", ("depth", "duration_ms", "curve")),
    "CGTilt": ("CG · 倾斜旋转", "CGAction", "r", ("rotation", "duration_ms", "curve")),
}
for preset_kind, (preset_title, base_kind, _channel, selected_fields) in ACTION_PRESETS.items():
    DEFINITIONS[preset_kind] = (preset_title, [copy.deepcopy(f) for f in DEFINITIONS[base_kind][1]
        if f["name"] in selected_fields])
    if base_kind == "Action":
        duration = next(f for f in DEFINITIONS[preset_kind][1] if f["name"] == "duration_ms")
        if _channel == "parts":
            duration["label"] = "表情渐变时长（毫秒；0=直接切换）"
            duration["default"] = EXPRESSION_DEFAULT_DURATION_MS
        else:
            duration.update(low=100, label="运动时长（毫秒）")


def values(kind, supplied):
    if kind not in DEFINITIONS:
        raise ValueError(f"未知综合演出节点: {kind}")
    fields = DEFINITIONS[kind][1]
    if set(supplied) - {f["name"] for f in fields}:
        raise ValueError(f"{kind} 含未知参数")
    result = {}
    for f in fields:
        default = f["default"]
        if kind == "Action" and f["name"] == "duration_ms" and result["channels"] == "parts":
            default = EXPRESSION_DEFAULT_DURATION_MS
        v = supplied.get(f["name"], default)
        if type(f["default"]) is int:
            if type(v) is not int or not f["low"] <= v <= f["high"]:
                raise ValueError(f"{f['label']} 超出范围")
        elif not isinstance(v, str) or len(v) > 4096:
            raise ValueError(f"{f['label']} 必须是短文本")
        if f["options"] and v not in f["options"]:
            raise ValueError(f"{f['label']} 不是支持的选项")
        result[f["name"]] = v
    if kind in ("Action", "ActionExpression") and result["duration_ms"] < 100:
        expression_only = kind == "ActionExpression" or result["channels"] == "parts"
        if not (expression_only and result["duration_ms"] == 0):
            raise ValueError("表情直接切换用0毫秒；渐变和其他动作时长须为100～6000毫秒")
    return result


def append(flow, kind, supplied):
    v = values(kind, supplied)
    if kind == "Project":
        return {"schema": SCHEMA, **v, "events": []}
    if not isinstance(flow, dict) or flow.get("schema") != SCHEMA:
        raise ValueError("请连接综合演出工程，不能混入原作保真流")
    if kind in ACTION_PRESETS:
        _title, base_kind, channel, _fields = ACTION_PRESETS[kind]
        v = values(base_kind, {**v, "channels": channel})
        kind = base_kind
    result = copy.deepcopy(flow)
    result["events"].append({"kind": kind, **v})
    return result


def workflow_to_program(graph):
    """Read topology, not node order; reject mute/bypass, fan-out and orphan nodes."""
    nodes = graph.get("nodes", [])
    by_id = {n["id"]: n for n in nodes}
    if len(by_id) != len(nodes) or not nodes:
        raise ValueError("节点 ID 重复或工作流为空")
    links = {l[0]: l for l in graph.get("links", [])}
    if len(links) != len(graph.get("links", [])):
        raise ValueError("连线 ID 重复")
    roots = [n for n in nodes if n.get("type") == PREFIX + "Project"]
    if len(roots) != 1:
        raise ValueError("综合演出须有且仅有一个工程入口")
    n, seen, flow, used = roots[0], set(), None, set()
    while True:
        if n["id"] in seen or n.get("mode", 0) != 0:
            raise ValueError("禁止连线环、静音或绕过节点")
        seen.add(n["id"])
        kind = n.get("type", "").removeprefix(PREFIX)
        if kind not in DEFINITIONS:
            raise ValueError(f"不支持的节点 {n.get('type')}")
        fields = DEFINITIONS[kind][1]
        widget = n.get("widgets_values", [])
        # Workflows saved before the run-mode selector had no Build widget.
        # They keep their original candidate-only meaning after an upgrade.
        if kind == "Build" and widget == []:
            widget = [RUN_MODE_CHECK]
        if not isinstance(widget, list) or len(widget) != len(fields):
            raise ValueError(f"{kind} 控件格式漂移")
        if kind == "Build" and widget[0] not in (RUN_MODE_CHECK, RUN_MODE_WRITE):
            raise ValueError("运行模式不是受支持的选项")
        if kind == "Build":
            break
        flow = append(flow, kind, dict(zip([f["name"] for f in fields], widget)))
        flow.setdefault("node_ids", []).append(n["id"])
        ports = n.get("outputs", [])
        outgoing = ports[0].get("links", []) if len(ports) == 1 else []
        if len(outgoing or []) != 1 or outgoing[0] not in links:
            raise ValueError(f"{kind} 须通过唯一演出流连接下一节点")
        l = links[outgoing[0]]
        if len(l) != 6 or l[1:3] != [n["id"], 0] or l[3] not in by_id or l[4] != 0 or l[5] != "FVP_PERFORMANCE":
            raise ValueError("连线端点或类型不匹配")
        n = by_id[l[3]]
        if not n.get("inputs") or n["inputs"][0].get("link") != l[0]:
            raise ValueError("输入输出连线不对称")
        used.add(l[0])
    if seen != set(by_id) or used != set(links) or any(p.get("links") for p in n.get("outputs", [])):
        raise ValueError("存在未纳入构建的节点/连线或构建节点不是终点")
    return flow


def digest(program):
    # Canvas-only position/title changes deliberately do not change runtime bytes.
    value = {k: v for k, v in program.items() if k != "node_ids"}
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def upstream_program(graph, selected_id):
    """Preview only: trace one node's ancestors; unfinished downstream is okay.

    Does not relax workflow_to_program/build validation. Never guesses disconnected
    input, mute/bypass, converted widgets or a mixed-family flow.
    """
    nodes = {n['id']: n for n in graph.get('nodes', [])}
    links = {l[0]: l for l in graph.get('links', [])}
    if len(nodes) != len(graph.get('nodes', [])) or len(nodes) > 600:
        raise ValueError('节点重复或预览规模超限')
    if len(links) != len(graph.get('links', [])):
        raise ValueError('连线 ID 重复')
    chain, seen = [], set()
    current = selected_id
    while True:
        if current in seen or current not in nodes:
            raise ValueError('上游断开或成环，不能猜测舞台状态')
        seen.add(current)
        n = nodes[current]
        kind = str(n.get('type','')).removeprefix(PREFIX)
        if n.get('mode',0) != 0 or kind not in DEFINITIONS or not str(n.get('type','')).startswith(PREFIX):
            raise ValueError('预览上游包含静音、绕过或非综合演出节点')
        fields = DEFINITIONS[kind][1]
        widgets = n.get('widgets_values',[])
        if not isinstance(widgets, list) or len(widgets) != len(fields):
            raise ValueError('控件格式漂移或控件已转换为输入；请恢复普通控件')
        e = values(kind, dict(zip([f['name'] for f in fields], widgets)))
        chain.append((n['id'],kind,e))
        if kind == 'Project':
            break
        inputs = n.get('inputs',[])
        l = links.get(inputs[0].get('link')) if inputs else None
        if not l or len(l) != 6 or l[3:5] != [current,0] or l[5] != 'FVP_PERFORMANCE' or l[2] != 0:
            raise ValueError('上游演出流未连接或类型错误')
        parent = nodes.get(l[1], {})
        outputs = parent.get('outputs', [])
        if not outputs or l[0] not in (outputs[0].get('links') or []):
            raise ValueError('上游输入输出连线不对称')
        current = l[1]
    flow = None
    node_ids = []
    for ident,kind,e in reversed(chain):
        if kind == 'Build':
            continue
        flow = append(flow,kind,e)
        if kind != 'Project':
            node_ids.append(ident)
    flow['node_ids'] = node_ids
    return flow
