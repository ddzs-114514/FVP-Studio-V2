"""Read-only GUI scene -> audited native emitter preflight.

This does NOT call Resources/build_candidate/publish_candidate/an installer.
Small, referenced entries and the audited HCB/EXE are read, the existing emitter
is exercised in memory, and only JSON proof is returned. Virtual resource names
make these bytes intentionally non-deliverable: no resource pack is assembled.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import math
from pathlib import Path
import re
import struct

from .gui_runtime import GuiRuntimeError, ID_RE, fingerprint
from .hcb import parse_bytes
from .performance_compile import (Emitter, SOURCE_SHA, CLEAN_SHA, EXE_SHA,
    ENTRY, ENTRY_BYTES, rounded, validate_program)
from .performance_portrait_limits import checked_portrait_scale
from .performance_choices import choice_options
from .gui_actor_program import KINDS as ACTOR_KINDS, event_values as actor_values
from .gui_background_program import KINDS as BG_KINDS, event_values as bg_values, report as background_report
from .gui_background_blur import KINDS as BLUR_KINDS, event_values as blur_values, report as blur_report
from .gui_choice_tracks import (SCHEMA as TRACK_PROGRAM_SCHEMA, CONTRACT as TRACK_CONTRACT,
    KINDS as TRACK_KINDS, event_values as track_event_values)
from .performance_workflow import SCHEMA as PROGRAM_SCHEMA, values, digest
from .gui_native_cg import (SCHEMA as CG_PROGRAM_SCHEMA, CONTRACT as CG_CONTRACT,
    KINDS as CG_KINDS, GuiCgEmitter, event_values as cg_event_values,
    validate_gui_program, cg_scale)

REQUEST_SCHEMA = "fvp-gui-preflight-request/1"
RESPONSE_SCHEMA = "fvp-gui-native-preflight/1"
PROJECT_SCHEMA = "fvp-story-studio-project/1"
SCOPE = "selected_scene_independent_rehearsal"
MAX_BYTES = 16 * 1024 * 1024
SCENE_RE = re.compile(r"story-scene-[0-9]{4,9}\Z")
LIMITS = ["仅当前场景独立试演预检，不检查章节连线或原作挂接",
          "未生成候选 HCB/BIN，未写入游戏",
          "舞台二维预览不等于原作引擎验收",
          "目前目标母本仅支持已审核星空 HD ABI；外部立绘仍按来源原生大小",
          "资源名为预检专用虚拟绑定，内存字节码不能作为可运行候选"]


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def checksum(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def numeric(value, low, high, label, *, integral=False):
    if (type(value) not in (int, float) or not math.isfinite(value)
            or not low <= value <= high or (integral and int(value) != value)):
        raise ValueError(f"{label} 超出范围或不是有限数值")
    return int(value) if integral else value


def ident(value, label="ID"):
    if not isinstance(value, str) or not ID_RE.fullmatch(value):
        raise ValueError(f"{label} 不合法")
    return value


def object_only(value, label):
    if not isinstance(value, dict):
        raise ValueError(f"{label} 必须是对象")
    return value


class FrozenResources:
    """Read metadata only; explicitly virtual names, never a final BIN pack."""
    def __init__(self):
        self.backgrounds, self.portraits, self.cgs, self.references = {}, {}, {}, []
        self.audios = {}
        self.speakers = {}
        self.audio_target_root, self._audio_bindings = None, None

    def bg(self, event):
        return self.backgrounds[(event["archive"], event["resource"], event["fit"])]

    def portrait(self, event):
        return self.portraits[(event["archive"], event["body"])]

    def cg(self, event):
        return self.cgs[(event["archive"], event["resource"])]

    def audio(self, event):
        return self.audio_binding_plan().audio(event)

    def speech(self, event):
        key = (event.get("source_game", event.get("speaker_source", "")), event["display_name"])
        binding = deepcopy(self.speakers.get(key))
        if binding and binding.get("source") != "hoshi" and binding.get("avatar"):
            binding["resource"] = "BL_PREFLIGHT_" + checksum(key)[:24].upper()
        return binding

    def audio_binding_plan(self):
        from .gui_audio_bindings import GuiAudioBindings
        if self._audio_bindings is None:
            if self.audio_target_root is None:
                # Compatibility for a direct, already frozen read-only set.
                if any(v.get("native_id") is None for v in self.audios.values()):
                    raise ValueError("声音导入缺少已登记的目标游戏。")
                self.audio_target_root = "."
            self._audio_bindings = GuiAudioBindings(self.audio_target_root, self)
        return self._audio_bindings

    def check_unchanged(self):
        for path, stamp in self.references:
            if fingerprint(path) != stamp:
                raise GuiRuntimeError("source_changed", "原生预检期间来源发生变化", 409)


class GuiNativePreflight:
    def __init__(self, runtime):
        self.runtime = runtime

    def run(self, request):
        object_only(request, "请求")
        if set(request) != {"schema", "scene_id", "request_id", "document"}:
            raise GuiRuntimeError("invalid_request", "预检请求包含未知或缺少字段")
        if request["schema"] != REQUEST_SCHEMA:
            raise GuiRuntimeError("invalid_request", "原生预检请求格式不支持")
        try:
            request_id = ident(request["request_id"], "请求 ID")
            scene_id = request["scene_id"]
            if not isinstance(scene_id, str) or not SCENE_RE.fullmatch(scene_id):
                raise ValueError("场景 ID 不合法")
            document = object_only(request["document"], "工程文件")
            if document.get("schema") != PROJECT_SCHEMA:
                raise ValueError("工程文件格式不支持")
            project = object_only(document.get("project"), "工程")
            scene = object_only(object_only(project.get("scenes"), "场景表").get(scene_id), "所选场景")
            if scene.get("id") != scene_id:
                raise ValueError("场景 ID 与场景表键不一致")
            if len(canonical(document)) > MAX_BYTES:
                raise GuiRuntimeError("request_too_large", "工程超过 16 MiB", 413)
            if len(canonical(scene)) > 512 * 1024:
                raise ValueError("当前场景过大，请分成较小场景预检")
        except GuiRuntimeError:
            raise
        except (ValueError, TypeError, RecursionError) as exc:
            raise GuiRuntimeError("invalid_request", str(exc)) from exc
        builder = SceneBuilder(self.runtime, project, scene)
        result = dict(ok=True, schema=RESPONSE_SCHEMA, request_id=request_id,
            scene_id=scene_id, scope=SCOPE, passed=False, document_sha256=checksum(document),
            scene_sha256=checksum(scene), writes_performed=False, game_writeback=False,
            candidate_generated=False, issues=builder.issues, mapping=builder.mapping,
            program=None, native_emit=None, limits=list(LIMITS))
        program = builder.translate()
        if builder.has_errors:
            return result
        try:
            validate_gui_program(program)
            proof = native_emit(program, builder.resources)
        except GuiRuntimeError:
            raise
        except (ValueError, KeyError, IndexError) as exc:
            builder.issue("error", "native_contract_rejected", str(exc), field="program")
            return result
        result.update(passed=True, program=program, native_emit=proof)
        return result


class SceneBuilder:
    def __init__(self, runtime, project, scene, *, story_variables=None, native_export_target=False):
        self.runtime, self.project, self.scene = runtime, project, scene
        # Chapter/story generation owns initialization and shared route state.
        # An isolated scene must not silently drop those semantics.
        self.story_variables = story_variables
        # Only the separate generic new-copy exporter opts into portable event
        # translation. This does not widen the Hoshi preflight/emitter gate.
        self.native_export_target = native_export_target
        self.issues, self.mapping = [], []
        self.events, self.resources = [], FrozenResources()
        self.actors, self.bodies, self.parameters, self.present = {}, {}, {}, set()
        self.actor_bindings = {}
        self.body_defs, self.verified = {}, {}
        self.location = {}
        self.cg_state, self.cg_bindings = None, {}
        self.camera_changed = False
        self.camera_state = (640, 360, 100)
        self.background_state = None
        self.background_asset_id, self.background_blur_state = None, None
        self.covered = False
        self.beat_ids, self.track_ids = set(), set()

    @property
    def has_errors(self):
        return any(i["level"] == "error" for i in self.issues)

    def issue(self, level, code, message, **location):
        entry = dict(level=level, code=code, message=str(message)[:1000],
            scene_id=self.scene["id"], **{**self.location, **location})
        if len(self.issues) >= 100:
            # CG diagnostics can fill the bounded report. Never let earlier
            # informational entries hide the first later error and falsely pass.
            if level == "error" and not self.has_errors:
                self.issues[-1] = entry
            return
        self.issues.append(entry)

    def add(self, kind, fields=None):
        from .gui_audio_program import KINDS as AUDIO_KINDS, event_values as audio_values
        from .gui_story_logic import KINDS as LOGIC_KINDS, event_values as logic_values
        parser = (lambda k, f: logic_values(k, f, self.story_variables or {}) if k in LOGIC_KINDS else
                  actor_values(k, f) if k in ACTOR_KINDS else audio_values(k, f) if k in AUDIO_KINDS else
                  track_event_values(k, f) if k in TRACK_KINDS else
                  bg_values(k, f) if k in BG_KINDS else
                  blur_values(k, f) if k in BLUR_KINDS else
                  cg_event_values(k, f) if k in CG_KINDS else values(k, f))
        event = {"kind": kind, **parser(kind, fields or {})}
        if len(self.events) >= 500:
            raise ValueError("原生事件数超过 500")
        self.mapping.append(dict(scene_id=self.scene["id"], **self.location,
                                 event_indexes=[len(self.events)]))
        self.events.append(event)

    def check_fields(self, value, allowed, label):
        object_only(value, label)
        extra = set(value) - set(allowed)
        if extra:
            raise ValueError(f"{label} 包含未处理字段：{', '.join(sorted(extra))}")

    def translate(self):
        if self.project.get("source") != "hoshi" and not self.native_export_target:
            self.issue("error", "unsupported_target", "原生预检目标母本目前仅支持已审核星空 HD，不把立绘通用导入误认为所有游戏编译均已接通")
            return None
        try:
            source = self.runtime._source(self.project.get("source"))
            self.root = source.root
            self.resources.audio_target_root = self.root
            title = self.scene.get("title")
            if not isinstance(title, str) or len(title) > 512:
                raise ValueError("场景标题须为不超过 512 字的文本")
            self.check_fields(self.scene, ("id", "title", "anchor", "setup", "actors", "beats", "exit"), "场景")
            self.add("Scene", dict(scene_id=self.scene["id"], title=title))
            self.issue("info", "scope_isolated", "仅预检当前场景独立试演；忽略原作挂接点和章节出口，不表示章节连线已通过", field="exit")
            setup = object_only(self.scene.get("setup"), "开场布置")
            self.check_fields(setup, ("bg", "cg"), "开场布置")
            if setup.get("cg") is not None:
                self.issue("error", "unsupported_cg_setup", "开场 CG 的直接显现尚未接通；本轮 CG 须在单独台词/等待节拍中显式淡入，不会省略开场 CG", field="setup.cg")
            if setup.get("bg") is None:
                self.issue("error", "missing_background", "独立立绘舞台必须指定原作背景，不猜测原作当前背景", field="setup.bg")
            else:
                self.background(setup["bg"])
            actors = self.scene.get("actors")
            if not isinstance(actors, list) or len(actors) > 4:
                raise ValueError("当前原生舞台最多 4 个角色槽")
            cast = self.project.get("cast")
            if not isinstance(cast, list):
                raise ValueError("缺少角色表")
            for character in cast:
                object_only(character, "角色")
                if not isinstance(character.get("bodies"), list):
                    raise ValueError("角色身体表格式错误")
                for body in character["bodies"]:
                    object_only(body, "身体")
                    key = ident(body.get("id"), "身体 ID")
                    if key in self.body_defs:
                        raise ValueError("身体 ID 重复")
                    self.body_defs[key] = (character.get("id"), body)
            for slot, actor in enumerate(actors, 1):
                self.check_fields(actor, ("key", "char", "body", "x", "expr", "atStart", "ov", "lock", "displayEvidence", "nativeSize"), "角色实例")
                key = ident(actor.get("key"), "角色实例 ID")
                if key in self.actors:
                    raise ValueError("角色实例 ID 重复")
                if type(actor.get("atStart")) is not bool:
                    raise ValueError("角色 atStart 必须为布尔值")
                pair = self.body_defs.get(actor.get("body"))
                if not pair or pair[0] != actor.get("char"):
                    raise ValueError("实例身体不属于引用角色")
                self.actors[key] = (slot, actor)
            # Load every actor before launching any same-beat motion: Portrait
            # settles previous motion; no accidental serialisation of fades.
            for key, (_slot, actor) in self.actors.items():
                if actor["atStart"]:
                    self.location = dict(field="actors", actor_key=key)
                    self.load_actor(key, 255)
            beats = self.scene.get("beats")
            if not isinstance(beats, list) or not 1 <= len(beats) <= 100:
                raise ValueError("当前场景节拍数须为 1～100")
            action_ids = set()
            for index, beat in enumerate(beats):
                following = beats[index+1] if index+1 < len(beats) else None
                self.next_beat_id = following.get("id") if isinstance(following, dict) else None
                self.last_root_beat = index == len(beats)-1
                self.translate_beat(beat, action_ids)
            self.location = dict(field="exit")
            self.add("End")
            self.location = {}
            from .gui_audio_program import KINDS as AUDIO_KINDS
            schema = (TRACK_PROGRAM_SCHEMA if any(e["kind"] in TRACK_KINDS for e in self.events)
                      else CG_PROGRAM_SCHEMA if any(e["kind"] in CG_KINDS | AUDIO_KINDS | ACTOR_KINDS | BG_KINDS | BLUR_KINDS for e in self.events)
                      else PROGRAM_SCHEMA)
            return dict(schema=schema, source_root=str(self.root),
                        title=title, events=self.events)
        except GuiRuntimeError as exc:
            self.issue("error", exc.code, str(exc))
        except (ValueError, TypeError, KeyError) as exc:
            self.issue("error", "invalid_scene", str(exc))
        return None

    def translate_beat(self, beat, action_ids, location=None):
        self.location = dict(location or {})
        try:
            object_only(beat, "节拍")
            bid = ident(beat.get("id"), "节拍 ID")
            self.location["beat_id"] = bid
            if bid in self.beat_ids:
                raise ValueError("节拍 ID 重复（包括各选项轨道）")
            self.beat_ids.add(bid)
            if location is not None and beat.get("kind") == "choice":
                raise ValueError("本轮分支轨道内还不能再嵌套选项")
            self.beat(beat, action_ids)
        except (ValueError, KeyError, TypeError) as exc:
            self.issue("error", "invalid_beat", str(exc), field=self.location.get("field", "beats"))

    def background_reference(self, asset_id):
        graphics = object_only(self.project.get("externalGraphics", {}), "原作背景登记")
        definition = graphics.get(asset_id)
        if not isinstance(definition, dict) or definition.get("category") != "background":
            raise ValueError("背景不是已登记原作素材；内置示意图不能参与原生预检")
        self.check_fields(definition, ("source", "category", "archive", "resource", "frame", "frame_count", "width", "height", "sha256", "entry_index", "category_basis", "fit"), "背景登记")
        if definition.get("fit") not in ("contain", "cover") or definition.get("frame") != 0:
            raise ValueError("原生预检背景只支持完整单帧 contain/cover")
        source = self.runtime._source(definition["source"])
        # Delegate archive allowlisting to the existing graphics bridge before
        # even inspecting a client-supplied archive path.
        descriptor = self.runtime.graphics.descriptor(source)
        if definition.get("archive") not in descriptor["graphics_archives"]["background"]:
            raise ValueError("背景档案不在来源允许列表")
        path = (source.root / definition["archive"]).resolve(strict=True)
        if path.parent != source.root:
            raise ValueError("背景档案不在已登记来源目录")
        before = fingerprint(path)
        fresh = self.runtime.graphics.graphic(definition.get("source"), "background",
            definition.get("archive"), definition.get("resource"))
        identity, image = fresh["identity"], fresh["image"]
        if (definition.get("sha256") != identity["payload_sha256"]
                or definition.get("entry_index") != identity["entry_index"]
                or any(definition.get(k) != image[k] for k in ("width", "height", "frame_count"))):
            raise ValueError("背景画布/指纹与本机来源不一致，请重新登记")
        if image["frame_count"] != 1:
            raise ValueError("原生预检背景不支持多帧资源")
        if fingerprint(path) != before:
            raise GuiRuntimeError("source_changed", "读取背景时来源发生变化", 409)
        archive = str(path)
        self.resources.references.append((path, before))
        self.resources.backgrounds[(archive, definition["resource"], definition["fit"])] = "BG_PREFLIGHT_" + definition["sha256"][:20].upper()
        return dict(source_game=source.name, archive=archive,
                    resource=definition["resource"], fit=definition["fit"])

    def background(self, asset_id):
        fields = self.background_reference(asset_id)
        self.add("Background", fields)
        self.background_state = (fields["archive"], fields["resource"], fields["fit"])
        self.background_asset_id, self.background_blur_state = asset_id, None
        self.camera_state, self.camera_changed = (640, 360, 100), False

    def background_action(self, action, valid):
        self.check_fields(action["p"], ("bg",), "换背景参数")
        if action["target"] != "stage":
            raise ValueError("换背景动作需要作用于舞台。")
        if sum(a["type"] == "bg" for a in valid) != 1:
            raise ValueError("同一拍只能换一次背景。")
        if self.cg_state is not None:
            raise ValueError("请先让 CG 退场，再换普通背景。")
        if action["dur"] and self.covered:
            raise ValueError("黑白场下请直接换背景，再用淡入恢复画面。")
        if action["dur"] and any(a["type"] not in ("bg", "bgm", "se") for a in valid):
            raise ValueError("换背景渐变这一拍先不要同时改角色或镜头，请放到下一拍。")
        fields = self.background_reference(action["p"].get("bg"))
        self.add("GuiBackgroundChange", {**fields, "duration_ms": action["dur"]})
        self.background_state = (fields["archive"], fields["resource"], fields["fit"])
        self.background_asset_id, self.background_blur_state = action["p"].get("bg"), None
        # Native loading preserves the current actor geometry and V3D pose.
        # In particular, do not reuse background()'s opening-camera reset.

    def background_blur_action(self, action, valid):
        from .native_background_pairs import lookup
        self.check_fields(action["p"], ("amount",), "背景模糊参数")
        if action["target"] != "stage" or self.background_state is None or self.cg_state is not None:
            raise ValueError("背景模糊作用于普通背景；请先让 CG 退场并换回背景。")
        if any(a["type"] in ("bg", "cg", "cgxf", "cgexit") for a in valid):
            raise ValueError("请先换好背景，再在下一拍调节背景模糊。")
        if action["dur"] and self.covered:
            raise ValueError("黑白场下请直接设置模糊，再用淡入恢复画面。")
        definition = self.project["externalGraphics"][self.background_asset_id]
        source = self.runtime._source(definition["source"])
        # Pairing is proven from this source's actual HCB, not a guessed name.
        evidence, hcb, hcb_stamp = lookup(source.root, definition["resource"])
        pair = self.runtime.graphics.blur_pair(definition["source"],
            definition["archive"], definition["resource"])
        sharp, blur = pair["sharp"], pair["blur"]
        if (pair["native_pair"]["hcb_sha256"] != evidence["hcb_sha256"]
                or sharp["resource"] != definition["resource"]
                or sharp["identity"]["archive"] != definition["archive"]
                or sharp["identity"]["payload_sha256"] != definition["sha256"]
                or sharp["identity"]["entry_index"] != definition["entry_index"]
                or any(sharp["image"][k] != definition[k] for k in ("width", "height", "frame_count"))
                or blur["resource"] != evidence["blur_resource"]):
            raise ValueError("背景或模糊配对已经变化，请重新选择背景。")
        archive = blur["identity"]["archive"]
        if archive not in self.runtime.graphics.descriptor(source)["graphics_archives"]["background"]:
            raise ValueError("模糊背景档案不在来源允许列表。")
        path = (source.root / archive).resolve(strict=True)
        if path.parent != source.root:
            raise ValueError("模糊背景不在登记来源目录内。")
        stamp = fingerprint(path)
        fresh = self.runtime.graphics.graphic(definition["source"], "background", archive, blur["resource"])
        if fresh["identity"] != blur["identity"] or any(fresh["image"][k] != blur["image"][k]
                for k in ("width", "height", "frame_count")):
            raise ValueError("模糊背景发生变化，请重新选择背景。")
        if fingerprint(path) != stamp or fingerprint(hcb) != hcb_stamp:
            raise GuiRuntimeError("source_changed", "读取模糊背景时来源发生变化。", 409)
        fields = dict(source_game=source.name, archive=str(path), resource=blur["resource"],
            fit=definition["fit"], sharp_archive=self.background_state[0],
            sharp_resource=self.background_state[1], amount=action["p"].get("amount"),
            duration_ms=action["dur"])
        blur_values("GuiBackgroundBlur", fields)
        self.resources.references.extend(((path, stamp), (hcb, hcb_stamp)))
        self.resources.backgrounds[(str(path), blur["resource"], definition["fit"])] = "BG_PREFLIGHT_" + blur["identity"]["payload_sha256"][:20].upper()
        self.add("GuiBackgroundBlur", fields)
        self.background_blur_state = (str(path), blur["resource"], definition["fit"],
                                      rounded(fields["amount"] * 255 / 100))

    def actor_parameters(self, key, *, body_id=None, expression=None, source_size=False):
        slot, actor = self.actors[key]
        selected = body_id or actor["body"]
        owner, body = self.body_defs[selected]
        if owner != actor["char"]:
            raise ValueError("换装目标身体不属于该角色。")
        ext = body.get("ext")
        if not isinstance(ext, dict):
            raise ValueError("角色身体不是原作导入素材，不能用示意图尺寸编译")
        srcid, name = ext.get("source"), ext.get("body")
        cache_key = (srcid, name)
        if cache_key not in self.verified:
            source = self.runtime._source(srcid)
            before = fingerprint(source.path)
            fresh = self.runtime.portrait(srcid, name)
            source, b, f, stamp = self.runtime._pair(srcid, name)
            if stamp != before or fresh["native_size"]["body_sha256"] != b["payload_sha256"]:
                raise GuiRuntimeError("source_changed", "读取立绘原生大小时来源发生变化", 409)
            n = fresh["native_size"]
            if (n.get("uses_face_matching") is not False
                    or n.get("uses_story_camera") is not False):
                raise ValueError("来源原生尺寸契约不是严格独立导入尺寸")
            self.verified[cache_key] = (source, fresh, b, f, stamp)
        source, fresh, b, f, stamp = self.verified[cache_key]
        native = ext.get("native")
        if not isinstance(native, dict):
            raise ValueError("身体缺少来源原生大小证据")
        critical = ("schema", "body_sha256", "height", "source_rs", "source_z", "source_viewport", "target_viewport", "uses_face_matching", "uses_story_camera")
        if any(native.get(k) != fresh["native_size"].get(k) for k in critical):
            raise ValueError("身体原生尺寸证据已过期或被改写，请重新导入，不猜测大小")
        image = ext.get("image")
        if (not isinstance(image, dict) or any(image.get(k) != fresh["image"][k] for k in ("width", "height"))
                or body.get("exprs") != fresh["image"]["expression_count"]
                or ext.get("sha256") != fresh["native_size"]["body_sha256"]):
            raise ValueError("身体画布与原生证据不一致")
        src = object_only(body.get("src"), "身体来源参数")
        expected = dict(bottomY=fresh["values"]["bottom_y"], height=fresh["values"]["height"], depth=fresh["values"]["depth"])
        if any(src.get(k) != v for k, v in expected.items()):
            raise ValueError("来源参数与后端原生换算不一致；手动编辑必须记录在 ov，不修改来源值")
        override = {} if source_size else object_only(actor.get("ov"), "手动覆盖")
        self.check_fields(override, ("bottomY", "height", "depth"), "手动覆盖")
        params = dict(actor=slot, source_game=source.name, archive=str(source.path), body=name,
            expression=numeric(actor.get("expr") if expression is None else expression, 0, f["frame_count"]-1, "表情帧", integral=True),
            stage_x=rounded(numeric(actor.get("x"), -640, 1920, "舞台 X")),
            bottom_y=rounded(numeric(override.get("bottomY", expected["bottomY"]), -720, 1800, "下缘 Y")),
            height=rounded(numeric(override.get("height", expected["height"]), 1, 10000, "立绘高度")),
            depth=rounded(numeric(override.get("depth", expected["depth"]), 1000, 2400, "景深")), alpha=255)
        # Enforce exactly the existing emitter field ranges and native RS guard.
        params = values("Portrait", params)
        if not self.native_export_target:
            checked_portrait_scale(params["height"], b["height"], params["depth"])
        # Other targets validate their own viewport/RS limits after binding.
        # They must not inherit the Hoshi emitter's perspective or clamp.
        if override:
            self.issue("warn", "manual_override", "采用已保存手动覆盖；原生来源大小保留且不做人脸/头部对齐", actor_key=key)
        if body_id is None and (not isinstance(actor.get("nativeSize"), dict) or actor["nativeSize"].get("body_sha256") != native["body_sha256"]):
            raise ValueError("实例原生大小引用缺失或不匹配")
        self.resources.portraits[(str(source.path), name)] = ("CHR_PREFLIGHT_" + native["body_sha256"][:20].upper(), deepcopy(b), deepcopy(f))
        self.resources.references.append((source.path, stamp))
        self.parameters[key] = params
        return params

    def load_actor(self, key, alpha):
        if self.cg_state is not None:
            raise ValueError("CG 尚未退场，不能加载普通立绘")
        if key in self.present:
            raise ValueError("已在场角色不能再次入场；请先退场")
        binding = self.actor_bindings.get(key)
        if binding is None:
            params = self.actor_parameters(key)
        else:
            previous = self.parameters.get(key, {})
            params = self.actor_parameters(key, body_id=binding["body"],
                expression=previous.get("expression"), source_size=True)
            # Re-entry resets the authored placement, not the selected costume.
            # KEEP is an explicit author choice; SOURCE stores verified height.
            _slot, actor = self.actors[key]
            original_body = self.body_defs[actor["body"]][1]
            params.update(height=binding["height"], bottom_y=rounded(actor["ov"].get(
                "bottomY", original_body["src"]["bottomY"])),
                depth=rounded(actor["ov"].get("depth", params["depth"])))
            params = values("Portrait", params)
            self.parameters[key] = params
        self.add("Portrait", {**params, "alpha": alpha})
        self.present.add(key)

    def beat(self, beat, action_ids):
        kind, actions = beat.get("kind"), beat.get("actions")
        allowed = {"id", "kind", "actions", "check", "effects"}
        allowed |= {"speaker", "text", "voice"} if kind == "line" else {"method", "dur"} if kind == "transition" else {"prompt", "options", "merge"} if kind == "choice" else set()
        self.check_fields(beat, allowed, "节拍")
        if kind not in ("line", "wait", "transition", "choice"):
            self.issue("error", "unsupported_beat", "当前支持台词、等待、整幕转场和场景内选项", field="kind")
            return
        if not isinstance(actions, list) or len(actions) > 32:
            raise ValueError("节拍动作数超限或不是数组")
        if "effects" in beat:
            self.story_effects(beat["effects"])
        local = dict(self.location)
        valid, channels = [], set()
        for action in actions:
            self.location = dict(local)
            try:
                self.check_fields(action, ("id", "target", "type", "p", "dur", "curve"), "动作")
                aid = ident(action.get("id"), "动作 ID")
                self.location["action_id"] = aid
                if aid in action_ids:
                    raise ValueError("动作 ID 重复")
                action_ids.add(aid)
                object_only(action.get("p"), "动作参数")
                numeric(action.get("dur"), 0, 6000, "动作时长", integral=True)
                if action.get("curve") not in (2, 3):
                    raise ValueError("动作曲线须为 2 或 3")
                target, typ = action.get("target"), action.get("type")
                channel = {"enter":"alpha", "exit":"alpha", "fade":"alpha", "expr":"parts", "scale":"s2", "move":"xy", "depth":"z", "tilt":"r", "swap":"body", "camera":"camera", "bg":"bg",
                    "bgblur":"bgblur", "cg":"cg", "cgexit":"cg", "cgxf":"cgxf", "bgm":"bgm", "se":"se"}.get(typ)
                if channel is None:
                    self.issue("error", "unsupported_action", f"{typ} 尚未接入原生预检；保留 GUI 数据，不会省略动作", field="actions")
                    continue
                mark = (target, channel)
                if mark in channels:
                    raise ValueError("同一节拍同一对象同一属性通道重复，不能按数组顺序排队")
                channels.add(mark)
                if typ in ("enter", "exit") and action["p"].get("preset") in ("slideL", "slideR"):
                    if (target, "xy") in channels:
                        raise ValueError("滑入滑出已经包含移动，请不要在同拍重复添加移动。")
                    channels.add((target, "xy"))
                valid.append(action)
            except (ValueError, KeyError, TypeError, AttributeError) as exc:
                self.issue("error", "invalid_action", str(exc), field="actions")
        self.location = dict(local)
        for target in self.actors:
            if (target, "xy") in channels and (target, "s2") in channels:
                self.issue("error", "unsupported_parallel_geometry", "同拍尺寸变换加绝对平移尚未完成原生原点对应，不按动作数组顺序猜测", actor_key=target, field="actions")
            if (target, "xy") in channels and (target, "z") in channels:
                self.issue("error", "unsupported_parallel_geometry", "移动和景深请先分成两个节拍；同时改变投影平面的轨道尚未接通。", actor_key=target, field="actions")
        if kind == "transition" and any(a.get("type") not in ("bgm", "se") for a in actions):
            self.issue("error", "unsupported_parallel_transition", "整幕转场与同拍动作尚未完成原生时序对应，不能把并行改成串行", field="actions")
            return
        cg_actions = [a for a in valid if a["type"] in ("cg", "cgxf", "cgexit") or a["target"] == "cgview"]
        handled = set()
        # Audio registration precedes this beat's visual actions. It does not
        # get serialized behind a blocking CG exit just because of array order.
        for action in valid:
            if action["type"] not in ("bgm", "se"):
                continue
            self.location = {**local, "action_id": action["id"]}
            try:
                self.audio_action(action)
            except (ValueError, KeyError, TypeError, GuiRuntimeError) as exc:
                self.issue("error", "audio_contract_rejected", str(exc), field="actions")
            handled.add(action["id"])
        if cg_actions:
            handled |= self.cg_beat([a for a in valid if a["type"] not in ("bgm", "se")], cg_actions, kind, local)
        for action in valid:
            if action["type"] != "bg" or action["id"] in handled:
                continue
            self.location = {**local, "action_id": action["id"]}
            try:
                self.background_action(action, valid)
            except (ValueError, KeyError, TypeError, GuiRuntimeError) as exc:
                self.issue("error", "background_change_rejected", str(exc), field="actions")
            handled.add(action["id"])
        self.location = dict(local)
        deferred_hide = []
        enters = [a for a in valid if a["type"] == "enter"]
        for action in enters:
            self.location = {**local, "action_id": action["id"]}
            try:
                self.check_fields(action["p"], ("preset",), "入场参数")
                if action["p"].get("preset") not in ("cut", "fade", "slideL", "slideR"):
                    raise ValueError("入场方式不正确。")
                if action.get("target") not in self.actors:
                    raise ValueError("入场角色引用断开")
                if action["p"]["preset"] == "cut" and action["dur"] != 0:
                    raise ValueError("直接入场必须为零时长")
                if action["p"]["preset"] == "fade":
                    numeric(action["dur"], 100, 6000, "淡入时长", integral=True)
                self.load_actor(action["target"], 255 if action["p"]["preset"] == "cut" else 0)
            except (ValueError, KeyError, TypeError, GuiRuntimeError) as exc:
                self.issue("error", "invalid_enter", str(exc), field="actions")
        # New body registration precedes other channels; positive swap dur
        # keeps the old body in its native back buffer until both fades end.
        # The source-size resolver remains unmodified.
        for action in [a for a in valid if a["type"] == "swap"]:
            self.location = {**local, "action_id": action["id"]}
            try:
                if action["dur"] > 0 and any(a["target"] == action["target"]
                        and a["type"] in ("enter", "exit", "fade") for a in valid):
                    raise ValueError("换装渐变和同一角色的入场、退场或透明度变化请分成两个节拍；不能静默省掉其中一个。")
                self.swap_actor(action)
            except (ValueError, KeyError, TypeError, GuiRuntimeError) as exc:
                self.issue("error", "invalid_swap", str(exc), field="actions")
            handled.add(action["id"])
        # Load every portrait/body first, then load/arm blur, then launch the
        # remaining motions. A first-use blur load must not join a fade that
        # was just started earlier in this same beat.
        for action in [a for a in valid if a["type"] == "bgblur"]:
            self.location = {**local, "action_id": action["id"]}
            try:
                self.background_blur_action(action, valid)
            except (ValueError, KeyError, TypeError, GuiRuntimeError) as exc:
                self.issue("error", "background_blur_rejected", str(exc), field="actions")
            handled.add(action["id"])
        for action in valid:
            self.location = {**local, "action_id": action["id"]}
            try:
                target, typ, p, dur = action["target"], action["type"], action["p"], action["dur"]
                if action["id"] in handled:
                    continue
                if typ == "bg":
                    continue
                if target == "camera":
                    if typ != "camera":
                        raise ValueError("镜头对象与动作类型不匹配")
                    self.check_fields(p, ("cx", "cy", "zoom"), "镜头参数")
                    self.add("CameraShot", dict(center_x=rounded(numeric(p.get("cx"), 0, 1280, "取景 X")),
                        center_y=rounded(numeric(p.get("cy"), 0, 720, "取景 Y")),
                        zoom=rounded(numeric(p.get("zoom"), 80, 150, "镜头倍率")), duration_ms=dur, curve=action["curve"]))
                    self.camera_changed = (p["cx"], p["cy"], p["zoom"]) != (640, 360, 100)
                    self.camera_state = (p["cx"], p["cy"], p["zoom"])
                    continue
                if self.cg_state is not None:
                    raise ValueError("CG 模式下不能对普通立绘执行动作")
                if target not in self.present or target not in self.actors:
                    raise ValueError("动作角色尚未入场或已退场")
                if typ == "enter" and p.get("preset") == "cut":
                    continue
                params = self.parameters[target]
                fields = dict(actor=params["actor"], duration_ms=dur, curve=action["curve"])
                if typ in ("enter", "exit") and p.get("preset") in ("slideL", "slideR"):
                    self.check_fields(p, ("preset",), "滑入滑出参数")
                    self.add("GuiActorSlide", dict(**fields, phase=typ,
                        direction="left" if p["preset"] == "slideL" else "right",
                        x=params["stage_x"], y=params["bottom_y"], height=params["height"]))
                    params["alpha"] = 255 if typ == "enter" else 0
                    if typ == "exit":
                        deferred_hide.append(target)
                    continue
                if typ == "enter":
                    fields.update(channels="alpha", alpha=255)
                elif typ == "exit":
                    self.check_fields(p, ("preset",), "退场参数")
                    if p.get("preset") == "cut" and dur == 0:
                        # Hide joins everything. It cannot replace a parallel
                        # cut while another same-beat motion is running.
                        if len([a for a in valid if a["type"] not in ("bgm", "se")]) != 1:
                            raise ValueError("直接退场和其他同拍动作尚未接通；请使用淡出或独立等待节拍")
                        self.add("Hide", dict(actor=params["actor"]))
                        self.present.remove(target)
                        continue
                    if p.get("preset") != "fade":
                        raise ValueError("原生预检只支持原地淡出/独立直接退场")
                    fields.update(channels="alpha", alpha=0)
                    deferred_hide.append(target)
                elif typ == "fade":
                    self.check_fields(p, ("alpha",), "透明度参数")
                    fields.update(channels="alpha", alpha=rounded(numeric(p.get("alpha"), 0, 255, "透明度")))
                elif typ == "expr":
                    self.check_fields(p, ("expr",), "表情参数")
                    face = self.resources.portraits[(params["archive"], params["body"])][2]
                    fields.update(channels="parts", expression=numeric(p.get("expr"), 0,
                        face["frame_count"]-1, "表情帧", integral=True))
                elif typ == "scale":
                    self.check_fields(p, ("sx", "sy"), "尺寸参数")
                    fields.update(channels="s2", scale_x=rounded(numeric(p.get("sx"), 50, 150, "横向尺寸")),
                                  scale_y=rounded(numeric(p.get("sy"), 50, 150, "纵向尺寸")))
                    params["transformed"] = True
                elif typ == "depth":
                    self.check_fields(p, ("z",), "景深参数")
                    fields.update(channels="z", depth=rounded(numeric(p.get("z"), 500, 2400, "景深")))
                    params.update(depth=fields["depth"], transformed=True)
                elif typ == "tilt":
                    self.check_fields(p, ("r",), "倾斜参数")
                    # Fixed target EXE: angle = R / 3600 * pi (20 units/degree).
                    fields.update(channels="r", rotation=rounded(numeric(p.get("r"), -50, 50, "倾斜角度") * 20))
                elif typ == "move":
                    self.check_fields(p, ("x", "y"), "平移参数")
                    x, y = numeric(p.get("x"), -640, 1920, "目标 X"), p.get("y")
                    if y is None:
                        y = params["bottom_y"]
                    y = numeric(y, -720, 1800, "目标 Y")
                    if params.get("transformed") or self.native_export_target:
                        self.add("GuiActorMove", dict(**fields, x=x, y=y))
                        params.update(stage_x=rounded(x), bottom_y=rounded(y))
                        continue
                    meta = self.resources.portraits[(params["archive"], params["body"])][1]
                    scale = checked_portrait_scale(params["height"], meta["height"], params["depth"])
                    project_x = lambda v: rounded((v-640)*1.5*(params["depth"]+200)/scale/2.4)
                    project_y = lambda v: rounded((v-360)*1.5*(params["depth"]+200)/scale/1.8)
                    fields.update(channels="xy", dx=project_x(x)-project_x(params["stage_x"]),
                                  dy=project_y(y)-project_y(params["bottom_y"]))
                    params.update(stage_x=rounded(x), bottom_y=rounded(y))
                else:
                    raise ValueError("对象/动作类型未支持")
                self.add("Action", fields)
                if typ in ("enter", "fade"):
                    params["alpha"] = fields["alpha"]
                elif typ == "expr":
                    params["expression"] = fields["expression"]
            except (ValueError, KeyError, TypeError) as exc:
                self.issue("error", "action_contract_rejected", str(exc), field="actions")
        self.location = dict(local)
        if kind == "line":
            self.line(beat["id"], beat.get("speaker"), beat.get("text"), beat.get("voice"))
        elif kind == "choice":
            # Resolve same-beat fade exits BEFORE the selection gate. They are
            # not a hidden cleanup after every alternative has already run.
            for target in deferred_hide:
                self.add("Hide", dict(actor=self.parameters[target]["actor"]))
                self.present.remove(target)
            deferred_hide.clear()
            self.choice(beat, action_ids)
        elif kind == "wait":
            self.add("Wait")
        else:
            self.add("Transition", dict(method=beat.get("method"), duration_ms=beat.get("dur")))
            method = beat.get("method")
            if method in ("black_out", "white_out"):
                self.covered = True
            elif method in ("reveal", "black_return", "white_return", "dissolve"):
                self.covered = False
        for target in deferred_hide:
            self.add("Hide", dict(actor=self.parameters[target]["actor"]))
            self.present.remove(target)

    def swap_actor(self, action):
        target, p = action["target"], action["p"]
        if target not in self.present or self.cg_state is not None:
            raise ValueError("请先让角色入场，再换身体。")
        self.check_fields(p, ("body", "policy"), "换身体参数")
        numeric(action["dur"], 0, 6000, "换装时长", integral=True)
        if p.get("policy") not in ("keep", "source"):
            raise ValueError("换身体需要选择保留大小或采用新来源大小。")
        body_id = ident(p.get("body"), "目标身体")
        previous = deepcopy(self.parameters[target])
        portrait = self.actor_parameters(target, body_id=body_id,
            expression=previous["expression"], source_size=True)
        fields = dict(portrait=portrait, policy=p["policy"])
        if action["dur"] > 0:
            fields["duration_ms"] = action["dur"]
        self.add("GuiActorSwap", fields)
        # Both modes keep the author's standing position. No face/head matching.
        portrait.update(stage_x=previous["stage_x"], bottom_y=previous["bottom_y"],
                        depth=previous["depth"], alpha=previous["alpha"], transformed=True)
        if p["policy"] == "keep":
            portrait["height"] = previous["height"]
        self.actor_bindings[target] = dict(body=body_id, height=portrait["height"])

    def audio_action(self, action):
        from .gui_audio_program import event_values as audio_values
        typ, p = action["type"], action["p"]
        if action["target"] != "audio":
            raise ValueError("声音动作的对象不正确。")
        self.check_fields(p, ("op", "asset", "volume", "loop"), "声音参数")
        fields = dict(op=p.get("op"), source=None, archive=None, resource=None, sha256=None,
                      volume=p.get("volume"), loop=p.get("loop"), duration_ms=action["dur"])
        if fields["op"] == "play":
            fields.update(self.audio_reference(p.get("asset"), typ))
            audio_values("GuiBGM" if typ == "bgm" else "GuiSE", fields)
        elif p.get("asset") is not None:
            raise ValueError("停止声音时不应指定素材。")
        self.add("GuiBGM" if typ == "bgm" else "GuiSE", fields)

    def audio_reference(self, asset_id, typ):
        from .gui_audio_bindings import direct_id
        from .gui_local_audio import SOURCE as LOCAL_SOURCE, LOCAL_ARCHIVES
        asset_id = ident(asset_id, "声音素材 ID")
        definition = object_only(object_only(self.project.get("audioAssets"), "声音素材表").get(asset_id), "声音素材")
        self.check_fields(definition, ("name", "kind", "source", "archive", "resource", "sha256", "size", "format", "mime", "local"), "声音素材")
        if definition.get("kind") != typ:
            raise ValueError("声音素材类型不匹配。")
        local = definition.get("source") == LOCAL_SOURCE
        if ("local" in definition and definition["local"] is not local
                or local and LOCAL_ARCHIVES.get(definition.get("archive")) != typ):
            raise ValueError("本地声音引用不正确，请重新导入。")
        fields = {k:definition.get(k) for k in ("source", "archive", "resource", "sha256")}
        allowed = {"bgm":{"bgm.bin","bgm2.bin","local-bgm"},
                   "se":{"se.bin","local-se"}, "voice":{"voice.bin","voice2.bin","local-voice"}}
        if fields["archive"] not in allowed[typ]:
            raise ValueError("声音档案与类型不匹配。")
        payload, info, ref = self.runtime.audio.asset(fields["source"], fields["archive"], fields["resource"], fields["sha256"])
        if any(definition.get(key) != info[key] for key in ("kind", "size", "format", "mime")):
            raise ValueError("这段声音的保存信息已变化，请重新选择。")
        native_id = direct_id(fields["source"], fields["archive"], fields["resource"])
        self.resources.audios[tuple(fields[k] for k in ("source","archive","resource","sha256"))] = dict(
            native_id=native_id, kind=typ, size=info["size"], format=info["format"],
            archive=fields["archive"], resource=fields["resource"], sha256=fields["sha256"])
        self.resources.references.append(ref)
        return fields

    def line(self, line_id, speaker, text, voice=None):
        if not isinstance(text, str) or not text.strip():
            raise ValueError("台词不能为空")
        if speaker == "narration" and voice is None:
            self.add("Text", dict(line_id=line_id, text=text))
            return
        characters = {c.get("id"):c for c in self.project["cast"]}
        if speaker == "narration":
            name = ""
        elif speaker in characters:
            name = characters[speaker].get("name")
        elif speaker == "you":
            name = "你"
        elif speaker == "unknown":
            name = "???"
        else:
            raise ValueError("台词说话人引用断开")
        if not isinstance(name, str) or speaker != "narration" and not name.strip():
            raise ValueError("说话人缺少显示名")
        source_id = ""
        if speaker in characters and not self.native_export_target:
            character = characters[speaker]
            native_speaker = character.get('nativeSpeaker')
            identity_name = name
            if native_speaker is not None:
                if (not isinstance(native_speaker, dict) or
                        native_speaker.get('schema') != 'fvp-gui-native-speaker/1' or
                        not isinstance(native_speaker.get('source'), str) or
                        not isinstance(native_speaker.get('name'), str) or
                        not native_speaker['name'].strip() or len(native_speaker['name']) > 128):
                    raise ValueError('原作人物选择信息不完整，请重新选择人物。')
                sources = {native_speaker['source']}
                identity_name = native_speaker['name']
            else:
                active = [a for a in self.scene.get("actors", []) if a.get("char") == speaker]
                bodies = character.get("bodies", [])
                selected = next((b for b in bodies if active and b.get("id") == active[0].get("body")), None)
                sources = {b.get("ext", {}).get("source") for b in ([selected] if selected else bodies)
                           if isinstance(b, dict) and isinstance(b.get("ext"), dict)} - {None}
            if len(sources) == 1:
                source_id = sources.pop()
                key = source_id, name
                if key in self.resources.speakers and self.resources.speakers[key].get('name') != identity_name:
                    raise ValueError('同名角色选中了不同的原作人物，请区分显示名后再生成。')
                if key not in self.resources.speakers:
                    from .gui_speaker_identity import resolve_identity
                    binding, references = resolve_identity(self.runtime._source(source_id), identity_name)
                    self.resources.speakers[key] = binding
                    self.resources.references.extend(references)
                binding = self.resources.speakers[key]
                if not binding.get("available"):
                    self.issue("warn", "speaker_identity_unresolved", "姓名会显示；来源角色的原生头像和配色还不能确定，保留原生未知角色样式", field="speaker")
                else:
                    if binding.get("source") != "hoshi" and binding.get("rgb") is None:
                        self.issue("warn", "speaker_colour_unresolved", "姓名和头像保留；来源角色默认文字配色尚不能确定，使用原生未知角色配色", field="speaker")
                    if not binding.get("avatar"):
                        self.issue("warn", "speaker_avatar_unresolved", "姓名会显示；来源角色没有可确定的原生回看头像", field="speaker")
            elif len(sources) > 1:
                self.issue("warn", "speaker_source_ambiguous", "角色有多个游戏的身体；先确定当前身体来源才能接入回看头像", field="speaker")
        if voice is not None:
            self.check_fields(voice, ("asset", "volume"), "台词语音")
            self.add("GuiVoiceLine", dict(line_id=line_id, text=text,
                speaker_mode="narration" if speaker == "narration" else "custom", display_name=name,
                volume=voice.get("volume"), speaker_source=source_id,
                **self.audio_reference(voice.get("asset"), "voice")))
            return
        self.add("Speech", dict(line_id=line_id, text=text, speaker_mode="custom",
            display_name=name, blog_mode="follow", source_game=source_id))

    def choice(self, beat, action_ids):
        """Lower every inline branch, never a browser preview pick or a timeout.

        Branch bodies are the GUI's existing speaker/text lines. Longer scene
        routes and nested choices need a separate chapter control-flow compile;
        target/beat/action fields here are rejected rather than ignored.
        """
        options = beat.get("options")
        if not isinstance(options, list) or not 2 <= len(options) <= 4:
            raise ValueError("场景内选项需要2～4项")
        if "merge" in beat or any(isinstance(o, dict) and ("beats" in o or "track_id" in o) for o in options):
            self.choice_tracks(beat, action_ids)
            return
        local, labels = dict(self.location), []
        for index, option in enumerate(options, 1):
            self.location = {**local, "option_index": index, "field": f"options[{index-1}]"}
            self.check_fields(option, ("label", "lines", "effects"), "场景内选项（长分支请通过场景出口连接）")
            label = option.get("label")
            if not isinstance(label, str) or not label.strip():
                raise ValueError("选项标题不能为空")
            labels.append(label)
            lines = option.get("lines")
            if not isinstance(lines, list) or len(lines) > 100:
                raise ValueError("分支台词须为0～100行的数组")
            for number, line in enumerate(lines, 1):
                self.location = {**local, "option_index": index, "branch_line_index": number,
                    "field": f"options[{index-1}].lines[{number-1}]"}
                self.check_fields(line, ("speaker", "text"), "分支台词")
        self.location = dict(local)
        if len({label.strip() for label in labels}) != len(labels):
            raise ValueError("选项标题不能相同")
        # Native choice IDs are bounded identifiers; GUI beat IDs can be longer.
        # The stable derived ID stays tied to the parent scene+beat, not its UI
        # list index. Existing beats and saved project data are not rewritten.
        choice_id = "C" + checksum([self.scene["id"], beat["id"]])[:24]
        fields = dict(choice_id=choice_id, prompt=beat.get("prompt"),
            **{f"option_{index}": label for index, label in enumerate(labels, 1)})
        choice_options(values("Choice", fields))
        self.add("Choice", fields)
        for index, option in enumerate(options, 1):
            self.location = {**local, "option_index": index, "field": f"options[{index-1}]"}
            self.add("ChoiceCase", dict(choice_id=choice_id, option_index=index))
            if "effects" in option:
                self.story_effects(option["effects"])
            for number, line in enumerate(option["lines"], 1):
                self.location = {**local, "option_index": index, "branch_line_index": number,
                    "field": f"options[{index-1}].lines[{number-1}]"}
                self.line(f"{choice_id}_o{index}_l{number}", line.get("speaker"), line.get("text"))
        self.location = dict(local)
        self.add("ChoiceEnd", dict(choice_id=choice_id))

    def track_state(self):
        return deepcopy(dict(parameters=self.parameters, present=self.present, actor_bindings=self.actor_bindings,
            cg_state=self.cg_state, camera_changed=self.camera_changed,
            camera_state=self.camera_state, covered=self.covered,
            background_state=self.background_state, background_asset_id=self.background_asset_id,
            background_blur_state=self.background_blur_state))

    def story_effects(self, items):
        from .gui_story_logic import effects
        if self.story_variables is None and items != []:
            raise ValueError("这里设置了剧情变量，请用整章输出保留选项和后续路线。")
        for item in effects(items, self.story_variables or {}):
            self.add("GuiStoryEffect", item)

    def restore_track_state(self, state):
        for name, value in state.items():
            setattr(self, name, deepcopy(value))

    @staticmethod
    def merge_state(state):
        # Parameters for cleared actors are only a translation cache, not a
        # visible/future state. A later explicit enter verifies them afresh.
        result = deepcopy(state)
        result["parameters"] = {key: result["parameters"][key] for key in result["present"]}
        # An asset alias does not affect the native BG pixels/blur or motion.
        result.pop("background_asset_id", None)
        return result

    def choice_tracks(self, beat, action_ids):
        """Each option owns complete beats; only explicit common/end exits."""
        local, labels = dict(self.location), []
        merge = beat.get("merge")
        self.location = {**local, "field": "merge"}
        self.check_fields(merge, ("type", "target"), "分支出口")
        if merge.get("type") == "beat":
            if set(merge) != {"type", "target"} or ident(merge["target"], "汇合节拍 ID") != self.next_beat_id:
                raise ValueError("本轮汇合须明确连到选项之后的下一公共节拍；不会跳过其他节拍")
            completion, target = "merge", merge["target"]
        elif merge.get("type") == "end":
            if set(merge) != {"type"} or not self.last_root_beat:
                raise ValueError("结束场景的分支之后不能再放公共节拍")
            completion, target = "end", None
        else:
            raise ValueError("分支须明确接回公共节拍，或分别结束当前场景")
        for index, option in enumerate(beat["options"], 1):
            self.location = {**local, "option_index": index, "field": f"options[{index-1}]"}
            self.check_fields(option, ("label", "track_id", "beats", "effects"), "分支轨道")
            track = ident(option.get("track_id"), "分支轨道 ID")
            self.location["track_id"] = track
            if track in self.track_ids:
                raise ValueError("分支轨道 ID 重复")
            self.track_ids.add(track)
            label = option.get("label")
            if not isinstance(label, str) or not label.strip():
                raise ValueError("选项标题不能为空")
            labels.append(label)
            if not isinstance(option.get("beats"), list) or len(option["beats"]) > 100:
                raise ValueError("每条分支须为0～100个完整节拍的数组")
        self.location = dict(local)
        if len({label.strip() for label in labels}) != len(labels):
            raise ValueError("选项标题不能相同")
        choice_id = "C" + checksum([self.scene["id"], beat["id"]])[:24]
        self.add("GuiChoice", dict(choice_id=choice_id, prompt=beat.get("prompt"),
            completion=completion, merge_beat_id=target,
            **{f"option_{index}": label for index, label in enumerate(labels, 1)}))
        baseline, joined = self.track_state(), None
        for index, option in enumerate(beat["options"], 1):
            self.restore_track_state(baseline)
            branch_location = {**local, "choice_beat_id": beat["id"],
                "option_index": index, "track_id": option["track_id"],
                "field": f"options[{index-1}]"}
            self.location = dict(branch_location)
            self.add("GuiChoiceCase", dict(choice_id=choice_id, option_index=index,
                track_id=option["track_id"]))
            if "effects" in option:
                self.story_effects(option["effects"])
            for number, branch_beat in enumerate(option["beats"], 1):
                self.translate_beat(branch_beat, action_ids, {**branch_location,
                    "branch_beat_index": number, "field": f"options[{index-1}].beats[{number-1}]"})
            state = self.track_state()
            self.location = dict(branch_location)
            if completion == "merge" and joined is not None and self.merge_state(state) != self.merge_state(joined):
                self.issue("error", "branch_merge_conflict", "这条轨道结束时的立绘、CG、背景或镜头与前一条不同；请明确恢复一致状态再接公共节拍，或分别结束场景。不会自动对齐或缩放角色。", field="merge")
            if joined is None:
                joined = state
        self.restore_track_state(joined if completion == "merge" else baseline)
        self.location = dict(local)
        self.add("GuiChoiceEnd", dict(choice_id=choice_id))

    def cg_binding(self, asset_id):
        ident(asset_id, "CG 素材 ID")
        if asset_id in self.cg_bindings:
            return self.cg_bindings[asset_id]
        definition = object_only(self.project.get("externalGraphics", {}), "CG 登记").get(asset_id)
        if not isinstance(definition, dict) or definition.get("category") != "cg":
            raise ValueError("CG 不是已登记原作完整事件图，内置示意图不能参加原生预检")
        self.check_fields(definition, ("source","category","archive","resource","frame","frame_count",
            "width","height","sha256","entry_index","category_basis","fit"), "CG 登记")
        if definition.get("fit") != "contain" or type(definition.get("frame")) is not int or definition["frame"] != 0:
            raise ValueError("CG 原生预检仅支持完整单帧 contain，不裁切或猜测多帧")
        source = self.runtime._source(definition.get("source"))
        descriptor = self.runtime.graphics.descriptor(source)
        if definition.get("archive") not in descriptor["graphics_archives"]["cg"]:
            raise ValueError("CG 档案不在来源允许列表")
        path = (source.root / definition["archive"]).resolve(strict=True)
        if path.parent != source.root:
            raise ValueError("CG 档案不在已登记来源目录")
        stamp = fingerprint(path)
        fresh = self.runtime.graphics.graphic(definition.get("source"), "cg", definition["archive"], definition.get("resource"))
        image, identity = fresh["image"], fresh["identity"]
        if (definition.get("sha256") != identity["payload_sha256"]
                or type(definition.get("entry_index")) is not int
                or definition["entry_index"] != identity["entry_index"]
                or definition.get("category_basis") != fresh.get("category_basis")
                or any(type(definition.get(k)) is not int or definition[k] != image[k] for k in ("width","height","frame_count"))):
            raise ValueError("CG 分类/画布/指纹与本机来源不一致，请重新登记")
        if image["frame_count"] != 1:
            raise ValueError("CG 原生预检不支持多帧资源")
        # Read the bounded entry metadata as well: pivot uses native offsets,
        # never guessed from dimensions or from a user's edited GUI definition.
        _source, entry_path, entry_stamp, index, payload, metadata = self.runtime.graphics._entry(
            definition["source"], "cg", definition["archive"], definition["resource"])
        if (entry_path.resolve() != path or entry_stamp != stamp or index != identity["entry_index"]
                or hashlib.sha256(payload).hexdigest() != identity["payload_sha256"]
                or fingerprint(path) != stamp):
            raise GuiRuntimeError("source_changed", "读取 CG 证据时来源发生变化", 409)
        cg_scale(metadata["width"], metadata["height"])
        fields = dict(source_game=source.name, archive=str(path), resource=definition["resource"], fit="contain")
        self.resources.cgs[(str(path), definition["resource"])] = dict(
            name="CG_PREFLIGHT_" + definition["sha256"].upper(), metadata=deepcopy(metadata))
        self.resources.references.append((path, stamp))
        self.cg_bindings[asset_id] = fields
        return fields

    def cg_beat(self, valid, cg_actions, kind, local):
        """CG loads/geometry are independent beats; never serialize a compound.

        Exception: wait-only exit+zero-time BG, loaded while still covered. GUI
        array order does not choose which event owns cleanup or the final BG.
        """
        handled = {a["id"] for a in cg_actions}
        background_actions = [a for a in valid if a["type"] == "bg"]
        exits = [a for a in cg_actions if a["type"] == "cgexit"]
        exit_background = len(exits) == 1 and len(cg_actions) == 1 and len(background_actions) == 1 and len(valid) == 2
        if exit_background:
            handled.add(background_actions[0]["id"])
        if len(cg_actions) != 1 or len(valid) != (2 if exit_background else 1):
            for action in cg_actions:
                self.location = {**local, "action_id": action["id"]}
                self.issue("error", "unsupported_parallel_cg", "CG 加载/构图与其他同拍动作的原生时序未接通；不会依数组顺序串行化", field="actions")
            self.location = dict(local)
            return handled
        action = cg_actions[0]
        self.location = {**local, "action_id": action["id"]}
        try:
            typ, p, dur = action["type"], action["p"], action["dur"]
            if typ == "cg" and action["target"] == "stage":
                self.check_fields(p, ("cg",), "CG 入场参数")
                if self.present:
                    raise ValueError("CG 入场前须先退场并清除普通立绘")
                if self.covered:
                    raise ValueError("CG 入场时整幕仍被黑/白遮盖；请先明确 reveal，不会自动揭开遮盖")
                if self.cg_state is None and self.camera_changed:
                    raise ValueError("首次 CG 入场前须恢复基准镜头；重定基尚未接通")
                fields = self.cg_binding(p.get("cg"))
                state = self.cg_state or dict(x=0,y=0,s=100)
                binding = self.resources.cgs[(fields["archive"], fields["resource"])]
                cg_scale(binding["metadata"]["width"], binding["metadata"]["height"], state["s"])
                self.add("GuiCGLoad", {**fields, "duration_ms": dur})
                self.cg_state = {**state, "asset": p["cg"]}
                self.background_state = None
                self.background_asset_id, self.background_blur_state = None, None
            elif typ == "cgxf" and action["target"] == "cgview":
                self.check_fields(p, ("x","y","s"), "CG 构图参数")
                if self.cg_state is None:
                    raise ValueError("没有正在显示的 CG，不能调整局部构图")
                fields = cg_event_values("GuiCGTransform", {**p,"duration_ms":dur,"curve":action["curve"]})
                state = self.cg_state
                if p["s"] != state["s"] and any(v != 0 for v in (state["x"],state["y"],p["x"],p["y"])):
                    raise ValueError("非零位移上的 CG 缩放尚需原点补偿；请独立回到原点再缩放，不会自动修改工作流")
                binding_fields = self.cg_bindings[state["asset"]]
                metadata = self.resources.cgs[(binding_fields["archive"], binding_fields["resource"])]["metadata"]
                cg_scale(metadata["width"], metadata["height"], p["s"])
                self.add("GuiCGTransform", fields)
                self.cg_state = {**state, **p}
            elif typ == "cgexit" and action["target"] == "stage":
                self.check_fields(p, ("color",), "CG 退场参数")
                if kind != "wait" or self.cg_state is None:
                    raise ValueError("CG 退场本轮须为独立等待节拍，并且已有 CG；台词同拍尚未接通")
                if self.camera_changed:
                    raise ValueError("CG 退场前须明确恢复基准镜头，不能把原生清理的镜头复位隐藏在退场里")
                self.add("GuiCGExit", dict(colour=p.get("color"), duration_ms=dur))
                self.cg_state, self.camera_changed = None, False
                self.camera_state, self.background_state = (640, 360, 100), None
                self.background_asset_id, self.background_blur_state = None, None
                self.covered = True
                if exit_background:
                    bg = background_actions[0]
                    self.location = {**local, "action_id": bg["id"]}
                    self.check_fields(bg["p"], ("bg",), "遮盖后背景参数")
                    if bg["target"] != "stage" or bg["dur"] != 0:
                        raise ValueError("CG 退场同拍的背景只支持零时长加载，渐变背景尚未接通")
                    self.background(bg["p"].get("bg"))
                    self.issue("info", "cg_exit_background_covered", "CG 退场完成后在黑/白场遮盖内加载背景；最终状态不依赖动作数组顺序，需后续 reveal 恢复显示", field="actions")
            else:
                raise ValueError("CG 对象与动作类型不匹配")
            self.issue("info", "cg_static_scope", "CG 仅做已审核目标 ABI 的内存预检；二维舞台不等于 V3D 中途轨道/实机显示验收", field="actions")
        except (ValueError, KeyError, TypeError, GuiRuntimeError) as exc:
            self.issue("error", "cg_contract_rejected", str(exc), field="actions")
        self.location = dict(local)
        return handled


def native_emit(program, resources):
    """Actual audited ABI/emitter invocation; output bytes remain in memory."""
    root = Path(program["source_root"]).resolve(strict=True)
    names = (".Hoshimemo_HD.hcb", "Hoshimemo_HD.hcb", "Hoshimemo_HD.exe")
    paths = [(root/name).resolve(strict=True) for name in names]
    if any(path.parent != root for path in paths):
        raise GuiRuntimeError("target_changed", "目标母本文件已指向登记目录之外", 409)
    stamps = [fingerprint(path) for path in paths]
    if any(path.stat().st_size > 32 * 1024 * 1024 for path in paths):
        raise ValueError("目标 HCB/EXE 超过已审核大小边界")
    source, clean, exe = [path.read_bytes() for path in paths]
    if [hashlib.sha256(b).hexdigest() for b in (source, clean, exe)] != [SOURCE_SHA, CLEAN_SHA, EXE_SHA]:
        raise ValueError("目标不是已审核的星空 HD 原始母本；不在已安装候选上叠加")
    if source[ENTRY:ENTRY+5] != ENTRY_BYTES:
        raise ValueError("登记入口指纹不匹配")
    from .gui_audio_program import KINDS as AUDIO_KINDS, GuiAudioEmitter
    emitter = (GuiAudioEmitter(source, clean) if any(e["kind"] in AUDIO_KINDS for e in program["events"])
               else GuiCgEmitter(source, clean))
    payload = emitter.compile(program, resources)
    prefix = bytearray(payload[:len(source)])
    prefix[ENTRY:ENTRY+5] = ENTRY_BYTES
    emitter.native_speakers.validate_patches(payload, prefix)
    if prefix != source:
        raise ValueError("内存编译修改了登记入口之外的原始 HCB")
    appended = payload[len(source):]
    table_at = struct.unpack_from("<I", clean)[0]
    synthetic = struct.pack("<I", 4+len(appended)) + appended + clean[table_at:]
    decoded = parse_bytes(synthetic, encoding="gbk")
    if decoded.warnings:
        raise ValueError("新增原生字节码解码失败")
    boundaries = {len(source)+ins.offset-4 for ins in decoded.instructions} | set(emitter.by_offset)
    if any(ins.opcode in (2, 6, 7) and ins.operands["target"] not in boundaries for ins in decoded.instructions):
        raise ValueError("新增原生调用/跳转未落在指令边界")
    resources.check_unchanged()
    if any(fingerprint(path) != stamp for path, stamp in zip(paths, stamps)):
        raise GuiRuntimeError("target_changed", "预检期间目标母本发生变化", 409)
    proof = dict(checked=True, instruction_count=len(decoded.instructions),
        appended_bytes=len(appended), payload_sha256=hashlib.sha256(payload).hexdigest(),
        original_prefix_unchanged_outside_entry=not emitter.native_speakers.patches, instruction_boundaries_checked=True,
        resource_pack_built=False, runtime_verified=False, virtual_resource_bindings=True,
        plan_sha256=digest(program), source_hcb_sha256=SOURCE_SHA,
        clean_hcb_sha256=CLEAN_SHA, target_exe_sha256=EXE_SHA)
    proof["native_motion_contract"] = emitter.stage_motion.report()
    proof["native_stage_helpers"] = emitter.stage_helpers.report()
    proof["speaker_identity_contract"] = emitter.native_speakers.report()
    if any(e["kind"] == "GuiActorSwap" and e.get("duration_ms", 0) > 0
           for e in program["events"]):
        proof["actor_swap_blend_contract"] = emitter.actor_swap_blend.report()
    if any(event["kind"] in BG_KINDS for event in program["events"]):
        proof["background_change_contract"] = background_report(emitter)
    if any(event["kind"] in BLUR_KINDS for event in program["events"]):
        proof["background_blur_contract"] = blur_report(emitter)
    if any(event["kind"] in CG_KINDS for event in program["events"]):
        proof["cg_contract"] = CG_CONTRACT
        proof["cg_states"] = [dict(event_index=i, kind=event["kind"],
            cg=event["cg_after"], camera=event["camera_after"], covered=event["covered_after"])
            for i,event in enumerate(emitter.events) if event["kind"] in CG_KINDS | {"CameraShot"}]
        proof["cg_adapters"] = [value for key,value in emitter.helpers.items()
            if isinstance(key,tuple) and key[0] == "gui_cg_loader"]
    if program["schema"] == TRACK_PROGRAM_SCHEMA:
        proof["choice_contract"] = TRACK_CONTRACT
    if any(event["kind"] in AUDIO_KINDS for event in program["events"]):
        proof["audio_contract"] = "fvp-gui-audio/1"
        proof["audio_bindings"] = resources.audio_binding_plan().report()
        proof["audio_adapters"] = [v for k,v in emitter.helpers.items()
                                   if isinstance(k,tuple) and k[0] in ("gui_bgm_asset_loader", "gui_voice_asset_loader")]
        proof["audio_calls"] = [call for event in emitter.events for call in event["calls"]
                                if call["function"].startswith(("gui_bgm_", "gui_se_", "gui_voice_"))]
        if any(event["kind"] == "GuiVoiceLine" for event in program["events"]):
            proof["voice_contract"] = "fvp-gui-voice-line/1"
            proof["voice_wait"] = dict(native=True, target=emitter.call_table["text_wait"][0],
                                       click=True, auto_mode_preserved=True, runtime_verified=False)
    return proof
