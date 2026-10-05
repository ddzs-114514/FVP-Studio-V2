"""Legacy partial-pivot compatibility, NOT a complete native M-form binding.

Foreign XY is converted from each source's proven wrapper (or direct syscall)
into Hoshimemo's 2.4/1.8 wrapper. This retains source-canvas geometry, not identical
framing between games with different render resolutions and scene cameras.
"""
import hashlib
from pathlib import Path

PROFILES = (
    dict(file=".Hoshimemo_HD.hcb", sha256="224ecf63f635d3229de0022ce880932fd034f20cb7985960ee68a9a38d7edc5c",
         bodies=("CHR_明日歩_基_夏制服", "CHR_明日歩_喜_夏制服", "CHR_こもも_基_夏制服"),
         body_sha={"CHR_明日歩_基_夏制服": "321c859ff9bfdc863825a2a427a638ad571503167ec9d467b6cda32216274caa",
                   "CHR_明日歩_喜_夏制服": "661cac754d6980b086c177a7f84f9b1ca57259b8133da59b46edbc9cd632e11c",
                   "CHR_こもも_基_夏制服": "ff18878a47ed798d1b1772133aa1a3e3f8c0fac05ae17f512aacba074776ab9d"},
         pivot=(1920, 1755), xy=(2.4, 1.8), dispatcher=0x5BA7A, op_call=0x60D5C),
    dict(file=".iroseka.hcb", sha256="baf7bee965c1bf88a2a4f1a595fa9b66300049a37a1c17835809d1f853869de5",
         bodies=("CHR_真紅_基_夏制服",), pivot=(1500, 1603), xy=(1.875, 1.6875),
         body_sha={"CHR_真紅_基_夏制服": "e22c16a304b06f740b573ceaff863275aab874f499f919a1688d485c6a3a23a3"},
         dispatcher=0x474AD, op_call=304285),
    dict(file=".irohika.hcb", sha256="feb0793d045597c327db61a6bbf15b1315efb68b13f2ddbd405dbac264bff054",
         bodies=("CHR_加奈_基_夏制服",), pivot=(1500, 1603), xy=(1.875, 1.6875),
         body_sha={"CHR_加奈_基_夏制服": "d71f7344bfc9f807637d2a753b04b2e3fb763f7d6f8e698b36035d8c4f1faa69"},
         dispatcher=0x51A17, op_call=352853),
    dict(file="Sakura.hcb", sha256="946877dd0ed8fbf318ba5c73d20afd46b9dcdc200aa7e8edc610c437cc1c789b",
         bodies=("CHR_クロ_喜_制服",), pivot=(1100, 775), xy=(1.0, 1.0),
         body_sha={"CHR_クロ_喜_制服": "2fc504c37f6e924a88133f2ec6c4f4278e614d000e96608683965b9df024c7d3"},
         dispatcher=0x58B8C, op_call=0x5EB45, selector=1, baseline_y=0,
         evidence="legacy M pivot only; RS1000 was a V16 reference, not the native M RS600"),
    dict(file="Snow.hcb", sha256="433cf4aa2979e95c6eb43e1cf107cf3ef5acb2fd4b178c1c6b51d81ea9ec557b",
         bodies=("CHR_コロナ_基_制服",), pivot=(800, 1008), xy=(1.0, 1.0),
         body_sha={"CHR_コロナ_基_制服": "28b20798b2a1d7cc2d917b138c59073ba7ed944adde7b78b561153f237df10b4"},
         dispatcher=0x6D913, op_call=0x731DA, selector=5, baseline_y=145,
         evidence="legacy M pivot only; RS1000 was a V16 reference, not the native M RS600"),
    dict(file="Snow.hcb", sha256="433cf4aa2979e95c6eb43e1cf107cf3ef5acb2fd4b178c1c6b51d81ea9ec557b",
         bodies=("CHR_葉月_基_制服",), pivot=(800, 1008), xy=(1.0, 1.0),
         body_sha={"CHR_葉月_基_制服": "797a927e6876fcd5b761a66233396f627b3bba3e1e01f5e5945a798b0e5bde1a"},
         dispatcher=0x6D913, op_call=0x731DA, selector=9, baseline_y=145,
         evidence="Snow selector 9 reaches the shared form=0 OP/XY/RS/Z path; scene camera and overrides remain unverified"),
)


def resolve_native_layout(event):
    root = Path(event["archive"]).resolve(strict=True).parent
    for profile in PROFILES:
        path = root / profile["file"]
        if event["body"] not in profile["bodies"] or not path.is_file():
            continue
        if hashlib.sha256(path.read_bytes()).hexdigest() != profile["sha256"]:
            raise ValueError("来源原生M景别的HCB指纹漂移，不能猜测原点")
        # The same resource name can exist in several games, or be replaced
        # independently of an unchanged HCB. The pivot evidence binds both.
        from .performance_compile import resource_reference
        _, body = resource_reference(event["archive"], event["body"])
        if body["payload_sha256"] != profile["body_sha"][event["body"]]:
            raise ValueError("来源立绘身体指纹漂移，不能沿用原生原点")
        return {**profile, "source_hcb": str(path), "scale": 1000,
                "geometry_mode": "source-native-M", "runtime_verified": False}
    raise ValueError("该素材尚无审核过的来源M景别；请用普通立绘节点明确指定构图")
