"""Whole source-form binding, distinct from legacy partial-pivot PortraitNative.

Sakura/Snow M=0 uses resource suffix L, RS600, Z(input)-400. L=1 uses
the unsuffixed resource, RS1000, Z(input). Mixing those halves caused V16's
low Kuro and floating Corona. Viewports come from fingerprinted source EXE
mode tables and the source HCB mode byte, not from oversized BG resources.
Existing Hoshimemo/Iroseka references deliberately retain accepted V16 framing;
they are NOT advertised as a new proof of original M form.
"""
import hashlib
import struct

from .performance_geometry import nearest
from .performance_native_layout import resolve_native_layout

# The three inspected FVP EXEs read mode 0..15 directly from the HCB header
# and index the same 16-bit (width, height) table at file offset 0x5C550.
# Source code at Sakura.exe 0x439016 uses [eax*4+0x45DB50] and +2.
_MODE_TABLE_OFFSET = 0x5C550
_TARGET_VIEWPORT = (1920, 1080)

FORMS = {
    'Sakura.hcb': dict(viewport=(1280, 720), mode=8, executable='Sakura.exe',
        executable_sha='c046246f00c35e1f9685c0eca8d89a1b98ead53a26af7e61f3a6b2f9452f2645',
        bg_size=(1600, 900),
        bg_sha='c32b6e215f18f534783ef306033def36207a75a1cc12d9c5304f5a459b551448',
        M=dict(suffix='L', pivot=(1100,775), y=0, scale=600, depth=800, op_call=0x5EB45,
               body_sha='e9e69eda8432364d7d1a535611daab8dbf5274c9730ae80442818bbf09e9a748'),
        L=dict(suffix='', pivot=(1100,800), y=0, scale=1000, depth=1200, op_call=0x5EEB2,
               body_sha='2fc504c37f6e924a88133f2ec6c4f4278e614d000e96608683965b9df024c7d3')),
    'Snow.hcb': dict(viewport=(1024, 640), mode=7, executable='WhiteEternity.exe',
        executable_sha='c61787811eb1924cbfb2c6594601dd47df18ea10feade5b5ec148ceca402c892',
        bg_size=(1280, 720),
        bg_sha='a912f37fa10588c14f8372ba36d255c113445f5562be3699080b16fe6337f6c3',
        M=dict(suffix='L', pivot=(800,1008), y=145, scale=600, depth=800, op_call=0x731DA,
               body_sha={'CHR_コロナ_基_制服': '42d3eaeda41a62c75a2d44976acc2c7ae966881ae2cefc5528d986394466a7d8',
                         'CHR_葉月_基_制服': 'a22cee6745301922feeb4a8b89d2bc358935f0dcafdefd6a0736139ab98d38e4'}),
        L=dict(suffix='', pivot=(800,930), y=335, scale=1000, depth=1200, op_call=0x7358A,
               pivot_by_body={'CHR_葉月_基_制服': (800,920)},
               body_sha={'CHR_コロナ_基_制服': '28b20798b2a1d7cc2d917b138c59073ba7ed944adde7b78b561153f237df10b4',
                         'CHR_葉月_基_制服': '797a927e6876fcd5b761a66233396f627b3bba3e1e01f5e5945a798b0e5bde1a'})),
}


def native_display_scale(source_scale, source_z, source_camera_z,
                         source_viewport_height, target_z, target_camera_z,
                         target_viewport_height=1080):
    """Preserve projected body-height / viewport-height for identical HZC bytes.

    No face/body bounding-box normalization is involved. The caller must
    supply an evidenced source camera at the selected scene/frame; a game-wide
    camera guess is not an original-size claim.
    """
    if (source_z <= source_camera_z or target_z <= target_camera_z
            or min(source_viewport_height, target_viewport_height, source_scale) <= 0):
        raise ValueError('原作/目标投影距离或画幅无效')
    return nearest(source_scale * target_viewport_height / source_viewport_height
                   * (target_z - target_camera_z) / (source_z - source_camera_z))


def _audited_viewport(root, source):
    """Fail closed when the executable's mode table or HCB mode has drifted."""
    hcb = (root / source['file']).read_bytes()
    descriptor = struct.unpack_from('<I', hcb, 0)[0]
    if descriptor + 9 > len(hcb) or hcb[descriptor + 8] != source['mode']:
        raise ValueError('来源HCB画面模式漂移，拒绝沿用旧比例')
    executable = (root / source['executable']).read_bytes()
    if hashlib.sha256(executable).hexdigest() != source['executable_sha']:
        raise ValueError('来源EXE指纹漂移，拒绝沿用旧画幅')
    viewport = struct.unpack_from('<HH', executable,
                                  _MODE_TABLE_OFFSET + 4 * source['mode'])
    if viewport != source['viewport']:
        raise ValueError('来源EXE分辨率表漂移，拒绝沿用旧画幅')
    return viewport


def resolve_framing(event):
    from pathlib import Path
    from .performance_compile import resource_reference
    base = resolve_native_layout(event)
    source = FORMS.get(base['file'])
    choice = event['framing']
    if choice == 'auto':
        choice = 'M' if source else 'reference'
    if choice == 'reference':
        # Explicit reference policy; never use cropped height normalization.
        form = dict(suffix='', pivot=base['pivot'], y=base.get('baseline_y',340),
                    scale=1000, depth=1200)
        ratio, viewport = 1., _TARGET_VIEWPORT
        label = 'V16参考构图（非完整原作景别）'
    else:
        if source is None or choice not in ('M','L'):
            raise ValueError('此来源尚未审核该景别，请选 auto/reference 或普通立绘明确构图')
        form = source[choice]
        root = Path(event['archive']).parent
        _, bg = resource_reference(root/'graph_bg.bin', 'BG001_000')
        if (bg['payload_sha256'] != source['bg_sha']
                or (bg['width'], bg['height']) != source['bg_size']):
            raise ValueError('来源BG素材指纹漂移，拒绝沿用旧档案')
        viewport = _audited_viewport(root, {'file': base['file'], **source})
        ratio = _TARGET_VIEWPORT[1] / viewport[1]
        label = f'来源{choice}档参数；按原生画面模式换算画幅（镜头仍待场景核对）'
    actual_body = event['body'] + form['suffix']
    pivot = form.get('pivot_by_body', {}).get(event['body'], form['pivot'])
    body_sha = form.get('body_sha')
    if isinstance(body_sha, dict):
        body_sha = body_sha[event['body']]
    scale = nearest(form['scale'] * ratio * event['size_percent'] / 100)
    depth = form['depth']
    d = depth + 200
    # stage_x is the projected source OP anchor, NOT the cropped-bitmap centre.
    x = nearest((event['stage_x']-640) * 1.5*d/scale/2.4)
    y = nearest((form['y']*base['xy'][1] + event['offset_y']*1.5*d/scale)/1.8)
    return {**base, 'body': actual_body, 'requested_body': event['body'],
            'pivot': list(pivot), 'scale': scale, 'depth': depth, 'x': x, 'y': y,
            'source_scale': form['scale'], 'source_depth': depth, 'source_y': form['y'],
            'op_call': form.get('op_call',base['op_call']), 'baseline_y': form['y'],
            'source_viewport': list(viewport), 'viewport_ratio': ratio,
            'source_camera_verified': False, 'native_size_verified': False,
            'form': choice, 'label': label, 'body_sha': body_sha,
            'evidence': ('source form=0 appends L, RS600, Z(input)-400; form=1 unsuffixed, RS1000, Z(input). '
                         'Viewport uses fingerprinted source EXE mode table + HCB game mode; '
                         'BG hash only binds resource identity. Source scene camera is still unknown, '
                         'so this is not a proven same-size original-frame conversion.'
                         if choice in ('M','L') else 'V16 reference geometry preserved; not a new native-form proof'),
            'geometry_mode': 'source-form-bundle/2', 'runtime_verified': False}
