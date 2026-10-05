"""Serialization and native RS limits for the sealed Hoshimemo target ABI.

Height is an authoring value, not a primitive storage field. Do not impose a
guessed visual-height cap. At each resource's actual body height/depth, check
the emitted scale against the verified target setter instead of shrinking it.
The actual EXE proof is checked by tests/test_native_primitive_scale.py.
"""
from .performance_geometry import nearest

HEIGHT_MIN = 1
HEIGHT_MAX = 0x7fffffff  # positive signed-32 HCB integer, not a visual-size guess
NATIVE_RS_MIN = 100
NATIVE_RS_MAX = 10000
TARGET_EXE_SHA256 = "d195c8916ba32089347b79e0ee24c505a6cd2cd230c6f3b1d97584c9fa9f8b0c"


def checked_portrait_scale(height, body_height, depth):
    if type(height) is not int or not HEIGHT_MIN <= height <= HEIGHT_MAX or body_height <= 0:
        raise ValueError("立绘显示高度或身体位图高度无效")
    scale = nearest(height * 1.5 * (depth + 200) / body_height)
    check_native_portrait_scales(scale)
    return scale


def check_native_portrait_scales(*scales):
    if any(not NATIVE_RS_MIN <= value <= NATIVE_RS_MAX for value in scales):
        raise ValueError("立绘大小换算超出目标原生 RS 100..10000；拒绝游戏钳位后与预览不一致，"
                         "不会自动截断或缩小，请调整创作大小/深度")
