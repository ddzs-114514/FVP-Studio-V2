"""Reviewed production profile for the Chinese Hoshimemo HD portrait ABI.

The values in this module identify one exact hidden ``.Hoshimemo_HD.hcb`` /
``graph_bs.bin`` pair.  They are a declarative audit profile only: the factory
does not read, write, or install a game file.  Every private portrait slot is
an independent clone of the original ``function_4477_`` region, so no address
from an older appended HCB is used as a source or overwritten in place.
"""

from __future__ import annotations

from .hoshimemo_portrait_backend import (
    BinaryFingerprint,
    CodeRegionFingerprint,
    HOSHIMEMO_NATIVE_PORTRAIT_PROFILE_ID,
    HoshimemoPortraitSlot,
    HoshimemoTargetProfile,
    LiteralPatchTemplate,
    PrivateDispatcherRecipe,
)
from .portrait_compile import HoshimemoPortraitBackendProfile


HOSHIMEMO_NATIVE_PORTRAIT_HCB_SIZE = 4_787_586
HOSHIMEMO_NATIVE_PORTRAIT_HCB_FILENAME = ".Hoshimemo_HD.hcb"
HOSHIMEMO_NATIVE_PORTRAIT_HCB_SHA256 = (
    "224ecf63f635d3229de0022ce880932fd034f20cb7985960ee68a9a38d7edc5c"
)
HOSHIMEMO_NATIVE_PORTRAIT_GRAPH_BS_SIZE = 649_869_829
HOSHIMEMO_NATIVE_PORTRAIT_GRAPH_BS_FILENAME = "graph_bs.bin"
HOSHIMEMO_NATIVE_PORTRAIT_GRAPH_BS_SHA256 = (
    "a9f0cae100c445ccfec7fcc2dba0dbd2a485a06ac1a84ba8832c5b458eee9c10"
)

HOSHIMEMO_NATIVE_PORTRAIT_FUNCTION_4477_START = 0x5BA7A
HOSHIMEMO_NATIVE_PORTRAIT_FUNCTION_4477_END = 0x61954
HOSHIMEMO_NATIVE_PORTRAIT_FUNCTION_4477_SHA256 = (
    "f8008113cecea6dad145aba453b2dd6171adda5b9c892c633fb105976b5e3b76"
)
HOSHIMEMO_NATIVE_PORTRAIT_FUNCTION_4286_START = 0x4B0A3
HOSHIMEMO_NATIVE_PORTRAIT_FUNCTION_4286_END = 0x4B0E4
HOSHIMEMO_NATIVE_PORTRAIT_FUNCTION_4286_SHA256 = (
    "73fd803dacdfcca07c172fa6452b95e01da591e4f6493db2709ac3e89b01ca46"
)

HOSHIMEMO_NATIVE_PORTRAIT_RESOURCE_VALUE_KEYS = (
    "resource_base",
    "outfit_suffix",
)

HOSHIMEMO_NATIVE_PORTRAIT_SYMBOLS = {
    "function_4286_": HOSHIMEMO_NATIVE_PORTRAIT_FUNCTION_4286_START,
    "function_4405_": 0x54343,
    "function_4406_": 0x543F0,
    "function_4407_": 0x5447C,
    "function_4408_": 0x544F8,
    "function_4409_": 0x54578,
    "function_4477_": HOSHIMEMO_NATIVE_PORTRAIT_FUNCTION_4477_START,
    "function_4480_": 0x61E37,
    "function_4487_": 0x6761B,
}


def _native_clone_recipe(
    *,
    selector: int,
    resource_base_offset: int,
    resource_base_expected: str,
    outfit_suffix_offset: int,
    outfit_suffix_expected: str,
) -> PrivateDispatcherRecipe:
    slot_token = f"selector{selector}"
    return PrivateDispatcherRecipe(
        recipe_id=f"hoshimemo-native-portrait-{slot_token}",
        output_symbol=f"hoshimemo-native-function-4477-{slot_token}",
        source_symbol="function_4477_",
        carrier_selector=selector,
        literal_patches=(
            LiteralPatchTemplate(
                resource_base_offset,
                resource_base_expected,
                "resource_base",
            ),
            LiteralPatchTemplate(
                outfit_suffix_offset,
                outfit_suffix_expected,
                "outfit_suffix",
            ),
        ),
    )


def build_hoshimemo_native_portrait_profile() -> HoshimemoTargetProfile:
    """Return the immutable reviewed target profile for the Chinese HCB pair."""

    recipes = (
        _native_clone_recipe(
            selector=16,
            resource_base_offset=0x5F631,
            resource_base_expected="graph_bs/CHR_レン",
            outfit_suffix_offset=0x5F678,
            outfit_suffix_expected="_死神",
        ),
        _native_clone_recipe(
            selector=21,
            resource_base_offset=0x5FCF9,
            resource_base_expected="graph_bs/CHR_看護婦",
            outfit_suffix_offset=0x5FD42,
            outfit_suffix_expected="_白衣",
        ),
        _native_clone_recipe(
            selector=19,
            resource_base_offset=0x5FABA,
            resource_base_expected="graph_bs/CHR_伊麻",
            outfit_suffix_offset=0x5FB01,
            outfit_suffix_expected="_巫女服",
        ),
    )
    recipe_by_selector = {item.carrier_selector: item for item in recipes}
    slots = tuple(
        HoshimemoPortraitSlot(
            slot_id=f"selector{selector}",
            selector=selector,
            primitive_ids=primitive_ids,
            dispatcher_symbol=recipe_by_selector[selector].output_symbol,
            kind="private_clone",
            clone_recipe_id=recipe_by_selector[selector].recipe_id,
            allocation_rank=rank,
        )
        for selector, primitive_ids, rank in (
            (16, (122, 123), 10),
            (19, (124, 125), 20),
            (21, (130, 131), 30),
        )
    )
    return HoshimemoTargetProfile(
        profile_id=HOSHIMEMO_NATIVE_PORTRAIT_PROFILE_ID,
        hcb=BinaryFingerprint(
            HOSHIMEMO_NATIVE_PORTRAIT_HCB_SHA256,
            HOSHIMEMO_NATIVE_PORTRAIT_HCB_SIZE,
        ),
        graph_bs=BinaryFingerprint(
            HOSHIMEMO_NATIVE_PORTRAIT_GRAPH_BS_SHA256,
            HOSHIMEMO_NATIVE_PORTRAIT_GRAPH_BS_SIZE,
        ),
        portrait_dispatcher=CodeRegionFingerprint(
            start=HOSHIMEMO_NATIVE_PORTRAIT_FUNCTION_4477_START,
            end=HOSHIMEMO_NATIVE_PORTRAIT_FUNCTION_4477_END,
            sha256=HOSHIMEMO_NATIVE_PORTRAIT_FUNCTION_4477_SHA256,
            args=13,
            locals=16,
        ),
        symbols=dict(HOSHIMEMO_NATIVE_PORTRAIT_SYMBOLS),
        slots=slots,
        clone_recipes=recipes,
    )


def build_hoshimemo_native_portrait_backend_profile() -> HoshimemoPortraitBackendProfile:
    """Return the compile-IR symbol contract paired with the target profile."""

    return HoshimemoPortraitBackendProfile(
        profile_id=HOSHIMEMO_NATIVE_PORTRAIT_PROFILE_ID,
        apply_layout_symbol="function_4480_",
        final_transform_symbol="native_primitive_state",
        opacity_symbol="function_4405_",
        rotation_symbol="function_4409_",
        expression_update_symbol="function_4487_",
        geometry_xy_symbol="function_4406_",
        geometry_z_symbol="function_4407_",
        geometry_scale_symbol="function_4408_",
    )


# Short aliases keep the factory discoverable for callers that use either
# "make" or "target" terminology while all aliases return the same canonical
# value and stable profile ID.
make_hoshimemo_native_portrait_profile = build_hoshimemo_native_portrait_profile
hoshimemo_native_portrait_profile = build_hoshimemo_native_portrait_profile
build_hoshimemo_native_portrait_target_profile = (
    build_hoshimemo_native_portrait_profile
)
make_hoshimemo_native_portrait_target_profile = (
    build_hoshimemo_native_portrait_profile
)
hoshimemo_native_portrait_target_profile = build_hoshimemo_native_portrait_profile
hoshimemo_native_portrait_backend_profile = (
    build_hoshimemo_native_portrait_backend_profile
)
make_hoshimemo_native_portrait_backend_profile = (
    build_hoshimemo_native_portrait_backend_profile
)


__all__ = [
    "HOSHIMEMO_NATIVE_PORTRAIT_GRAPH_BS_SHA256",
    "HOSHIMEMO_NATIVE_PORTRAIT_GRAPH_BS_SIZE",
    "HOSHIMEMO_NATIVE_PORTRAIT_GRAPH_BS_FILENAME",
    "HOSHIMEMO_NATIVE_PORTRAIT_HCB_SHA256",
    "HOSHIMEMO_NATIVE_PORTRAIT_HCB_SIZE",
    "HOSHIMEMO_NATIVE_PORTRAIT_HCB_FILENAME",
    "HOSHIMEMO_NATIVE_PORTRAIT_FUNCTION_4477_END",
    "HOSHIMEMO_NATIVE_PORTRAIT_FUNCTION_4477_SHA256",
    "HOSHIMEMO_NATIVE_PORTRAIT_FUNCTION_4477_START",
    "HOSHIMEMO_NATIVE_PORTRAIT_FUNCTION_4286_END",
    "HOSHIMEMO_NATIVE_PORTRAIT_FUNCTION_4286_SHA256",
    "HOSHIMEMO_NATIVE_PORTRAIT_FUNCTION_4286_START",
    "HOSHIMEMO_NATIVE_PORTRAIT_PROFILE_ID",
    "HOSHIMEMO_NATIVE_PORTRAIT_RESOURCE_VALUE_KEYS",
    "HOSHIMEMO_NATIVE_PORTRAIT_SYMBOLS",
    "build_hoshimemo_native_portrait_backend_profile",
    "build_hoshimemo_native_portrait_profile",
    "build_hoshimemo_native_portrait_target_profile",
    "hoshimemo_native_portrait_backend_profile",
    "hoshimemo_native_portrait_profile",
    "hoshimemo_native_portrait_target_profile",
    "make_hoshimemo_native_portrait_profile",
    "make_hoshimemo_native_portrait_backend_profile",
    "make_hoshimemo_native_portrait_target_profile",
]
