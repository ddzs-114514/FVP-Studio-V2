"""Own full allocation descendants, not live heap or exception acceptance.

Every explicit branch, API identity, local finalizer and shared heap reference
is checked. Arithmetic witnesses do not allocate or execute native code. Heap
handles, mutable metadata, lock/SEH ownership, callbacks and reentry remain
conditions; this binding does not grant public CG output.
"""
import hashlib
import struct

from .native_import_size_discovery import _pe_sections
from .native_legacy_size_discovery import _relocated
from .native_cg_vm_cleanup import _code
from .native_cg_vm_application import _writable_image_range, _import_slots
from .native_cg_vm_startup import _record
from .native_cg_vm_heap_paths import _Grammar, _word, _callee, _import
from .native_cg_vm_heap_children import _data, _same
from .native_cg_vm_member_copy import _native_signed_remainder16
from .native_cg_vm_restore_symbols import bind_native_cg_vm_restore_symbols

SCHEMA = 'fvp-native-cg-vm-heap-allocations/1'
MASK = 2**32 - 1


class _AllocationGrammar(_Grammar):
    def __init__(self):
        super().__init__()
        self.words = set()

    def word(self, name):
        if name in self.words:
            self.parts.append(b'(?P=' + name.encode() + b')')
        else:
            super().word(name)
            self.words.add(name)


def _bits(*values):
    if any(type(v) is not int or not 0 <= v <= MASK for v in values):
        raise ValueError('CG 分配参数必须是实际32位位模式。')


def _calloc_request_witness(count, size, mode, threshold):
    """Own overflow check and requests; no allocator/handler is invoked."""
    _bits(count, size, mode, threshold)
    if count and size > 0xffffffe0 // count:
        return dict(overflow=True, product=None, heap_request=None, small_request=None)
    product = (count * size) & MASK
    request = max(product, 1)
    if mode == 3:
        request = (request + 15) & 0xfffffff0
    return dict(overflow=False, product=product, heap_request=request,
                small_request=product if mode == 3 and product <= threshold else None)


def _small_request_witness(size):
    _bits(size)
    aligned = ((size + 23) & MASK) & 0xfffffff0
    signed = aligned if aligned < 0x80000000 else aligned - 2**32
    index = (signed >> 4) - 1
    shift = (index if index < 32 else index - 32) & 31
    return dict(aligned_block_bytes=aligned, signed_bucket_index=index,
                low_mask=MASK >> shift if index < 32 else 0,
                high_mask=MASK if index < 32 else MASK >> shift)


def _retry_next_witness(current, maximum):
    _bits(current, maximum)
    next_value = (current + 1000) & MASK
    return MASK if next_value > maximum else next_value


def _zero_optimized_plan(destination, count):
    """Conditional own caller plan, including negative signed remainders."""
    _bits(destination, count)
    if count < 256:
        raise ValueError('CG 清零见证需要满足自身入口的至少256字节条件。')
    remainder = _native_signed_remainder16(destination)
    prefix = 16 - remainder if remainder else 0
    remaining = count - prefix
    return dict(prefix_bytes=prefix, recursive_calls=int(prefix != 0),
                chunk_iterations=remaining >> 7, remainder_bytes=remaining & 127)


def _bind(raw, image, sections, imports, address, g, *, ranges=(), apis=()):
    at, code = _code(raw, image, sections, address, 1024)
    m = g.match(code)
    for name, api in apis:
        _import(raw, image, sections, imports, m, name, api)
    helpers = {n:_callee(raw, image, sections, address, m, n) for n in m.groupdict()
               if '_call' in n and not n.startswith('branch_')}
    return m, dict(**_record(address, at, m[0]), helper_addresses=helpers,
                   static_ranges={n:_writable_image_range(raw, image, sections, _word(m, n), 4) for n in ranges},
                   imported_identities={n:imports[_word(m, n)] for n, _ in apis},
                   callee_argument_cleanup_bytes=0,
                   own_complete_explicit_normal_instruction_paths_static_bound=True,
                   valid_nonwrapping_memory_and_child_ABI_required=True, native_code_executed=False)


def _retry(raw, image, sections, imports, address, *, calloc):
    g = _AllocationGrammar()
    g.code('8bff558bec565733f6'); g.mark('retry')
    g.code('6a00ff750cff7508' if calloc else 'ff7508')
    g.code('e8'); g.word('allocator_call')
    g.code('8bf883c40c85ff' if calloc else '8bf85985ff'); g.branch('75', 'return')
    g.code('3905'); g.word('timeout'); g.branch('76', 'return')
    g.code('56ff15'); g.word('sleep_api'); g.code('8d86e80300003b05'); g.word('timeout')
    g.branch('76', 'advance'); g.code('83c8ff'); g.mark('advance')
    g.code('8bf083f8ff'); g.branch('75', 'retry'); g.mark('return'); g.code('8bc75f5e5dc3')
    _, row = _bind(raw, image, sections, imports, address, g, ranges=('timeout',), apis=(('sleep_api', 'Sleep'),))
    return dict(**row, entry_SP_argument_displacements=dict(count=4, size=8) if calloc else dict(size=4),
                calloc_optional_error_pointer_passed_zero=calloc,
                timeout_zero_returns_after_first_failed_attempt_without_sleep=True,
                first_allowed_retry_requests_Sleep_zero=True, next_sleep_request_step=1000,
                timeout_is_reread_after_failure_and_sleep=True,
                retry_counter_addition_wraps_32_bits=True, retry_stops_on_minus_one_sentinel=True,
                actual_elapsed_time_and_retry_termination_proven=False)


def _small_core(raw, image, sections, imports, address):
    g = _AllocationGrammar()
    g.code('8bff558bec83ec14a1'); g.word('count'); g.code('8b4d086bc0140305'); g.word('buffer')
    g.code('83c11783e1f0894df0c1f904534983f9205657'); g.branch('7d', 'high_mask')
    g.code('83ceffd3ee834df8ff'); g.branch('eb', 'scan_start'); g.mark('high_mask')
    g.code('83c1e083caff33f6d3ea8955f8'); g.mark('scan_start')
    g.code('8b0d'); g.word('scan'); g.code('8bd9'); g.branch('eb', 'scan_test')
    g.mark('scan_loop'); g.code('8b53048b3b2355f823fe0bd7'); g.branch('75', 'scan_end')
    g.code('83c314'); g.mark('scan_test'); g.code('895d083bd8'); g.branch('72', 'scan_loop')
    g.mark('scan_end'); g.code('3bd8'); g.branch('75', 'found'); g.code('8b1d'); g.word('buffer')
    g.branch('eb', 'wrap_test'); g.mark('wrap_loop'); g.code('8b53048b3b2355f823fe0bd7')
    g.branch('75', 'wrap_end'); g.code('83c314'); g.mark('wrap_test'); g.code('895d083bd9')
    g.branch('72', 'wrap_loop'); g.mark('wrap_end'); g.code('3bd9'); g.branch('75', 'found')
    g.branch('eb', 'region_test'); g.mark('region_loop'); g.code('837b0800'); g.branch('75', 'region_end')
    g.code('83c314895d08'); g.mark('region_test'); g.code('3bd8'); g.branch('72', 'region_loop')
    g.mark('region_end'); g.code('3bd8'); g.branch('75', 'region_ready'); g.code('8b1d'); g.word('buffer')
    g.branch('eb', 'region_wrap_test'); g.mark('region_wrap_loop'); g.code('837b0800')
    g.branch('75', 'region_wrap_end'); g.code('83c314'); g.mark('region_wrap_test'); g.code('895d083bd9')
    g.branch('72', 'region_wrap_loop'); g.mark('region_wrap_end'); g.code('3bd9'); g.branch('75', 'region_ready')
    g.code('e8'); g.word('grow_call'); g.code('8bd8895d0885db'); g.branch('75', 'region_ready')
    g.mark('zero'); g.code('33c0'); g.branch('e9', 'return', True); g.mark('region_ready')
    g.code('53e8'); g.word('region_call'); g.code('598b4b1089018b43108338ff'); g.branch('74', 'zero')
    g.mark('found'); g.code('891d'); g.word('scan'); g.code('8b43108b108955fc83faff')
    g.branch('74', 'region_scan'); g.code('8b8c90c40000008b7c9044234df823fe0bcf')
    g.branch('75', 'region_found'); g.mark('region_scan'); g.code('8365fc008b90c40000008d4844')
    g.mark('region_scan_loop'); g.code('8b392355f823fe0bd7'); g.branch('75', 'region_scan_end')
    g.code('ff45fc8b918400000083c104'); g.branch('eb', 'region_scan_loop')
    g.mark('region_scan_end'); g.code('8b55fc'); g.mark('region_found')
    g.code('8bca69c9040200008d8c0144010000894df48b4c904433ff23ce'); g.branch('75', 'bit_test')
    g.code('8b8c90c4000000234df86a205f'); g.branch('eb', 'bit_test'); g.mark('bit_loop')
    g.code('03c947'); g.mark('bit_test'); g.code('85c9'); g.branch('7d', 'bit_loop')
    g.code('8b4df48b54f9048b0a2b4df08bf1c1fe044e83fe3f894df8'); g.branch('7e', 'bucket')
    g.code('6a3f5e'); g.mark('bucket'); g.code('3bf7'); g.branch('0f84', 'split_test', True)
    g.code('8b4a043b4a08'); g.branch('75', 'unlink'); g.code('83ff20bb00000080')
    g.branch('7d', 'remove_high'); g.code('8bcfd3eb8b4dfc8d7c3804f7d3895dec235c8844895c8844fe0f')
    g.branch('75', 'remove_done'); g.code('8b4dec8b5d08210b'); g.branch('eb', 'unlink')
    g.mark('remove_high'); g.code('8d4fe0d3eb8b4dfc8d8c88c40000008d7c3804f7d32119fe0f895dec')
    g.branch('75', 'remove_done'); g.code('8b5d088b4dec214b04'); g.branch('eb', 'unlink')
    g.mark('remove_done'); g.code('8b5d08'); g.mark('unlink')
    g.code('837df8008b4a088b7a048979048b4a048b7a08897908'); g.branch('0f84', 'no_remainder', True)
    g.code('8b4df48d0cf18b7904894a08897a048951048b4a048951088b4a043b4a08')
    g.branch('75', 'insert_done'); g.code('8a4c0604884d0bfec183fe20884c0604')
    g.branch('7d', 'insert_high'); g.code('807d0b00'); g.branch('75', 'insert_low_local')
    g.code('bf000000808bced3ef093b'); g.mark('insert_low_local')
    g.code('8bcebf00000080d3ef8b4dfc097c8844'); g.branch('eb', 'insert_done')
    g.mark('insert_high'); g.code('807d0b00'); g.branch('75', 'insert_high_local')
    g.code('8d4ee0bf00000080d3ef097b04'); g.mark('insert_high_local')
    g.code('8b4dfc8dbc88c40000008d4ee0be00000080d3ee0937'); g.mark('insert_done')
    g.code('8b4df8'); g.mark('split_test'); g.code('85c9'); g.branch('74', 'allocated')
    g.code('890a894c11fc'); g.branch('eb', 'allocated'); g.mark('no_remainder'); g.code('8b4df8')
    g.mark('allocated'); g.code('8b75f003d18d4e01890a894c32fc8b75f48b0e8d7901893e85c9')
    g.branch('75', 'publish'); g.code('3b1d'); g.word('cached_header'); g.branch('75', 'publish')
    g.code('8b4dfc3b0d'); g.word('cached_region'); g.branch('75', 'publish')
    g.code('8325'); g.word('cached_header'); g.code('00'); g.mark('publish')
    g.code('8b4dfc89088d4204'); g.mark('return'); g.code('5f5e5bc9c3')
    _, row = _bind(raw, image, sections, imports, address, g,
                   ranges=('count','buffer','scan','cached_header','cached_region'))
    return dict(**row, entry_SP_argument_displacements=dict(size=4),
                header_stride_bytes=20, region_metadata_stride_bytes=516, size_bucket_maximum=63,
                request_adds_23_then_aligns_down_16_with_32_bit_wrap=True,
                signed_bucket_and_x86_masked_shift_counts_preserved=True,
                header_and_region_searches_use_own_bitmap_before_grow=True,
                region_allocation_failure_returns_zero_without_rollback_of_published_header=True,
                selected_free_block_split_and_bidirectional_list_updates_static_bound=True,
                block_header_and_trailer_store_size_plus_one=True,
                may_write_byte_in_original_caller_size_argument=True,
                cached_empty_region_is_cleared_only_on_matching_header_and_region=True,
                metadata_shape_bounds_list_validity_and_mutation_effects_proven=False)


def _small_grow(raw, image, sections, imports, address):
    g = _AllocationGrammar()
    g.code('a1'); g.word('capacity'); g.code('568b35'); g.word('count'); g.code('5733ff3bf0')
    g.branch('75','metadata'); g.code('83c0106bc01450ff35'); g.word('buffer')
    g.code('57ff35'); g.word('heap'); g.code('ff15'); g.word('realloc_api'); g.code('3bc7')
    g.branch('75','grown'); g.mark('zero'); g.code('33c0'); g.branch('eb','return')
    g.mark('grown'); g.code('8305'); g.word('capacity'); g.code('108b35'); g.word('count')
    g.code('a3'); g.word('buffer'); g.mark('metadata'); g.code('6bf6140335'); g.word('buffer')
    g.code('68c44100006a08ff35'); g.word('heap'); g.code('ff15'); g.word('alloc_api')
    g.code('8946103bc7'); g.branch('74','zero'); g.code('6a046800200000680000100057ff15')
    g.word('virtual_api'); g.code('89460c3bc7'); g.branch('75','publish')
    g.code('ff761057ff35'); g.word('heap'); g.code('ff15'); g.word('free_api'); g.branch('eb','zero')
    g.mark('publish'); g.code('834e08ff893e897e04ff05'); g.word('count')
    g.code('8b46108308ff8bc6'); g.mark('return'); g.code('5f5ec3')
    _, row = _bind(raw, image, sections, imports, address, g, ranges=('capacity','count','buffer','heap'),
                   apis=(('realloc_api','HeapReAlloc'),('alloc_api','HeapAlloc'),('virtual_api','VirtualAlloc'),('free_api','HeapFree')))
    return dict(**row, header_stride_bytes=20, capacity_growth_entries=16, metadata_request_bytes=0x41c4,
                metadata_heap_flags=8, reserved_region_bytes=0x100000, virtual_allocation_type=0x2000,
                virtual_protection=4, failed_reserve_frees_new_metadata=True,
                failed_realloc_or_metadata_or_reserve_returns_zero=True,
                header_count_increments_only_after_successful_reserve=True,
                grown_header_array_is_not_rolled_back_after_later_failure=True,
                new_header_and_metadata_cached_indices_are_minus_one=True,
                capacity_and_count_arithmetic_wraps_32_bits=True,
                allocation_bounds_reentry_and_external_API_effects_proven=False)


def _small_region(raw, image, sections, imports, address):
    g = _AllocationGrammar()
    g.code('8bff558bec51518b4d088b410853568b71105733db'); g.branch('eb','bit_test')
    g.mark('bit_loop'); g.code('03c043'); g.mark('bit_test'); g.code('85c0'); g.branch('7d','bit_loop')
    g.code('8bc369c0040200008d8430440100006a3f8945f85a'); g.mark('list_loop')
    g.code('89400889400483c0084a'); g.branch('75','list_loop')
    g.code('6a048bfb6800100000c1e70f03790c680080000057ff15'); g.word('virtual_api')
    g.code('85c0'); g.branch('75','pages'); g.code('83c8ff'); g.branch('e9','return',True)
    g.mark('pages'); g.code('8d97007000008955fc3bfa'); g.branch('77','link')
    g.code('8bca2bcfc1e90c8d471041'); g.mark('page_loop')
    g.code('8348f8ff8388ec0f0000ff8d90fc0f000089108d90fcefffffc740fcf00f0000895004c780e80f0000f00f0000050010000049')
    g.branch('75','page_loop'); g.code('8b55fc'); g.mark('link')
    g.code('8b45f805f80100008d4f0c8948048941088d4a0c89480889410483649e440033ff4789bc9ec40000008a46438ac8fec184c08b4508884e43')
    g.branch('75','bitmap'); g.code('097804'); g.mark('bitmap')
    g.code('ba000000808bcbd3eaf7d22150088bc3'); g.mark('return'); g.code('5f5e5bc9c3')
    _, row = _bind(raw,image,sections,imports,address,g,apis=(('virtual_api','VirtualAlloc'),))
    return dict(**row, entry_SP_argument_displacements=dict(header=4), virtual_region_bytes=0x8000,
                virtual_allocation_type=0x1000, virtual_protection=4, region_shift_bits=15,
                region_metadata_stride_bytes=516, ordinary_free_list_initialization_iterations=63,
                free_page_block_bytes=0xff0, page_stride_bytes=0x1000,
                failed_commit_returns_minus_one_after_metadata_list_initialization=True,
                successful_commit_publishes_free_bitmaps_and_returns_region_index=True,
                no_local_zero_bitmap_or_region_index_guard=True,
                dynamic_region_metadata_and_committed_memory_bounds_proven=False)


def _calloc_core(raw, image, sections, imports, address):
    g = _AllocationGrammar()
    g.code('6a0c68'); g.word('seh'); g.code('e8'); g.word('frame_call')
    g.code('8b4d0833ff3bcf'); g.branch('76','product'); g.code('6ae05833d2f7f13b450c1bc040')
    g.branch('75','product'); g.code('e8'); g.word('error_call'); g.code('c7000c0000005757575757e8')
    g.word('invalid_call'); g.code('83c414'); g.mark('zero'); g.code('33c0'); g.branch('e9','return',True)
    g.mark('product'); g.code('0faf4d0c8bf18975083bf7'); g.branch('75','retry')
    g.code('33f646'); g.mark('retry'); g.code('33db895de483fee0'); g.branch('77','failed')
    g.code('833d'); g.word('mode'); g.code('03'); g.branch('75','test_small_result')
    g.code('83c60f83e6f089750c8b45083b05'); g.word('threshold'); g.branch('77','test_small_result')
    g.code('6a04e8'); g.word('lock_call'); g.code('59897dfcff7508e8'); g.word('small_call')
    g.code('598945e4c745fcfeffffffe8'); g.word('finally_call')
    g.code('8b5de43bdf'); g.branch('74','heap_allocate'); g.code('ff75085753e8'); g.word('fill_call'); g.code('83c40c')
    g.mark('test_small_result'); g.code('3bdf'); g.branch('75','success'); g.mark('heap_allocate')
    g.code('566a08ff35'); g.word('heap'); g.code('ff15'); g.word('heap_api'); g.code('8bd8')
    g.mark('failed'); g.code('3bdf'); g.branch('75','success'); g.code('393d'); g.word('new_mode')
    g.branch('74','store_optional'); g.code('56e8'); g.word('handler_call'); g.code('5985c0')
    g.branch('0f85','retry',True); g.code('8b45103bc7'); g.branch('0f84','zero',True)
    g.code('c7000c000000'); g.branch('e9','zero',True)
    g.mark('unwind'); g.code('33ff8b750c'); g.mark('finally'); g.code('6a04e8'); g.word('unlock_call'); g.code('59c3')
    g.mark('store_optional'); g.code('3bdf'); g.branch('75','success'); g.code('8b45103bc7')
    g.branch('74','success'); g.code('c7000c000000'); g.mark('success'); g.code('8bc3')
    g.mark('return'); g.code('e8'); g.word('unframe_call'); g.code('c3')
    m, row = _bind(raw,image,sections,imports,address,g,ranges=('mode','threshold','heap','new_mode'),apis=(('heap_api','HeapAlloc'),))
    if row['helper_addresses']['finally_call'] != address + m.start('finally'):
        raise ValueError('CG 清零分配没有使用自身的锁释放收尾入口。')
    seh_address = _word(m,'seh')
    seh_at = _relocated(raw,image,sections,seh_address,executable=False,length=28)
    words = list(struct.unpack_from('<7I',raw,seh_at))
    if words != [MASK - 1,0,MASK - 43,0,MASK - 1,0,address + m.start('unwind')]:
        raise ValueError('CG 清零分配的异常表没有对应自身完整的锁释放路径。')
    return dict(**row, own_SEH_scope_table=_data(raw,image,sections,seh_address,28), own_SEH_scope_words=words,
                entry_SP_argument_displacements=dict(count=4,size=8,optional_error_pointer=12),
                nonzero_count_guard_size_maximum_dividend=0xffffffe0,
                zero_count_bypasses_division_and_yields_zero_product=True,
                overflow_stores_12_then_calls_own_invalid_handler_and_returns_zero=True,
                zero_product_normal_heap_request_is_one=True,
                mode3_small_path_uses_product_and_clears_only_product_bytes=True,
                mode3_normal_heap_fallback_aligns_request_16=True,
                normal_heap_flags=8, optional_error_pointer_written_only_on_final_allocation_failure=True,
                enabled_handler_nonzero_result_retries_with_current_mutable_state=True,
                own_local_finalizer_and_SEH_unwind_landing_static_bound=True,
                exception_cookie_dispatch_handler_reentry_and_zeroed_extent_proven=False)


def _zero_fill(raw, image, sections, imports, address):
    g = _AllocationGrammar()
    g.code('8b54240c8b4c240485d2'); g.branch('74','empty'); g.code('33c08a44240884c0')
    g.branch('75','ordinary'); g.code('81fa00010000'); g.branch('72','ordinary')
    g.code('833d'); g.word('optimized_enabled'); g.code('00'); g.branch('74','ordinary')
    g.code('e9'); g.word('optimized_call'); g.mark('ordinary'); g.code('578bf983fa04')
    g.branch('72','bytes'); g.code('f7d983e103'); g.branch('74','dwords')
    g.code('2bd1'); g.mark('prefix'); g.code('880783c70183e901'); g.branch('75','prefix')
    g.mark('dwords'); g.code('8bc8c1e00803c18bc8c1e01003c18bca83e203c1e902')
    g.branch('74','bytes'); g.code('f3ab85d2'); g.branch('74','return')
    g.mark('bytes'); g.code('880783c70183ea01'); g.branch('75','bytes')
    g.mark('return'); g.code('8b4424085fc3'); g.mark('empty'); g.code('8b442404c3')
    _, row = _bind(raw,image,sections,imports,address,g,ranges=('optimized_enabled',))
    return dict(**row,entry_SP_argument_displacements=dict(destination=4,value=8,count=12),
                count_zero_returns_destination_without_writing=True,
                value_uses_low_byte_then_replicates_for_REP_STOSD=True,
                ordinary_path_prefix_aligns_destination_four_bytes=True,
                optimized_zero_path_requires_value_zero_count_at_least_256_and_enabled_flag=True,
                DF_zero_and_valid_memory_required=True, actual_zeroed_extent_and_memory_aliases_proven=False)


def _zero_optimized(raw, image, sections, imports, address):
    g = _AllocationGrammar()
    g.code('558bec83ec10897dfc8b4508998bf833fa2bfa83e70f33fa2bfa85ff')
    g.branch('75','prefix'); g.code('8b4d108bd183e27f8955f43bca'); g.branch('74','tail')
    g.code('2bca5150e8'); g.word('chunk_call'); g.code('83c4088b45088b55f4')
    g.mark('tail'); g.code('85d2'); g.branch('74','return')
    g.code('0345102bc28945f833c08b7df88b4df4f3aa8b4508'); g.branch('eb','return')
    g.mark('prefix'); g.code('f7df83c710897df033c08b7d088b4df0f3aa8b45f08b4d088b551003c82bd0526a0051e8')
    g.word('recursive_call'); g.code('83c40c8b4508'); g.mark('return'); g.code('8b7dfc8be55dc3')
    _, row = _bind(raw,image,sections,imports,address,g)
    _same(row['helper_addresses'],dict(recursive_call=address))
    return dict(**row, signed_destination_remainder_16_preserved=True,
                prefix_bytes_can_be_up_to_31_for_negative_signed_addresses=True,
                aligned_chunk_called_only_when_count_minus_remainder_128_is_nonzero=True,
                remainder_uses_REP_STOSB_and_original_destination_returned=True,
                own_caller_minimum_size_condition_required=True,
                DF_zero_SSE2_memory_and_recursive_aliasing_effects_proven=False)


def _zero_chunk(raw, image, sections, imports, address):
    g = _AllocationGrammar()
    g.code('558bec83ec04897dfc8b7d088b4d0cc1e907660fefc0'); g.branch('eb','loop')
    g.code('8da4240000000090'); g.mark('loop'); g.code('660f7f07')
    for displacement in range(16,128,16):
        g.code('660f7f47' + bytes([displacement]).hex())
    g.code('8dbf8000000049'); g.branch('75','loop'); g.code('8b7dfc8be55dc3')
    _, row = _bind(raw,image,sections,imports,address,g)
    return dict(**row, bytes_per_iteration=128, destination_alignment_bytes=16,
                do_while_counter_is_unsigned_count_shifted_seven_bits=True,
                zero_block_count_would_iterate_2_to_32=True,
                own_optimized_caller_static_path_requires_positive_block_count=True,
                XMM0_clobbered=True, usable_SSE2_required=True, actual_store_bounds_proven=False)


def _own_allocation_paths(raw, image, sections, imports, heap):
    c = heap['native_heap_child_dispatch_paths']; p = heap['native_vm_heap_paths']['native_heap_instruction_paths']
    free = heap['native_vm_heap_paths']['native_vm_member_copy']['native_vm_member_children']['native_vm_members'][
        'native_vm_teardown']['native_vm_cleanup']['native_release_bridge']['native_free_paths']
    paths = dict(malloc_retry=_retry(raw,image,sections,imports,c['lock_initialize']['helper_addresses']['allocate_call'],calloc=False),
                 calloc_retry=_retry(raw,image,sections,imports,c['thread_data']['helper_addresses']['calloc_call'],calloc=True),
                 small_core=_small_core(raw,image,sections,imports,c['small_allocate']['helper_addresses']['small_call']))
    paths['calloc_core'] = _calloc_core(raw,image,sections,imports,paths['calloc_retry']['helper_addresses']['allocator_call'])
    paths['small_grow'] = _small_grow(raw,image,sections,imports,paths['small_core']['helper_addresses']['grow_call'])
    paths['small_region'] = _small_region(raw,image,sections,imports,paths['small_core']['helper_addresses']['region_call'])
    paths['zero_fill'] = _zero_fill(raw,image,sections,imports,paths['calloc_core']['helper_addresses']['fill_call'])
    paths['zero_optimized'] = _zero_optimized(raw,image,sections,imports,paths['zero_fill']['helper_addresses']['optimized_call'])
    paths['zero_chunk'] = _zero_chunk(raw,image,sections,imports,paths['zero_optimized']['helper_addresses']['chunk_call'])
    _same(paths['malloc_retry']['helper_addresses'],dict(allocator_call=p['allocation']['address']))
    _same(paths['calloc_core']['helper_addresses'],dict(error_call=p['error_slot']['address'],
          invalid_call=c['string_copy']['helper_addresses']['invalid_call'],handler_call=p['handler']['address'],
          lock_call=p['lock_dispatch']['lock']['address'],unlock_call=p['lock_dispatch']['unlock']['address'],
          frame_call=free['helper_addresses']['frame_call'],unframe_call=free['helper_addresses']['unframe_call'],
          small_call=paths['small_core']['address']))
    if paths['malloc_retry']['static_ranges']['timeout'] != paths['calloc_retry']['static_ranges']['timeout']:
        raise ValueError('CG 普通与清零分配重试没有使用自身同一超时设置。')
    relations = dict(count=p['lookup']['header_count_storage'],buffer=p['lookup']['header_buffer_pointer_storage'],
                     scan=p['small_release']['static_heap_ranges']['scan_pointer'],
                     cached_header=p['small_release']['static_heap_ranges']['cached_header0'],
                     cached_region=p['small_release']['static_heap_ranges']['cached_region0'])
    if paths['small_core']['static_ranges'] != relations:
        raise ValueError('CG 小块分配、查找与释放没有使用自身同一组区域表和缓存。')
    grow = paths['small_grow']['static_ranges']; allocation = p['allocation']['static_heap_ranges']
    if any(grow[n] != relations[n] for n in ('count','buffer')) or grow['heap'] != allocation['heap_global']:
        raise ValueError('CG 小块扩容没有使用自身同一区域表和普通堆。')
    calloc = paths['calloc_core']['static_ranges']
    if calloc != dict(mode=allocation['heap_mode'],threshold=c['small_allocate']['own_small_request_threshold_range'],
                      heap=allocation['heap_global'],new_mode=allocation['new_mode']):
        raise ValueError('CG 清零分配没有使用自身普通分配的堆、模式、处理设置和小块阈值。')
    rows = list(paths.values()) + list(c.values()) + [p['allocation'],p['small_release']]
    for index, first in enumerate(rows):
        if any(max(first['address'],second['address']) < min(first['address'] + first['code_bytes'],second['address'] + second['code_bytes'])
               for second in rows[index + 1:]):
            raise ValueError('CG 分配后代与自身已经绑定的函数字节重叠。')
    return paths


def bind_native_cg_vm_heap_allocations(executable, header, vm, frames):
    raw = bytes(executable); parent = bind_native_cg_vm_restore_symbols(raw,header,vm,frames)
    legacy = parent['layout'] == 'signed-word-legacy'; allocations = None
    if not legacy:
        heap = parent['native_vm_restore_huffman']['native_vm_restore_blocks']['native_vm_restore_inflate'][
            'native_vm_restore_children']['native_vm_restore']['native_vm_thread_startup']['native_vm_loader']['native_vm_heap_children']
        image, sections = _pe_sections(raw)
        paths = _own_allocation_paths(raw,image,sections,_import_slots(raw,image),heap)
        allocations = dict(paths=paths,own_complete_allocation_descendant_instruction_paths_static_bound=True,
                           own_shared_heap_metadata_lock_error_and_release_identity_static_bound=True,
                           remaining_allocation_dispatch_children=dict(
                               invalid_parameter_dispatch=paths['calloc_core']['helper_addresses']['invalid_call']),
                           actual_heap_objects_zeroed_bytes_callbacks_SEH_aliases_and_reentry_proven=False,
                           native_code_executed=False)
    return dict(schema=SCHEMA,exe_sha256=hashlib.sha256(raw).hexdigest(),layout=parent['layout'],
                native_vm_restore_symbols=parent,native_heap_allocation_descendants=allocations,
                own_modern_allocation_descendant_paths_static_bound=not legacy,
                legacy_external_allocator_implementation_not_substituted=legacy,
                actual_heap_allocation_release_and_zeroed_extents_proven=False,
                complete_heap_and_aliasing_effects_proven=False,complete_exception_and_reentry_effects_proven=False,
                complete_compression_child_effects_proven=False,actual_file_bytes_and_type_read_bounds_proven=False,
                post_main_restoration_paths_and_children_bound=False,
                complete_thread_and_root_initial_state_at_first_dispatch_proven=False,
                same_live_instance_lifetime_proven=False,initial_syscall_vector_count_zero_proven=False,
                reload_clear_before_header_append_proven=False,source_header_arity_to_native_descriptor_bound=False,
                native_code_executed=False,runtime_verified=False,scene_export_connected=False,public_cg_export_enabled=False)
