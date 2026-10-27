"""Shared audio-only adapter for absolute script/scene/chapter emitters.

The native implementation is exactly NativeAudioResumeCode, also used by the
full scene-state bridge. This adapter adds no title, slot or EXE address rule.
It returns bytes only; publishing must install the matching EXE and HCB pair.
"""
from copy import deepcopy
import hashlib
import struct

from .hcb import Syscall, parse_bytes
from .native_audio_program import audio_script_snapshot
from .native_audio_resume import NativeAudioResumeBinding
from .native_cg_state_bridge import (AUDIO_HOLD_NAME, AUDIO_RESTORE_NAME,
                                    build_audio_state_bridge)


class NativeAudioResumeSession:
    def __init__(self, source, document, output, bank, native, executable, *, extra_globals=(), checkpoint_test=False):
        from .gui_audio_checkpoint import bridge_options
        checkpoint_options = bridge_options(checkpoint_test)
        if native.source is not document or bank.e.source!=source or bank.e.output is not output:
            raise ValueError('原剧情音频接口必须使用同一脚本及其私有变量分配器。')
        self.source=source
        self.output=output
        self.encoding=document.encoding
        self.header_at=None
        self.header_bytes=None
        self.restore_sites=[]
        self.binding=NativeAudioResumeBinding(executable)
        self.bridge=build_audio_state_bridge(executable,self.binding,
            original_volatile_globals=document.header.volatile_globals, **checkpoint_options)
        names=[s.name for s in document.header.syscalls]
        if (AUDIO_HOLD_NAME in names or AUDIO_RESTORE_NAME in names
                or len(names)+1 > 0x7fff):
            raise ValueError('原剧情音频接口已存在或原生调用表已满。')
        self.first=len(names)
        self.original_syscalls=[(s.name,s.args) for s in document.header.syscalls]
        self.snapshot=audio_script_snapshot(native,bank.reserve_private,extra_globals=extra_globals)
        output.extend(self.snapshot['snapshot'])
        self.hold_site=len(output)
        output.extend(b'\x03'+struct.pack('<H',self.first))

    def restore(self):
        """Called at final story exits only, not at chapter scene boundaries."""
        self.output.extend(self.snapshot['restore'])
        self.restore_sites.append(len(self.output))
        self.output.extend(b'\x03'+struct.pack('<H',self.first+1))

    def finalize(self, payload):
        if self.header_at is not None:
            raise ValueError('音频续播脚本不能重复封装。')
        if not self.restore_sites:
            raise ValueError('音频续播缺少返回原剧情的出口。')
        table=struct.unpack_from('<I',self.source)[0]
        if struct.unpack_from('<I',payload)[0]!=table or not 4<=table<len(self.source):
            raise ValueError('原剧情音频接口的脚本头发生变化。')
        header=parse_bytes(struct.pack('<I',4)+payload[table:len(self.source)],self.encoding)
        if [(s.name,s.args) for s in header.header.syscalls]!=self.original_syscalls:
            raise ValueError('音频续播不能改变原有系统调用编号。')
        for name in (AUDIO_HOLD_NAME,AUDIO_RESTORE_NAME):
            header.header.syscalls.append(Syscall(0,name,name.encode('ascii')+b'\0'))
        self.header_at=len(payload)
        self.header_bytes=header._build_sysdesc(self.header_at,header.header.entry_point)
        result=bytearray(payload+self.header_bytes)
        struct.pack_into('<I',result,0,self.header_at)
        self.script_sha256=hashlib.sha256(result).hexdigest()
        return bytes(result)

    def validation_parts(self, payload):
        if (self.header_at is None or struct.unpack_from('<I',payload)[0]!=self.header_at
                or payload[self.header_at:]!=self.header_bytes
                or payload[self.hold_site:self.hold_site+3]!=b'\x03'+struct.pack('<H',self.first)
                or any(payload[at:at+3]!=b'\x03'+struct.pack('<H',self.first+1)
                       for at in self.restore_sites)):
            raise ValueError('音频续播脚本头或进入／返回调用与配套接口不一致。')
        normalized=bytearray(payload[:self.header_at])
        normalized[:4]=self.source[:4]
        return bytes(normalized),self.header_bytes

    def report(self):
        report=deepcopy(self.bridge.report)
        report.update(script_linked=self.header_at is not None,
            output_script_sha256=getattr(self,'script_sha256',None),
            native_interface_syscall_ids=[self.first,self.first+1],
            hold_site=self.hold_site,restore_sites=list(self.restore_sites),
            original_audio_globals=self.snapshot['report']['global_ids'],
            original_syscall_ids_unchanged=True,original_script_entry_unchanged=True,
            chapter_boundary_restores_original=False,
            original_playback_restore_connected=self.header_at is not None,
            requires_matching_new_test_executable=True)
        return report
