#!/usr/bin/env python3
"""Batch-export G.711 RTP audio from pcap/pcapng files to WAV."""

from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import re
import struct
import sys
import unicodedata
import wave
from array import array
from collections import Counter
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from pathlib import Path
from typing import Iterable, Iterator


SIP_200_RE = re.compile(rb"(?im)^SIP/2\.0[ \t]+200(?:[ \t]|\r?$)")
CSEQ_INVITE_RE = re.compile(rb"(?im)^CSeq\s*:\s*\d+\s+INVITE(?:\s|$)")
PCAP_EXTENSIONS = {".pcap", ".pcapng", ".cap"}
STATIC_CODECS = {0: ("PCMU", 8000), 8: ("PCMA", 8000)}


class CaptureError(Exception):
    pass


class AsrError(Exception):
    pass


@dataclass(frozen=True)
class TransportPacket:
    time: float
    src: str
    dst: str
    sport: int
    dport: int
    protocol: int
    payload: bytes
    tcp_seq: int | None = None


@dataclass(frozen=True)
class RtpPacket:
    time: float
    src: str
    dst: str
    sport: int
    dport: int
    payload_type: int
    sequence: int
    timestamp: int
    ssrc: int
    payload: bytes


@dataclass
class Stream:
    key: tuple[str, int, str, int, int]
    payload_type: int
    packets: list[RtpPacket] = field(default_factory=list)


@dataclass
class Result:
    source: Path
    answered: bool = False
    wav: Path | None = None
    stream_count: int = 0
    packet_count: int = 0
    duration: float = 0.0
    note: str = ""
    transcript: str = ""
    prompt_category: str = ""
    asr_note: str = ""


@dataclass
class CaptureStatus:
    truncated_tail: bool = False


@dataclass(frozen=True)
class PromptGroup:
    name: str
    representative: str
    count: int
    variants: tuple[str, ...]


class FasterWhisperRecognizer:
    def __init__(self, model: str, model_dir: Path | None = None):
        try:
            from faster_whisper import WhisperModel
        except (ImportError, OSError) as error:
            raise AsrError(f"无法加载 faster-whisper：{error}") from error
        try:
            self._model = WhisperModel(
                model,
                device="cpu",
                compute_type="int8",
                download_root=str(model_dir) if model_dir else None,
            )
        except Exception as error:
            raise AsrError(f"ASR 模型加载失败：{error}") from error

    def transcribe(self, wav_path: Path) -> str:
        segments, _info = self._model.transcribe(
            str(wav_path),
            language="zh",
            beam_size=5,
            vad_filter=True,
            condition_on_previous_text=False,
        )
        return "".join(segment.text.strip() for segment in segments).strip()


def iter_capture(path: Path, status: CaptureStatus | None = None) -> Iterator[tuple[float, int, bytes]]:
    status = status or CaptureStatus()
    with path.open("rb") as fh:
        magic = fh.read(4)
        fh.seek(0)
        if magic == b"\x0a\x0d\x0d\x0a":
            yield from _iter_pcapng(fh, status)
        elif magic in {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"}:
            yield from _iter_pcap(fh, status)
        else:
            raise CaptureError("不是支持的 pcap/pcapng 文件")


def _read_exact(fh, size: int) -> bytes:
    data = fh.read(size)
    if len(data) != size:
        raise CaptureError("抓包文件被截断")
    return data


def _iter_pcap(fh, status: CaptureStatus) -> Iterator[tuple[float, int, bytes]]:
    header = _read_exact(fh, 24)
    magic = header[:4]
    endian = "<" if magic in {b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"} else ">"
    scale = 1_000_000_000 if magic in {b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"} else 1_000_000
    linktype = struct.unpack_from(endian + "I", header, 20)[0]
    while True:
        record = fh.read(16)
        if not record:
            return
        if len(record) != 16:
            status.truncated_tail = True
            return
        sec, fraction, captured, _original = struct.unpack(endian + "IIII", record)
        if captured > 64 * 1024 * 1024:
            raise CaptureError("pcap 包长度异常")
        frame = fh.read(captured)
        if len(frame) != captured:
            status.truncated_tail = True
            return
        yield sec + fraction / scale, linktype, frame


def _iter_pcapng(fh, status: CaptureStatus) -> Iterator[tuple[float, int, bytes]]:
    endian = "<"
    interfaces: list[tuple[int, float]] = []
    have_section = False
    while True:
        block_type_raw = fh.read(4)
        if not block_type_raw:
            return
        if len(block_type_raw) != 4:
            if have_section:
                status.truncated_tail = True
                return
            raise CaptureError("pcapng 块头被截断")
        length_raw = fh.read(4)
        if len(length_raw) != 4:
            if have_section:
                status.truncated_tail = True
                return
            raise CaptureError("抓包文件被截断")
        if block_type_raw == b"\x0a\x0d\x0d\x0a":
            bom = fh.read(4)
            if len(bom) != 4:
                if have_section:
                    status.truncated_tail = True
                    return
                raise CaptureError("抓包文件被截断")
            if bom == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif bom == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            else:
                raise CaptureError("pcapng 字节序无效")
            total = struct.unpack(endian + "I", length_raw)[0]
            if total < 28:
                raise CaptureError("pcapng Section Header 长度无效")
            remainder = fh.read(total - 12)
            if len(remainder) != total - 12:
                if have_section:
                    status.truncated_tail = True
                    return
                raise CaptureError("抓包文件被截断")
            interfaces = []
            have_section = True
            continue
        total = struct.unpack(endian + "I", length_raw)[0]
        if total < 12 or total > 64 * 1024 * 1024:
            raise CaptureError("pcapng 块长度异常")
        body = fh.read(total - 12)
        if len(body) != total - 12:
            status.truncated_tail = True
            return
        trailer = fh.read(4)
        if len(trailer) != 4:
            status.truncated_tail = True
            return
        if struct.unpack(endian + "I", trailer)[0] != total:
            raise CaptureError("pcapng 块长度校验失败")
        block_type = struct.unpack(endian + "I", block_type_raw)[0]
        if block_type == 1 and len(body) >= 8:  # Interface Description Block
            linktype = struct.unpack_from(endian + "H", body, 0)[0]
            resolution = _pcapng_resolution(body[8:], endian)
            interfaces.append((linktype, resolution))
        elif block_type == 6 and len(body) >= 20:  # Enhanced Packet Block
            interface_id, high, low, captured = struct.unpack_from(endian + "IIII", body, 0)
            if interface_id >= len(interfaces) or 20 + captured > len(body):
                continue
            linktype, resolution = interfaces[interface_id]
            yield ((high << 32) | low) * resolution, linktype, body[20 : 20 + captured]
        elif block_type == 3 and len(body) >= 4 and interfaces:  # Simple Packet Block
            original = struct.unpack_from(endian + "I", body, 0)[0]
            yield 0.0, interfaces[0][0], body[4 : 4 + min(original, len(body) - 4)]


def _pcapng_resolution(options: bytes, endian: str) -> float:
    offset = 0
    while offset + 4 <= len(options):
        code, length = struct.unpack_from(endian + "HH", options, offset)
        offset += 4
        value = options[offset : offset + length]
        offset += (length + 3) & ~3
        if code == 0:
            break
        if code == 9 and value:
            number = value[0]
            return (2.0 ** -(number & 0x7F)) if number & 0x80 else (10.0 ** -number)
    return 1e-6


def parse_transport(timestamp: float, linktype: int, frame: bytes) -> TransportPacket | None:
    ip_data = _network_payload(linktype, frame)
    if not ip_data:
        return None
    version = ip_data[0] >> 4
    if version == 4:
        if len(ip_data) < 20:
            return None
        ihl = (ip_data[0] & 0x0F) * 4
        if ihl < 20 or len(ip_data) < ihl or (struct.unpack_from("!H", ip_data, 6)[0] & 0x1FFF):
            return None
        protocol = ip_data[9]
        src, dst = str(ipaddress.ip_address(ip_data[12:16])), str(ipaddress.ip_address(ip_data[16:20]))
        total = struct.unpack_from("!H", ip_data, 2)[0]
        segment = ip_data[ihl : min(total or len(ip_data), len(ip_data))]
    elif version == 6:
        parsed = _ipv6_payload(ip_data)
        if not parsed:
            return None
        protocol, src, dst, segment = parsed
    else:
        return None
    if protocol == 17 and len(segment) >= 8:
        sport, dport, length = struct.unpack_from("!HHH", segment, 0)
        return TransportPacket(timestamp, src, dst, sport, dport, protocol, segment[8 : min(length, len(segment))])
    if protocol == 6 and len(segment) >= 20:
        sport, dport, seq = struct.unpack_from("!HHI", segment, 0)
        offset = (segment[12] >> 4) * 4
        if offset < 20 or offset > len(segment):
            return None
        return TransportPacket(timestamp, src, dst, sport, dport, protocol, segment[offset:], seq)
    return None


def _network_payload(linktype: int, frame: bytes) -> bytes | None:
    if linktype == 1:  # Ethernet
        if len(frame) < 14:
            return None
        offset, ether_type = 14, struct.unpack_from("!H", frame, 12)[0]
        while ether_type in {0x8100, 0x88A8, 0x9100} and len(frame) >= offset + 4:
            ether_type = struct.unpack_from("!H", frame, offset + 2)[0]
            offset += 4
        return frame[offset:] if ether_type in {0x0800, 0x86DD} else None
    if linktype in {101, 12}:  # Raw IP
        return frame
    if linktype == 0 and len(frame) >= 4:  # BSD loopback
        return frame[4:]
    if linktype == 113 and len(frame) >= 16:  # Linux cooked v1
        return frame[16:] if struct.unpack_from("!H", frame, 14)[0] in {0x0800, 0x86DD} else None
    if linktype == 276 and len(frame) >= 20:  # Linux cooked v2
        return frame[20:] if struct.unpack_from("!H", frame, 0)[0] in {0x0800, 0x86DD} else None
    return None


def _ipv6_payload(data: bytes) -> tuple[int, str, str, bytes] | None:
    if len(data) < 40:
        return None
    protocol, offset = data[6], 40
    src, dst = str(ipaddress.ip_address(data[8:24])), str(ipaddress.ip_address(data[24:40]))
    while protocol in {0, 43, 44, 51, 60}:
        if offset + 2 > len(data):
            return None
        next_header = data[offset]
        if protocol == 44:
            if offset + 8 > len(data) or (struct.unpack_from("!H", data, offset + 2)[0] & 0xFFF8):
                return None
            size = 8
        elif protocol == 51:
            size = (data[offset + 1] + 2) * 4
        else:
            size = (data[offset + 1] + 1) * 8
        protocol, offset = next_header, offset + size
    return (protocol, src, dst, data[offset:]) if offset <= len(data) else None


def parse_rtp(packet: TransportPacket) -> RtpPacket | None:
    data = packet.payload
    if packet.protocol != 17 or len(data) < 12 or data[0] >> 6 != 2:
        return None
    payload_type = data[1] & 0x7F
    if 72 <= payload_type <= 76:  # RTCP packet types overlap marker/PT bits
        return None
    csrc_count = data[0] & 0x0F
    offset = 12 + csrc_count * 4
    if len(data) < offset:
        return None
    if data[0] & 0x10:
        if len(data) < offset + 4:
            return None
        extension_words = struct.unpack_from("!H", data, offset + 2)[0]
        offset += 4 + extension_words * 4
    end = len(data)
    if data[0] & 0x20:
        padding = data[-1]
        if padding == 0 or padding > end - offset:
            return None
        end -= padding
    if offset >= end:
        return None
    sequence, rtp_timestamp, ssrc = struct.unpack_from("!HII", data, 2)
    return RtpPacket(packet.time, packet.src, packet.dst, packet.sport, packet.dport, payload_type, sequence, rtp_timestamp, ssrc, data[offset:end])


def _contains_invite_200(data: bytes) -> bool:
    for match in SIP_200_RE.finditer(data):
        end = data.find(b"\r\n\r\n", match.start())
        separator = 4
        if end < 0:
            end = data.find(b"\n\n", match.start())
            separator = 2
        if end < 0:
            end = min(len(data), match.start() + 65536)
            separator = 0
        if CSEQ_INVITE_RE.search(data[match.start() : end + separator]):
            return True
    return False


def _tcp_streams(packets: Iterable[TransportPacket]) -> Iterator[bytes]:
    groups: dict[tuple[str, int, str, int], list[TransportPacket]] = {}
    for packet in packets:
        if packet.protocol == 6 and packet.payload:
            groups.setdefault((packet.src, packet.sport, packet.dst, packet.dport), []).append(packet)
    for group in groups.values():
        output = bytearray()
        next_seq: int | None = None
        for packet in sorted(group, key=lambda item: (item.tcp_seq or 0, item.time)):
            seq = packet.tcp_seq or 0
            if next_seq is None:
                output.extend(packet.payload)
                next_seq = seq + len(packet.payload)
            elif seq < next_seq:
                overlap = next_seq - seq
                if overlap < len(packet.payload):
                    output.extend(packet.payload[overlap:])
                    next_seq += len(packet.payload) - overlap
            elif seq == next_seq:
                output.extend(packet.payload)
                next_seq += len(packet.payload)
            else:
                output.extend(b"\r\n\r\n")
                output.extend(packet.payload)
                next_seq = seq + len(packet.payload)
        yield bytes(output)


def inspect_capture(path: Path, status: CaptureStatus | None = None) -> tuple[bool, list[Stream], int, set[int]]:
    status = status or CaptureStatus()
    tcp_packets: list[TransportPacket] = []
    streams: dict[tuple[str, int, str, int, int], Stream] = {}
    answered = False
    payload_types: set[int] = set()
    packet_count = 0
    for timestamp, linktype, frame in iter_capture(path, status):
        packet = parse_transport(timestamp, linktype, frame)
        if packet is None:
            continue
        if packet.protocol == 6 and packet.payload:
            tcp_packets.append(packet)
        if packet.payload and _contains_invite_200(packet.payload):
            answered = True
        rtp = parse_rtp(packet)
        if rtp:
            payload_types.add(rtp.payload_type)
            if rtp.payload_type in STATIC_CODECS:
                key = (rtp.src, rtp.sport, rtp.dst, rtp.dport, rtp.ssrc)
                stream = streams.setdefault(key, Stream(key, rtp.payload_type))
                if stream.payload_type == rtp.payload_type:
                    stream.packets.append(rtp)
                    packet_count += 1
    if not answered:
        answered = any(_contains_invite_200(data) for data in _tcp_streams(tcp_packets))
    valid = [stream for stream in streams.values() if _valid_stream(stream)]
    return answered, valid, packet_count, payload_types


def _valid_stream(stream: Stream) -> bool:
    packets = stream.packets
    if len(packets) < 2:
        return False
    ordered = sorted(packets, key=lambda item: item.time)
    plausible = 0
    for previous, current in zip(ordered, ordered[1:]):
        seq_delta = (current.sequence - previous.sequence) & 0xFFFF
        time_delta = (current.timestamp - previous.timestamp) & 0xFFFFFFFF
        if 0 < seq_delta < 100 and 0 < time_delta < 8000 * 10:
            plausible += 1
    return plausible >= min(2, len(packets) - 1)


def decode_g711(payload: bytes, codec: str) -> list[int]:
    decoder = _decode_ulaw if codec == "PCMU" else _decode_alaw
    return [decoder(value) for value in payload]


def _decode_ulaw(value: int) -> int:
    value = ~value & 0xFF
    sample = ((value & 0x0F) << 3) + 0x84
    sample <<= (value & 0x70) >> 4
    sample -= 0x84
    return -sample if value & 0x80 else sample


def _decode_alaw(value: int) -> int:
    value ^= 0x55
    sample = (value & 0x0F) << 4
    segment = (value & 0x70) >> 4
    sample += 8 if segment == 0 else 0x108
    if segment > 1:
        sample <<= segment - 1
    return sample if value & 0x80 else -sample


def _unwrap(value: int, base: int, bits: int) -> int:
    modulus = 1 << bits
    delta = (value - base) & (modulus - 1)
    return delta - modulus if delta >= modulus // 2 else delta


def render_stream(stream: Stream, global_start: float, rate: int = 8000) -> tuple[int, array[int]]:
    unique: dict[int, RtpPacket] = {}
    for packet in sorted(stream.packets, key=lambda item: item.time):
        unique.setdefault(packet.sequence, packet)
    packets = sorted(unique.values(), key=lambda item: item.time)
    first = packets[0]
    start = max(0, round((first.time - global_start) * rate))
    output = array("h")
    codec = STATIC_CODECS[stream.payload_type][0]
    for packet in packets:
        offset = _unwrap(packet.timestamp, first.timestamp, 32)
        if offset < -rate or offset > rate * 24 * 60 * 60:
            continue
        samples = decode_g711(packet.payload, codec)
        if offset < len(output):
            overlap = len(output) - offset
            if overlap >= len(samples):
                continue
            samples = samples[overlap:]
            offset = len(output)
        if offset > len(output):
            output.extend(array("h", [0]) * (offset - len(output)))
        output.extend(samples)
    return start, output


def mix_streams(streams: list[Stream]) -> array[int]:
    global_start = min(packet.time for stream in streams for packet in stream.packets)
    rendered = [render_stream(stream, global_start) for stream in streams]
    length = max(start + len(samples) for start, samples in rendered)
    sums = array("i", [0]) * length
    counts = array("H", [0]) * length
    seen: set[str] = set()
    for start, samples in rendered:
        sample_bytes = samples.tobytes()
        if sys.byteorder != "little":
            little_endian = array("h", samples)
            little_endian.byteswap()
            sample_bytes = little_endian.tobytes()
        digest = hashlib.sha256(sample_bytes).hexdigest()
        if digest in seen:
            continue
        seen.add(digest)
        for index, sample in enumerate(samples, start):
            if sample:
                sums[index] += sample
                counts[index] = min(65535, counts[index] + 1)
    output = array("h")
    output.extend(max(-32768, min(32767, round(total / count))) if count else 0 for total, count in zip(sums, counts))
    return output


def write_wav(path: Path, samples: array[int], rate: int = 8000) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with wave.open(str(path), "wb") as output:
        output.setnchannels(1)
        output.setsampwidth(2)
        output.setframerate(rate)
        chunk_size = 100_000
        for start in range(0, len(samples), chunk_size):
            chunk = samples[start : start + chunk_size]
            if sys.byteorder != "little":
                chunk.byteswap()
            output.writeframesraw(chunk.tobytes())


def find_captures(root: Path, recursive: bool) -> list[Path]:
    iterator = root.rglob("*") if recursive else root.glob("*")
    return sorted(path for path in iterator if path.is_file() and path.suffix.lower() in PCAP_EXTENSIONS)


def process_file(source: Path, output: Path, status_filter: str) -> Result:
    result = Result(source)
    try:
        capture_status = CaptureStatus()
        answered, streams, packet_count, payload_types = inspect_capture(source, capture_status)
        warning = "（已忽略尾部截断数据）" if capture_status.truncated_tail else ""
        result.answered = answered
        result.stream_count = len(streams)
        result.packet_count = packet_count
        if status_filter == "answered" and not answered or status_filter == "unanswered" and answered:
            result.note = "已按接通状态跳过" + warning
            return result
        if not streams:
            known = sorted(payload_types)
            result.note = "未发现可导出的 G.711 RTP 媒体流"
            if known:
                result.note += f"（检测到 RTP Payload Type: {known}）"
            result.note += warning
            return result
        samples = mix_streams(streams)
        if not samples:
            result.note = "媒体流没有有效音频样本" + warning
            return result
        category = "已接通" if answered else "未接通"
        target = output / category / f"{source.stem}.wav"
        write_wav(target, samples)
        result.wav = target
        result.duration = len(samples) / 8000
        result.note = "导出成功" + warning
    except (OSError, CaptureError, struct.error, ValueError) as error:
        result.note = f"处理失败：{error}"
    return result


def transcribe_unanswered(results: list[Result], recognizer) -> None:
    for result in results:
        if result.answered:
            continue
        if result.wav is None:
            result.asr_note = "无可识别录音"
            continue
        if recognizer is None:
            continue
        try:
            result.transcript = recognizer.transcribe(result.wav)
            result.asr_note = "识别成功" if result.transcript else "未识别到语音"
        except Exception as error:
            result.asr_note = f"识别失败：{error}"


def normalize_transcript(text: str) -> str:
    normalized = unicodedata.normalize("NFKC", text).casefold()
    normalized = "".join(character for character in normalized if character.isalnum())
    return re.sub(r"\d+", "0", normalized)


def transcript_similarity(left: str, right: str) -> float:
    if left == right:
        return 1.0
    if not left or not right:
        return 0.0
    return SequenceMatcher(None, left, right, autojunk=False).ratio()


def classify_transcripts(results: list[Result], threshold: float = 0.82) -> list[PromptGroup]:
    variants: dict[str, list[Result]] = {}
    for result in results:
        normalized = normalize_transcript(result.transcript)
        if normalized:
            variants.setdefault(normalized, []).append(result)
    texts = sorted(variants)
    parents = list(range(len(texts)))

    def find(index: int) -> int:
        while parents[index] != index:
            parents[index] = parents[parents[index]]
            index = parents[index]
        return index

    def union(left: int, right: int) -> None:
        left_root, right_root = find(left), find(right)
        if left_root != right_root:
            parents[right_root] = left_root

    for left in range(len(texts)):
        for right in range(left + 1, len(texts)):
            if transcript_similarity(texts[left], texts[right]) >= threshold:
                union(left, right)

    clusters: dict[int, list[Result]] = {}
    for index, text in enumerate(texts):
        clusters.setdefault(find(index), []).extend(variants[text])

    prepared: list[tuple[str, list[Result], tuple[str, ...]]] = []
    for members in clusters.values():
        counts = Counter(item.transcript.strip() for item in members)
        representative = min(counts, key=lambda value: (-counts[value], len(value), value))
        ordered_variants = tuple(sorted(counts, key=lambda value: (-counts[value], value)))
        prepared.append((representative, members, ordered_variants))
    prepared.sort(key=lambda item: (-len(item[1]), normalize_transcript(item[0]), item[0]))

    groups: list[PromptGroup] = []
    for index, (representative, members, ordered_variants) in enumerate(prepared, 1):
        name = f"提示音-{index:03d}"
        for result in members:
            result.prompt_category = name
        groups.append(PromptGroup(name, representative, len(members), ordered_variants))
    return groups


def write_report(output: Path, results: list[Result]) -> Path:
    output.mkdir(parents=True, exist_ok=True)
    path = output / "导出报告.csv"
    with path.open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["抓包文件", "接通状态", "WAV文件", "RTP流数", "RTP包数", "时长秒", "提示音内容", "提示音分类", "ASR结果", "结果"])
        for item in results:
            writer.writerow([
                str(item.source),
                "已接通" if item.answered else "未接通",
                str(item.wav or ""),
                item.stream_count,
                item.packet_count,
                f"{item.duration:.3f}" if item.duration else "",
                item.transcript,
                item.prompt_category,
                item.asr_note,
                item.note,
            ])
    return path


def write_category_report(output: Path, groups: list[PromptGroup]) -> Path:
    output.mkdir(parents=True, exist_ok=True)
    path = output / "提示音分类汇总.csv"
    with path.open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["提示音分类", "数量", "代表内容", "识别文本变体"])
        for group in groups:
            writer.writerow([group.name, group.count, group.representative, " | ".join(group.variants)])
    return path


def similarity_threshold(value: str) -> float:
    try:
        threshold = float(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("相似度必须是 0 到 1 之间的数字") from error
    if not 0 <= threshold <= 1:
        raise argparse.ArgumentTypeError("相似度必须是 0 到 1 之间的数字")
    return threshold


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="批量识别 SIP 接通状态并将 G.711 RTP 媒体导出为 WAV")
    parser.add_argument("input", type=Path, help="抓包目录，或单个 pcap/pcapng 文件")
    parser.add_argument("-o", "--output", type=Path, default=Path("wav_output"), help="输出目录（默认：wav_output）")
    parser.add_argument(
        "--status",
        choices=("all", "answered", "unanswered"),
        default="all",
        help="all=全部，answered=仅接通，unanswered=仅未接通（默认：all）",
    )
    parser.add_argument("--no-recursive", action="store_true", help="不扫描输入目录的子目录")
    parser.add_argument("--asr", action="store_true", help="对未接通 WAV 执行中文 ASR 识别")
    parser.add_argument("--asr-model", default="small", help="faster-whisper 模型名称或本地模型目录（默认：small）")
    parser.add_argument("--asr-model-dir", type=Path, help="模型下载和缓存目录")
    parser.add_argument("--asr-similarity", type=similarity_threshold, default=0.82, help="提示音文本聚类阈值 0-1（默认：0.82）")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    source = args.input.resolve()
    output = args.output.resolve()
    if not source.exists():
        print(f"错误：输入路径不存在：{source}", file=sys.stderr)
        return 2
    captures = [source] if source.is_file() else find_captures(source, not args.no_recursive)
    if not captures:
        print("没有找到 .pcap、.pcapng 或 .cap 文件。", file=sys.stderr)
        return 1
    results: list[Result] = []
    for index, capture in enumerate(captures, 1):
        result = process_file(capture, output, args.status)
        results.append(result)
        state = "已接通" if result.answered else "未接通"
        print(f"[{index}/{len(captures)}] {capture.name} | {state} | {result.note}")
    if args.asr:
        candidates = [item for item in results if not item.answered and item.wav is not None]
        if candidates:
            print(f"正在加载 ASR 模型：{args.asr_model}")
            try:
                recognizer = FasterWhisperRecognizer(args.asr_model, args.asr_model_dir)
            except AsrError as error:
                transcribe_unanswered(results, None)
                for item in candidates:
                    item.asr_note = f"识别失败：{error}"
            else:
                transcribe_unanswered(results, recognizer)
                for index, item in enumerate(candidates, 1):
                    print(f"[ASR {index}/{len(candidates)}] {item.wav.name} | {item.asr_note} | {item.transcript}")
        else:
            transcribe_unanswered(results, None)
    groups = classify_transcripts(results, args.asr_similarity) if args.asr else []
    category_report = write_category_report(output, groups) if args.asr else None
    report = write_report(output, results)
    exported = sum(item.wav is not None for item in results)
    failed = sum(item.note.startswith("处理失败") for item in results)
    asr_failed = sum(item.asr_note.startswith("识别失败") for item in results)
    category_message = f"，提示音分类 {len(groups)} 个；分类汇总：{category_report}" if category_report else ""
    print(f"完成：导出 {exported} 个 WAV，抓包失败 {failed} 个，ASR失败 {asr_failed} 个{category_message}；报告：{report}")
    return 2 if failed or asr_failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
