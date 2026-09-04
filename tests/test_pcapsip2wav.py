import csv
import socket
import struct
import tempfile
import unittest
import wave
from pathlib import Path

import pcapsip2wav as tool


def udp_frame(payload: bytes, sport: int, dport: int, src: str = "10.0.0.1", dst: str = "10.0.0.2") -> bytes:
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    ip = bytearray(20)
    ip[0] = 0x45
    struct.pack_into("!H", ip, 2, 20 + len(udp))
    ip[8] = 64
    ip[9] = 17
    ip[12:16] = socket.inet_aton(src)
    ip[16:20] = socket.inet_aton(dst)
    ethernet = b"\x00" * 12 + b"\x08\x00"
    return ethernet + bytes(ip) + udp


def tcp_frame(payload: bytes, sequence: int, sport: int = 5060, dport: int = 5060) -> bytes:
    tcp = bytearray(20)
    struct.pack_into("!HHI", tcp, 0, sport, dport, sequence)
    tcp[12] = 0x50
    ip = bytearray(20)
    ip[0] = 0x45
    struct.pack_into("!H", ip, 2, 20 + len(tcp) + len(payload))
    ip[8] = 64
    ip[9] = 6
    ip[12:16] = socket.inet_aton("10.0.0.1")
    ip[16:20] = socket.inet_aton("10.0.0.2")
    return b"\x00" * 12 + b"\x08\x00" + bytes(ip) + bytes(tcp) + payload


def rtp(payload_type: int, sequence: int, timestamp: int, ssrc: int, audio: bytes) -> bytes:
    return struct.pack("!BBHII", 0x80, payload_type, sequence, timestamp, ssrc) + audio


def write_pcap(path: Path, frames: list[tuple[float, bytes]]) -> None:
    with path.open("wb") as output:
        output.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for timestamp, frame in frames:
            sec = int(timestamp)
            usec = int(round((timestamp - sec) * 1_000_000))
            output.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
            output.write(frame)


def write_pcapng(path: Path, frames: list[tuple[float, bytes]]) -> None:
    def block(block_type: int, body: bytes) -> bytes:
        body += b"\x00" * ((-len(body)) % 4)
        length = 12 + len(body)
        return struct.pack("<II", block_type, length) + body + struct.pack("<I", length)

    section = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    interface = block(1, struct.pack("<HHI", 1, 0, 65535))
    packets = []
    for timestamp, frame in frames:
        ticks = round(timestamp * 1_000_000)
        body = struct.pack("<IIIII", 0, ticks >> 32, ticks & 0xFFFFFFFF, len(frame), len(frame)) + frame
        packets.append(block(6, body))
    path.write_bytes(section + interface + b"".join(packets))


class ToolTests(unittest.TestCase):
    def test_invite_200_is_answered_and_unrelated_200_is_not(self):
        invite_ok = b"SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP host\r\nCSeq: 42 INVITE\r\n\r\n"
        options_ok = b"SIP/2.0 200 OK\r\nCSeq: 9 OPTIONS\r\n\r\n"
        self.assertTrue(tool._contains_invite_200(invite_ok))
        self.assertFalse(tool._contains_invite_200(options_ok))

    def test_export_answered_g711_capture_and_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            capture = root / "20260903-10086-13800138000-abc.pcap"
            sip = b"SIP/2.0 200 OK\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n"
            frames = [(1.0, udp_frame(sip, 5060, 5060))]
            for index in range(3):
                audio = bytes([0xD5] * 160)
                frames.append((1.1 + index * 0.02, udp_frame(rtp(8, 100 + index, index * 160, 1234, audio), 10000, 20000)))
            write_pcap(capture, frames)
            output = root / "out"
            result = tool.process_file(capture, output, "all")
            self.assertTrue(result.answered)
            self.assertIsNotNone(result.wav)
            self.assertEqual(result.stream_count, 1)
            with wave.open(str(result.wav), "rb") as wav_file:
                self.assertEqual(wav_file.getframerate(), 8000)
                self.assertEqual(wav_file.getnchannels(), 1)
                self.assertEqual(wav_file.getnframes(), 480)
            report = tool.write_report(output, [result])
            with report.open(encoding="utf-8-sig", newline="") as source:
                rows = list(csv.reader(source))
            self.assertEqual(rows[1][1], "已接通")
            self.assertEqual(rows[0][-4:], ["提示音内容", "提示音分类", "ASR结果", "结果"])

    def test_asr_only_transcribes_unanswered_wav(self):
        class Recognizer:
            def __init__(self):
                self.paths = []

            def transcribe(self, path):
                self.paths.append(path)
                return "您拨打的号码暂时无法接通"

        unanswered = tool.Result(Path("unanswered.pcap"), wav=Path("unanswered.wav"))
        answered = tool.Result(Path("answered.pcap"), answered=True, wav=Path("answered.wav"))
        no_audio = tool.Result(Path("no-audio.pcap"))
        recognizer = Recognizer()

        tool.transcribe_unanswered([unanswered, answered, no_audio], recognizer)

        self.assertEqual(recognizer.paths, [Path("unanswered.wav")])
        self.assertEqual(unanswered.transcript, "您拨打的号码暂时无法接通")
        self.assertEqual(unanswered.asr_note, "识别成功")
        self.assertEqual(answered.asr_note, "")
        self.assertEqual(no_audio.asr_note, "无可识别录音")

    def test_asr_failure_does_not_stop_other_results(self):
        class Recognizer:
            def transcribe(self, _path):
                raise RuntimeError("bad audio")

        result = tool.Result(Path("unanswered.pcap"), wav=Path("unanswered.wav"))

        tool.transcribe_unanswered([result], Recognizer())

        self.assertEqual(result.asr_note, "识别失败：bad audio")

    def test_similar_transcripts_are_grouped_and_distinct_prompts_stay_separate(self):
        results = [
            tool.Result(Path("a.pcap"), transcript="您拨打的号码暂时无法接通，请稍后再拨。"),
            tool.Result(Path("b.pcap"), transcript="您拨打的号码暂时无法接通请稍后再拨"),
            tool.Result(Path("c.pcap"), transcript="您拨打的用户暂时无法接通，请稍后再拨"),
            tool.Result(Path("d.pcap"), transcript="您拨打的用户已关机"),
        ]

        groups = tool.classify_transcripts(results)

        self.assertEqual(len(groups), 2)
        self.assertEqual(groups[0].count, 3)
        self.assertEqual(results[0].prompt_category, "提示音-001")
        self.assertEqual(results[1].prompt_category, "提示音-001")
        self.assertEqual(results[2].prompt_category, "提示音-001")
        self.assertEqual(results[3].prompt_category, "提示音-002")

    def test_transcript_normalization_ignores_punctuation_and_number_values(self):
        left = tool.normalize_transcript("号码 138-0013-8000 暂停服务！")
        right = tool.normalize_transcript("号码13900139000暂停服务")

        self.assertEqual(left, right)

    def test_category_report_contains_representative_and_count(self):
        with tempfile.TemporaryDirectory() as directory:
            results = [
                tool.Result(Path("a.pcap"), transcript="线路忙，请稍后再拨"),
                tool.Result(Path("b.pcap"), transcript="线路忙请稍后再拨"),
            ]
            groups = tool.classify_transcripts(results)

            report = tool.write_category_report(Path(directory), groups)

            with report.open(encoding="utf-8-sig", newline="") as source:
                rows = list(csv.reader(source))
            self.assertEqual(rows[0], ["提示音分类", "数量", "代表内容", "识别文本变体"])
            self.assertEqual(rows[1][0:2], ["提示音-001", "2"])

    def test_unanswered_filter_skips_answered_capture(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            capture = root / "answered.pcap"
            sip = b"SIP/2.0 200 OK\r\nCSeq: 1 INVITE\r\n\r\n"
            frames = [(1.0, udp_frame(sip, 5060, 5060))]
            for index in range(2):
                frames.append((1.1 + index * 0.02, udp_frame(rtp(0, index, index * 160, 99, b"\xff" * 160), 10000, 20000)))
            write_pcap(capture, frames)
            result = tool.process_file(capture, root / "out", "unanswered")
            self.assertTrue(result.answered)
            self.assertIsNone(result.wav)
            self.assertEqual(result.note, "已按接通状态跳过")

    def test_no_media_is_reported_without_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            capture = root / "unanswered.pcap"
            write_pcap(capture, [(1.0, udp_frame(b"SIP/2.0 486 Busy Here\r\nCSeq: 1 INVITE\r\n\r\n", 5060, 5060))])
            result = tool.process_file(capture, root / "out", "unanswered")
            self.assertFalse(result.answered)
            self.assertIsNone(result.wav)
            self.assertIn("未发现", result.note)

    def test_pcapng_is_supported(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "early-media.pcapng"
            frames = []
            for index in range(2):
                frames.append((2.0 + index * 0.02, udp_frame(rtp(0, index, index * 160, 7, b"\xff" * 160), 12000, 22000)))
            write_pcapng(path, frames)
            answered, streams, _packet_count, _payload_types = tool.inspect_capture(path)
            self.assertFalse(answered)
            self.assertEqual(len(streams), 1)

    def test_truncated_pcap_tail_keeps_complete_rtp_packets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "truncated.pcap"
            frames = [
                (1.0 + index * 0.02, udp_frame(rtp(8, index, index * 160, 1234, b"\xd5" * 160), 10000, 20000))
                for index in range(3)
            ]
            write_pcap(path, frames)
            with path.open("ab") as output:
                output.write(struct.pack("<IIII", 2, 0, 200, 200) + b"incomplete")

            result = tool.process_file(path, root / "out", "all")

            self.assertIsNotNone(result.wav)
            self.assertEqual(result.packet_count, 3)
            self.assertEqual(result.note, "导出成功（已忽略尾部截断数据）")

    def test_truncated_pcapng_tail_keeps_complete_rtp_packets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "truncated.pcapng"
            frames = [
                (1.0 + index * 0.02, udp_frame(rtp(0, index, index * 160, 7, b"\xff" * 160), 12000, 22000))
                for index in range(3)
            ]
            write_pcapng(path, frames)
            with path.open("ab") as output:
                output.write(struct.pack("<II", 6, 100) + b"incomplete")

            result = tool.process_file(path, root / "out", "all")

            self.assertIsNotNone(result.wav)
            self.assertEqual(result.packet_count, 3)
            self.assertEqual(result.note, "导出成功（已忽略尾部截断数据）")

    def test_truncated_global_header_still_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "broken.pcap"
            path.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 8)

            result = tool.process_file(path, root / "out", "all")

            self.assertEqual(result.note, "处理失败：抓包文件被截断")

    def test_segmented_tcp_invite_200_is_reassembled(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "tcp-signaling.pcap"
            first = b"SIP/2.0 200 OK\r\nVia: SIP/2.0/TCP host\r\nCS"
            second = b"eq: 77 INVITE\r\nContent-Length: 0\r\n\r\n"
            write_pcap(path, [(1.0, tcp_frame(first, 1000)), (1.01, tcp_frame(second, 1000 + len(first)))])
            answered, _streams, _packet_count, _payload_types = tool.inspect_capture(path)
            self.assertTrue(answered)


if __name__ == "__main__":
    unittest.main()
