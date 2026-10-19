"""Inert WOFF, CFF and Type 1 container metadata with shared decode accounting."""

import struct

from malpdf.extraction.media import MediaIssue, digest, table_checksum


def inspect_woff(data: bytes, *, budget, max_expansion_ratio: int) -> dict:
    from malpdf.extraction.filters import _Stopped, _flate
    result = {'format': 'woff', 'complete': False, 'reason_codes': [], 'tables': [],
              'scope': 'WOFF directory, table byte bounds and checksums; no font programs executed',
              'font_execution_performed': False, 'font_validity_verified': False}
    if len(data) < 44 or data[:4] not in {b'wOFF', b'wOF2'}:
        raise MediaIssue('woff_header_invalid', details=result)
    length, count, reserved = struct.unpack_from('>IHH', data, 8)
    if reserved or length != len(data) or not count:
        raise MediaIssue('woff_header_invalid', details=result)
    result.update(table_count=count, sfnt_size_declared=int.from_bytes(data[16:20], 'big'))
    if data[:4] == b'wOF2':
        result.update(format='woff2', reason_codes=['woff2_transform_decoder_unavailable'])
        return result
    if 44 + count * 20 > len(data):
        raise MediaIssue('woff_directory_truncated', details=result)
    reasons, seen, tags, ranges = set(), set(), [], []
    for index in range(count):
        tag, offset, compressed, original, checksum = struct.unpack_from('>4sIIII', data, 44 + index * 20)
        tags.append(tag)
        entry = {'tag_hex': tag.hex(), 'offset': offset, 'compressed_bytes': compressed,
                 'original_bytes': original, 'checksum_declared': checksum, 'checksum_verified': False}
        result['tables'].append(entry)
        if tag in seen:
            reasons.add('woff_duplicate_table')
        seen.add(tag)
        if offset < 44 + count * 20 or offset + compressed > len(data) or compressed > original or offset % 4:
            reasons.add('woff_table_bounds_invalid')
            continue
        if compressed:
            ranges.append((offset, offset + compressed))
        body = data[offset:offset + compressed]
        if compressed < original:
            try:
                body = _flate(body, min(budget.remaining, compressed * max_expansion_ratio))
            except _Stopped as error:
                budget.remaining -= len(error.prefix or b'')
                reasons.add(error.code)
                continue
            budget.remaining -= len(body)
        entry.update(observed_bytes=len(body), sha256=digest(body))
        if len(body) != original:
            reasons.add('woff_table_size_mismatch')
        else:
            entry['checksum_verified'] = table_checksum(body, head=tag == b'head') == checksum
            if not entry['checksum_verified']:
                reasons.add('woff_table_checksum_mismatch')
            if tag == b'maxp' and len(body) >= 6:
                result['glyph_count'] = int.from_bytes(body[4:6], 'big')
    ranges.sort()
    if any(left[1] > right[0] for left, right in zip(ranges, ranges[1:])):
        reasons.add('woff_table_overlap')
    if tags != sorted(tags):
        reasons.add('woff_table_order_invalid')
    result.update(complete=not reasons, reason_codes=sorted(reasons))
    return result


def inspect_cff(data: bytes) -> dict:
    result = {'format': 'cff', 'complete': False, 'reason_codes': [], 'indexes': [],
              'scope': 'CFF1 header and initial INDEX framing only; CharStrings and glyph programs not evaluated',
              'font_execution_performed': False, 'font_validity_verified': False}
    if len(data) < 4 or data[0] != 1 or not 4 <= data[2] <= len(data) or data[3] not in (1, 2, 3, 4):
        raise MediaIssue('cff_header_unsupported', 'unsupported', result)
    offset = data[2]
    for name in ('names', 'top_dicts', 'strings', 'global_subrs'):
        if offset + 2 > len(data):
            raise MediaIssue('cff_index_truncated', details=result)
        count = int.from_bytes(data[offset:offset + 2], 'big')
        offset += 2
        if not count:
            result['indexes'].append({'kind': name, 'count': 0, 'size_bytes': 0})
            continue
        if offset >= len(data) or data[offset] not in (1, 2, 3, 4):
            raise MediaIssue('cff_offset_size_invalid', details=result)
        width = data[offset]
        offset += 1
        if offset + (count + 1) * width > len(data):
            raise MediaIssue('cff_index_truncated', details=result)
        offsets = [int.from_bytes(data[offset + index * width:offset + (index + 1) * width], 'big')
                   for index in range(count + 1)]
        offset += (count + 1) * width
        if offsets[0] != 1 or offsets != sorted(offsets) or offset + offsets[-1] - 1 > len(data):
            raise MediaIssue('cff_index_bounds_invalid', details=result)
        size = offsets[-1] - 1
        result['indexes'].append({'kind': name, 'count': count, 'size_bytes': size,
                                  'sha256': digest(memoryview(data)[offset:offset + size])})
        offset += size
    if result['indexes'][0]['count'] != result['indexes'][1]['count'] or not result['indexes'][0]['count']:
        raise MediaIssue('cff_font_count_invalid', details=result)
    result.update(complete=True, font_count=result['indexes'][0]['count'])
    return result


def inspect_type1(data: bytes) -> dict:
    result = {'format': 'type1', 'complete': False, 'reason_codes': [], 'segments': [],
              'scope': 'Type1 container/header boundaries and hashes only; PostScript/eexec programs never executed',
              'font_execution_performed': False, 'font_validity_verified': False}
    if data.startswith((b'%!PS-AdobeFont', b'%!FontType1')):
        result.update(complete=True, lexical_header_verified=True, encrypted_program_marker_present=b'eexec' in data)
        return result
    offset = 0
    while offset < len(data):
        if offset + 2 > len(data) or data[offset] != 128 or data[offset + 1] not in (1, 2, 3):
            raise MediaIssue('type1_segment_header_invalid', details=result)
        kind = data[offset + 1]
        if kind == 3:
            result.update(complete=offset + 2 == len(data),
                          reason_codes=[] if offset + 2 == len(data) else ['type1_trailing_data'])
            return result
        if offset + 6 > len(data):
            raise MediaIssue('type1_segment_truncated', details=result)
        length = int.from_bytes(data[offset + 2:offset + 6], 'little')
        if offset + 6 + length > len(data):
            raise MediaIssue('type1_segment_truncated', details=result)
        result['segments'].append({'kind': kind, 'offset': offset, 'size_bytes': length,
                                   'sha256': digest(memoryview(data)[offset + 6:offset + 6 + length])})
        offset += 6 + length
    raise MediaIssue('type1_end_marker_missing', details=result)
