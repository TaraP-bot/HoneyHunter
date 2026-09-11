"""Bounded HTTP body collection and upload extraction; never executes content."""
import asyncio
from email import policy
from email.parser import BytesParser
from urllib.parse import unquote_to_bytes

HEADER_LIMIT = 64 * 1024
BODY_LIMIT = 10 * 1024 * 1024
WIRE_LIMIT = BODY_LIMIT + 2 * 1024 * 1024


class CaptureStopped(Exception):
    pass


async def collect_request(initial, reader, writer):
    """Return wire bytes, transfer-decoded body, headers, and completion status."""
    wire = bytearray(initial)
    body = bytearray()
    headers = {}
    position = 0
    deadline = asyncio.get_running_loop().time() + 60

    async def more(limit):
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            raise CaptureStopped('timeout')
        if len(wire) >= limit:
            raise CaptureStopped('size_limit')
        try:
            data = await asyncio.wait_for(reader.read(min(65536, limit - len(wire))), min(10, remaining))
        except asyncio.TimeoutError:
            raise CaptureStopped('timeout')
        except ConnectionError:
            raise CaptureStopped('connection_error')
        if not data:
            raise CaptureStopped('peer_eof')
        wire.extend(data)

    async def line():
        nonlocal position
        while True:
            end = wire.find(b'\r\n', position)
            if end >= 0:
                if end - position > HEADER_LIMIT:
                    raise CaptureStopped('invalid_chunk_line')
                result = bytes(wire[position:end])
                position = end + 2
                return result
            if len(wire) - position > HEADER_LIMIT:
                raise CaptureStopped('invalid_chunk_line')
            await more(WIRE_LIMIT)

    try:
        while b'\r\n\r\n' not in wire:
            await more(HEADER_LIMIT)
        end = wire.index(b'\r\n\r\n')
        if end + 4 > HEADER_LIMIT:
            raise CaptureStopped('header_limit')
        position = end + 4
        for item in bytes(wire[:end]).split(b'\r\n')[1:]:
            if b':' not in item:
                raise CaptureStopped('invalid_headers')
            key, value = item.split(b':', 1)
            key = key.decode('latin1').strip().lower()
            value = value.decode('latin1').strip()
            if key in headers:
                headers[key] += ',' + value
            else:
                headers[key] = value
        if headers.get('expect', '').lower() == '100-continue':
            writer.write(b'HTTP/1.1 100 Continue\r\n\r\n')
            await writer.drain()
        transfer = headers.get('transfer-encoding', '').lower()
        if transfer:
            if transfer != 'chunked' or 'content-length' in headers:
                raise CaptureStopped('unsupported_or_ambiguous_framing')
            while True:
                size_line = (await line()).split(b';', 1)[0]
                if not size_line or any(c not in b'0123456789abcdefABCDEF' for c in size_line):
                    raise CaptureStopped('invalid_chunk_size')
                size = int(size_line, 16)
                if size == 0:
                    trailer_start = position
                    while await line():
                        if position - trailer_start > HEADER_LIMIT:
                            raise CaptureStopped('trailer_limit')
                    return bytes(wire[:position]), bytes(body), headers, 'complete'
                if len(body) + size > BODY_LIMIT:
                    raise CaptureStopped('body_limit')
                remaining = size
                while remaining:
                    available = min(remaining, len(wire) - position)
                    if available:
                        body.extend(wire[position:position + available])
                        position += available
                        remaining -= available
                    else:
                        await more(WIRE_LIMIT)
                while len(wire) - position < 2:
                    await more(WIRE_LIMIT)
                if wire[position:position + 2] != b'\r\n':
                    raise CaptureStopped('invalid_chunk_terminator')
                position += 2
        length = headers.get('content-length')
        if length is None:
            # Unframed bytes already sent are evidence, not a complete HTTP body.
            body.extend(wire[position:position + BODY_LIMIT])
            return bytes(wire), bytes(body), headers, 'unframed' if body else 'complete'
        if not length.isascii() or not length.isdigit() or len(length) > 20:
            raise CaptureStopped('invalid_content_length')
        expected = int(length)
        target = min(expected, BODY_LIMIT)
        while len(body) < target:
            available = min(target - len(body), len(wire) - position)
            if available:
                body.extend(wire[position:position + available])
                position += available
            else:
                await more(WIRE_LIMIT)
        return bytes(wire[:position]), bytes(body), headers, 'complete' if expected <= BODY_LIMIT else 'body_limit'
    except CaptureStopped as exc:
        return bytes(wire), bytes(body), headers, str(exc)


def extract_parts(body, content_type):
    """Yield exact MIME part bytes or percent-decoded form values with labels."""
    kind = content_type.split(';', 1)[0].strip().lower()
    if kind == 'multipart/form-data':
        message = BytesParser(policy=policy.default).parsebytes(
            b'Content-Type: ' + content_type.encode('latin1') + b'\r\nMIME-Version: 1.0\r\n\r\n' + body
        )
        # No recursion into attacker-supplied nested MIME structures.
        if message.is_multipart():
            for part in message.iter_parts():
                if part.is_multipart():
                    continue
                data = part.get_payload(decode=True)
                if data is not None:
                    yield data, {
                        'filename': part.get_filename(),
                        'field_name': part.get_param('name', header='content-disposition'),
                        'content_type': part.get_content_type(),
                        'artifact_kind': 'multipart_part',
                        'parser_defects': [type(d).__name__ for d in part.defects],
                    }
    elif kind == 'application/x-www-form-urlencoded':
        for field in body.split(b'&'):
            name, _, value = field.partition(b'=')
            yield unquote_to_bytes(value.replace(b'+', b' ')), {
                'field_name': unquote_to_bytes(name.replace(b'+', b' ')).decode('utf-8', 'replace'),
                'artifact_kind': 'form_field',
            }
