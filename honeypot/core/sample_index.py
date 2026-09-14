"""Searchable sample derivatives. Original bytes remain in samples/*.bin."""
import asyncio
import hashlib
import re
from datetime import datetime

SAMPLE_INDEX = 'honeypot-samples'
TEXT_BYTE_LIMIT = 1024 * 1024
MAPPINGS = {
    'dynamic': False,
    'properties': {
        'sha256': {'type': 'keyword'},
        'size': {'type': 'long'},
        'indexed_at': {'type': 'date'},
        'content_text': {'type': 'text'},
        'extraction_method': {'type': 'keyword'},
        'text_truncated': {'type': 'boolean'},
        'bytes_examined': {'type': 'long'},
        'filename': {'type': 'keyword', 'ignore_above': 1024},
        'content_type': {'type': 'keyword', 'ignore_above': 1024},
        'artifact_kind': {'type': 'keyword'},
        'capture_status': {'type': 'keyword'},
        'metadata': {'type': 'object', 'enabled': False},
    },
}


def sample_document(data, metadata, digest=None, size=None):
    """UTF-8 text when plausible; otherwise printable ASCII runs of >=4 bytes.

    Backfill may pass a bounded prefix with a hash/size of the entire file.
    """
    size = len(data) if size is None else size
    prefix = data[:TEXT_BYTE_LIMIT]
    truncated = size > len(prefix)
    try:
        # A prefix may end within a UTF-8 character; don't mistake that for binary.
        import codecs
        text = codecs.getincrementaldecoder('utf-8')('strict').decode(prefix, final=not truncated)
        if any(ord(c) < 32 and c not in '\r\n\t' for c in text):
            raise ValueError('binary controls')
        method = 'utf8'
    except (UnicodeError, ValueError):
        text = '\n'.join(match.group().decode('ascii') for match in re.finditer(rb'[\x20-\x7e]{4,}', prefix))
        method = 'ascii_strings'
    document = {
        'sha256': digest or hashlib.sha256(data).hexdigest(),
        'size': size,
        'indexed_at': datetime.utcnow().isoformat(),
        'content_text': text,
        'extraction_method': method,
        'text_truncated': truncated,
        'bytes_examined': len(prefix),
        'metadata': dict(metadata),
    }
    for name in ('filename', 'content_type', 'artifact_kind', 'capture_status'):
        if isinstance(metadata.get(name), str):
            document[name] = metadata[name]
    return document


def error_status(exc):
    return getattr(exc, 'status_code', getattr(getattr(exc, 'meta', None), 'status', None))


class SampleIndexer:
    def __init__(self, client):
        self.client = client
        self.ready = False
        self.lock = asyncio.Lock()

    async def ensure_index(self):
        async with self.lock:
            if self.ready:
                return
            # Exact, higher-priority template overrides the existing honeypot-* template.
            await self.client.indices.put_index_template(
                name='honeypot_samples_template', index_patterns=[SAMPLE_INDEX],
                priority=500,
                template={'mappings': MAPPINGS, 'settings': {'number_of_shards': 1}},
            )
            if not await self.client.indices.exists(index=SAMPLE_INDEX):
                try:
                    await self.client.indices.create(index=SAMPLE_INDEX, mappings=MAPPINGS)
                except Exception as exc:
                    # Another process may have created it between exists and create.
                    if error_status(exc) != 400 or 'resource_already_exists_exception' not in str(exc):
                        raise
            # Fail visibly on incompatible existing mappings instead of silently
            # indexing source text into an unsearchable field.
            await self.client.indices.put_mapping(index=SAMPLE_INDEX, **MAPPINGS)
            self.ready = True

    async def index_document(self, document):
        await self.ensure_index()
        try:
            await self.client.index(index=SAMPLE_INDEX, id=document['sha256'],
                                    document=document, op_type='create')
            return True
        except Exception as exc:
            if error_status(exc) == 409:
                return False  # Same bytes already indexed; preserve first metadata.
            raise
