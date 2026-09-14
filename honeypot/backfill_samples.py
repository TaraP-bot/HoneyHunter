#!/usr/bin/env python3
"""Index existing sample files without running the honeypot or modifying them."""
import argparse
import asyncio
import hashlib
import json
import logging
from pathlib import Path

from core.sample_index import SampleIndexer, TEXT_BYTE_LIMIT, sample_document


def document_from_file(path):
    digest = hashlib.sha256()
    prefix = bytearray()
    size = 0
    with path.open('rb') as sample:
        while True:
            chunk = sample.read(65536)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
            if len(prefix) < TEXT_BYTE_LIMIT:
                prefix.extend(chunk[:TEXT_BYTE_LIMIT - len(prefix)])
    if digest.hexdigest() != path.stem:
        raise ValueError('sample contents do not match SHA-256 filename')
    metadata = {}
    sidecar = path.with_suffix('.json')
    if sidecar.exists():
        metadata = json.loads(sidecar.read_text())
        if not isinstance(metadata, dict):
            raise ValueError('metadata must be a JSON object')
    return sample_document(bytes(prefix), metadata, digest.hexdigest(), size)


async def backfill(directory, indexer):
    counts = {'indexed': 0, 'existing': 0, 'failed': 0}
    for path in directory.glob('*.bin'):
        try:
            document = document_from_file(path)
            created = await indexer.index_document(document)
            counts['indexed' if created else 'existing'] += 1
        except Exception as exc:
            counts['failed'] += 1
            logging.error('Could not index %s: %s', path.name, exc)
    return counts


async def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, default=Path('honeypot_config.json'))
    parser.add_argument('--samples-dir', type=Path)
    parser.add_argument('--host', help='Override Elasticsearch host from config')
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    directory = args.samples_dir or Path(config.get('output_dir', './honeypot_data')) / 'samples'
    if not directory.is_dir():
        parser.error(f'Samples directory does not exist: {directory}')
    hosts = [args.host] if args.host else config.get('elasticsearch', {}).get('hosts', ['http://localhost:9200'])
    from elasticsearch import AsyncElasticsearch
    async with AsyncElasticsearch(hosts) as client:
        indexer = SampleIndexer(client)
        await indexer.ensure_index()
        counts = await backfill(directory, indexer)
    print(json.dumps(counts))
    return 1 if counts['failed'] else 0


if __name__ == '__main__':
    raise SystemExit(asyncio.run(main()))
