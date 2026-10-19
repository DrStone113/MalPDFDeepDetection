"""Link recursive child facts to the root bundle without merging PDF identities."""

from copy import deepcopy

from malpdf.extraction.contracts import feature


def append_artifacts(profile, digest, records, features, edges):
    from malpdf.extraction.normalize import _record, normalize_profile

    carving = profile.get('carving') or {}
    if not carving:
        return
    if carving.get('document_sha256') != digest:
        raise ValueError('artifact_root_identity_mismatch')
    artifacts = {entry['id']: entry for entry in carving['records']}
    if len(artifacts) != len(carving['records']):
        raise ValueError('duplicate_artifact_identity')
    ids = {record['evidence_id'] for record in records}
    storage = {item['sha256']: item for item in (profile.get('raw_stream_storage') or {}).get('records', [])}
    def verified_retention(value):
        if isinstance(value, list):
            for item in value:
                verified_retention(item)
        elif isinstance(value, dict):
            if 'sha256' in value and 'size_bytes' in value and 'status' in value:
                parent = storage.get(value['sha256'])
                value['parent_verification_status'] = parent['status'] if parent else 'unverified'
            for item in list(value.values()):
                if isinstance(item, (dict, list)):
                    verified_retention(item)
    imported = set()
    for identifier, analysis in carving.get('analyses', {}).items():
        artifact = artifacts.get(identifier)
        if artifact is None:
            raise ValueError('artifact_analysis_identity_missing')
        if artifact['kind'] != 'pdf' or not analysis.get('layout'):
            continue
        child_digest = artifact['sha256']
        if child_digest == digest or child_digest in imported:
            raise ValueError('recursive_pdf_identity_alias')
        child = {'status': analysis.get('status', 'partial'), 'errors': analysis.get('errors', []),
            'raw_layout': analysis['layout'], 'static': analysis.get('static'), 'code': analysis.get('code'),
            'analysis_v9': analysis.get('analysis_v9'), 'stream_analysis': analysis.get('stream_analysis'),
            'raw_stream_storage': profile.get('raw_stream_storage')}
        bundle = normalize_profile(child, child_digest, 'deep-static')
        for record in bundle['evidence_store']['records']:
            if record['evidence_id'] in ids:
                raise ValueError('child_evidence_identity_collision')
            ids.add(record['evidence_id'])
            record['is_synthetic_repaired'] = record['is_synthetic_repaired'] or artifact['is_synthetic_repaired']
            records.append(record)
        edges.extend(bundle['evidence_store']['edges'])
        coverage_id = 'child-coverage:' + child_digest
        records.append(_record(coverage_id, 'artifact_pdf_coverage', 'recursive_carver', bundle['status'],
                               details=bundle['coverage_report'], is_synthetic_repaired=artifact['is_synthetic_repaired']))
        ids.add(coverage_id)
        for record in bundle['feature_store']['records']:
            copy = deepcopy(record)
            copy['feature_name'] = 'child:' + child_digest + ':' + record['feature_name']
            copy['scope'] = 'child PDF ' + child_digest + '; ' + record['scope']
            features.append(copy)
        imported.add(child_digest)
    summary_id = 'artifact-analysis:' + digest
    summary = {key: value for key, value in carving.items() if key not in {'records', 'analyses'}}
    records.append(_record(summary_id, 'artifact_analysis', 'recursive_carver', carving['status'], details=summary))
    ids.add(summary_id)
    for entry in carving['records']:
        if entry['id'] in ids:
            raise ValueError('artifact_evidence_identity_collision')
        ids.add(entry['id'])
        details = deepcopy(entry)
        analysis = carving.get('analyses', {}).get(entry['id'])
        if analysis and entry['kind'] != 'pdf':
            details['analysis'] = deepcopy(analysis)
        verified_retention(details)
        records.append(_record(entry['id'], 'artifact', 'recursive_carver', entry['status'], details=details,
            is_synthetic_repaired=entry['is_synthetic_repaired']))
    for entry in carving['records']:
        if entry['parent_id'] not in ids:
            raise ValueError('artifact_parent_evidence_missing')
        if entry['container_id'] is not None and entry['container_id'] not in artifacts:
            raise ValueError('artifact_container_evidence_missing')
        edges.append({'id': entry['id'] + ':parent', 'source': entry['parent_id'], 'target': entry['id'],
                      'kind': 'artifact_lineage', 'status': 'verified'})
        if entry['reused_from_id']:
            original = artifacts.get(entry['reused_from_id'])
            if original is None or original['sha256'] != entry['sha256'] or original['kind'] != entry['kind']:
                raise ValueError('artifact_reuse_identity_mismatch')
            edges.append({'id': entry['id'] + ':reuse', 'source': entry['reused_from_id'], 'target': entry['id'],
                          'kind': 'same_artifact_content', 'status': 'verified'})
        if entry['kind'] == 'pdf' and entry['sha256'] in imported:
            edges.append({'id': entry['id'] + ':document', 'source': entry['id'], 'target': 'original:' + entry['sha256'],
                          'kind': 'artifact_document', 'status': 'verified'})
            edges.append({'id': entry['id'] + ':coverage', 'source': entry['id'], 'target': 'child-coverage:' + entry['sha256'],
                          'kind': 'artifact_pdf_coverage', 'status': 'verified'})
        features.append(feature(entry['id'] + ':size_bytes', 'embedded_artifacts', entry['size_bytes'],
            'observed', [entry['id']], 'complete admitted artifact byte span; does not prove format validity or maliciousness', complete=True))
    for identifier, analysis in carving.get('analyses', {}).items():
        artifact = artifacts[identifier]
        if analysis.get('format'):
            _media_features(identifier, analysis, artifact, features)
        if analysis.get('ast'):
            _ast_features(identifier, analysis, records, features, edges, ids)
        for row in analysis.get('zip_members', []):
            member_id = identifier + ':zip-member:' + str(row['index'])
            details = deepcopy(row)
            verified_retention(details)
            records.append(_record(member_id, 'zip_member', 'recursive_carver', row['status'], details=details,
                                   is_synthetic_repaired=artifact['is_synthetic_repaired']))
            ids.add(member_id)
            edges.append({'id': member_id + ':parent', 'source': identifier, 'target': member_id,
                          'kind': 'archive_member_metadata', 'status': 'verified'})
            features.append(feature(member_id + ':decoded_bytes', 'embedded_artifacts',
                row.get('observed_prefix_bytes') if row['status'] == 'observed' else None,
                'observed' if row['status'] == 'observed' else row['status'], [member_id],
                'one stored/deflated ZIP member after size/CRC validation; unavailable members stay null',
                row.get('reason_codes', []), complete=row['status'] == 'observed'))
        for index, script in enumerate(analysis.get('scripts', [])):
            script_id = script.get('id', identifier + ':xml-script:' + str(index))
            records.append(_record(script_id, 'artifact_xml_script', 'recursive_carver', script['status'], details=script,
                                   is_synthetic_repaired=artifact['is_synthetic_repaired']))
            ids.add(script_id)
            edges.append({'id': script_id + ':parent', 'source': identifier, 'target': script_id,
                          'kind': 'artifact_script_source', 'status': 'verified'})
            if (script.get('analysis') or {}).get('ast'):
                _ast_features(script_id, script['analysis'], records, features, edges, ids)
        for index, member in enumerate(analysis.get('members', [])):
            member_id = member.get('id', identifier + ':object:' + str(index))
            records.append(_record(member_id, 'object_stream_member', 'recursive_carver', member['status'], details=member,
                object_number=member['object_number'], generation=0, is_synthetic_repaired=artifact['is_synthetic_repaired']))
            ids.add(member_id)
            edges.append({'id': member_id + ':parent', 'source': identifier, 'target': member_id,
                          'kind': 'object_stream_source', 'status': 'verified'})
            if (member.get('script') or {}).get('analysis'):
                _ast_features(member_id, member['script']['analysis'], records, features, edges, ids)
    for kind in sorted({entry['kind'] for entry in carving['records']}):
        features.append(feature('observed_artifact_kind_' + kind, 'embedded_artifacts',
            sum(entry['kind'] == kind for entry in carving['records']), 'partial', [summary_id],
            'observed recognized/declared candidate occurrences; unrecognized streams are not proved absent'))


def _ast_features(source, analysis, records, features, edges, ids):
    for name in ('node_count', 'max_depth', 'loops', 'computed_members'):
        value = analysis['ast'].get(name)
        if type(value) is int:
            features.append(feature(source + ':artifact_ast:' + name, 'javascript_xfa', value,
                'observed', [source], 'one artifact script syntax tree; no execution or activation proof', complete=True))
    reuse = analysis.get('reused_from_evidence_id')
    if reuse and reuse != source:
        edges.append({'id': source + ':syntax-reuse', 'source': reuse, 'target': source,
                      'kind': 'same_decoded_script_syntax', 'status': 'verified'})


def _media_features(source: str, analysis: dict, artifact: dict, features: list) -> None:
    complete = analysis.get('complete') is True
    limitations = sorted(set(analysis.get('reason_codes', [])) | set(artifact['reason_codes']))
    group = 'embedded_artifacts' if analysis['format'] == 'swf' else 'fonts_images_multimedia'
    for name in ('width', 'height', 'components', 'bits_per_component', 'table_count', 'glyph_count',
                 'units_per_em', 'script_tag_count', 'declared_frames', 'instruction_tables_present',
                 'svg_table_present', 'cff_table_present', 'trailing_bytes', 'scan_count'):
        value = analysis.get(name)
        if type(value) not in (int, bool):
            continue
        status = ('absent_within_scope' if value == 0 else 'observed') if complete else 'partial'
        features.append(feature(source + ':media:' + name, group, value, status, [source],
            analysis.get('scope', 'static media metadata only; no execution or rendering'), limitations, complete=complete))
