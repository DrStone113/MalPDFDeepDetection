"""Expose byte-raster geometry, retention and evidence without page rendering."""

from copy import deepcopy

from malpdf.extraction.contracts import feature


def append_byte_images(profile,digest,records,features,edges):
    from malpdf.extraction.normalize import _record
    analysis=profile.get('byte_images') or {}
    if not analysis: return
    if analysis.get('document_sha256')!=digest:
        raise ValueError('byte_image_export_document_mismatch')
    ids={record['evidence_id']:record for record in records}
    storage={item['sha256']:item for item in (profile.get('raw_stream_storage') or {}).get('records',[])}
    summary_id='byte-images:'+str(digest)
    summary={key:deepcopy(value) for key,value in analysis.items() if key not in {'sources','tiles'}}
    matched={source['id']:source for source in analysis.get('sources',[]) if source['source_ref'] in ids}
    summary.update(matched_source_views=len(matched),unmatched_source_views=len(analysis.get('sources',[]))-len(matched),
                   persisted_image_tiles=0,verified_unpersisted_image_tiles=0,unavailable_image_tiles=0)
    records.append(_record(summary_id,'byte_image_analysis','byte_raster','partial',details=summary))
    for source in matched.values():
        details=deepcopy(source)
        recovered=source['is_synthetic_repaired'] or ids[source['source_ref']]['is_synthetic_repaired']
        details['is_synthetic_repaired']=recovered
        records.append(_record(source['id'],'byte_image_source','byte_raster',source['status'],details=details,
            object_number=source['object_number'],generation=source['generation'],is_synthetic_repaired=recovered,
            byte_offset_start=source['source_byte_start'] if source['source_space']=='original_bytes' else None,
            byte_offset_end=source['source_byte_end'] if source['source_space']=='original_bytes' else None))
        edges.append({'id':source['id']+':source','source':source['source_ref'],'target':source['id'],
                      'kind':'byte_raster_source_view','status':'derived'})
        ids[source['id']]=records[-1]
    persisted={source:0 for source in matched}
    for tile in analysis.get('tiles',[]):
        source=matched.get(tile['source_id'])
        if source is None: continue
        if tile['id'] in ids: raise ValueError('byte_image_duplicate_identity')
        details=deepcopy(tile)
        state=details.get('artifact')
        parent=storage.get((state or {}).get('sha256'))
        verified=parent['status'] if parent is not None else 'unverified'
        if state is not None: state['parent_verification_status']=verified
        available=verified=='verified' and state is not None and state['status']=='retained'
        not_persisted=verified=='verified_not_persisted' and state is not None and state['status']=='retained'
        details['image_availability']='persisted' if available else 'verified_not_persisted' if not_persisted else 'unavailable'
        summary['persisted_image_tiles']+=int(available)
        summary['verified_unpersisted_image_tiles']+=int(not_persisted)
        summary['unavailable_image_tiles']+=int(not available and not not_persisted)
        if available: persisted[source['id']]+=tile['valid_pixels']
        recovered=ids[source['id']]['is_synthetic_repaired']
        records.append(_record(tile['id'],'byte_image_tile','byte_raster',tile['status'],details=details,
            object_number=source['object_number'],generation=source['generation'],is_synthetic_repaired=recovered,
            byte_offset_start=tile['original_file_byte_start'],
            byte_offset_end=tile['original_file_byte_start']+tile['valid_pixels'] if tile['original_file_byte_start'] is not None else None))
        ids[tile['id']]=records[-1]
        edges.append({'id':tile['id']+':source','source':source['id'],'target':tile['id'],
                      'kind':'byte_raster_tile','status':'derived'})
        for name in ('valid_pixels','padding_pixels','byte_entropy'):
            value=tile.get(name)
            features.append(feature(tile['id']+':'+name,'raw_layout',value,
                'partial' if value is not None else 'resource_limit',[tile['id']],
                'one raw-byte tile; valid pixels exclude padding; not a PDF page image',tile['reason_codes']))
    for source in matched.values():
        for name,value in (('source_size_bytes',source['source_size_bytes']),
                           ('encoded_source_bytes',source['encoded_source_bytes']),
                           ('worker_retained_source_bytes',source['retained_source_bytes']),
                           ('persisted_source_bytes',persisted[source['id']])):
            features.append(feature(source['id']+':'+name,'raw_layout',value,'partial',[source['id']],
                'one source view; views can overlap and cannot be summed into file coverage',source['reason_codes']))
        if source['kind']=='file_bytes':
            size=source['source_size_bytes']
            for name,count in (('encoded',source['encoded_source_bytes']),('persisted',persisted[source['id']])):
                features.append(feature('byte_image_file_'+name+'_ratio','raw_layout',count/size if size else None,
                    'partial',[source['id']],'fraction of original file bytes represented by whole tiles; no resizing or inferred unobserved coverage'))
    for name in ('matched_source_views','persisted_image_tiles','verified_unpersisted_image_tiles','unavailable_image_tiles'):
        features.append(feature('byte_image_'+name,'raw_layout',summary[name],'partial',[summary_id],
            'counts/lower bounds in the admitted byte-raster supplement; not page-render or format coverage',analysis.get('reason_codes',[])))
