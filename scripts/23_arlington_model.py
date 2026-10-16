"""Verify the locked offline Arlington reference, optionally with benign fixtures."""

import argparse
from collections import Counter
from dataclasses import asdict
from io import BytesIO
import json
import os
from pathlib import Path
import re

for name in ('OPENBLAS_NUM_THREADS','OMP_NUM_THREADS','MKL_NUM_THREADS'):
    os.environ[name]='1'


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('verify','smoke'))
    parser.add_argument('--lock',default='configs/arlington.lock.json')
    args=parser.parse_args()
    root=Path(__file__).resolve().parents[1]
    from malpdf.extraction.arlington_model import load_model
    from malpdf.extraction.orchestrator import extract_pdf
    from malpdf.extraction.jobs import fingerprint
    from malpdf.provenance.research_runs import ResearchRun,write_json
    from malpdf.static.code_inspector import CodeInspectionLimits
    method={'protocol':'Arlington dependency verification and benign synthetic static fixtures',
        'seed':42,'lock':args.lock,'test_access':False,'dataset_access':False,
        'pdf_content_executed':False,'rendering_performed':False,'fitting':False}
    with ResearchRun(root,'arlington_model_verify',method,maintenance=True) as run:
        catalog=load_model(root,args.lock)
        limits=CodeInspectionLimits(wall_seconds=20,cpu_seconds=12)
        functions=Counter(fn for rows in catalog.tables.values() for row in rows
            for column,text in row.items() if column in {'Type','SinceVersion','Required','IndirectReference','DefaultValue','PossibleValues','SpecialCase','Link'}
            for fn in re.findall(r'fn:([A-Za-z0-9_]+)\(',text))
        verification={'model':catalog.provenance,'code_fingerprint':fingerprint(root,limits,args.lock),
            'predicate_occurrences':dict(sorted(functions.items())),
            'fixture_results':[],'real_pdf_analyzed':False,'test_access':False,
            'interpretation':'All TSV checksums verified; synthetic checks do not establish corpus coverage or complete Arlington conformance.'}
        write_json(run.artifacts/'reference_verification_initial.json',verification)
        if args.action=='smoke':
            from pypdf import PdfWriter
            from pypdf.generic import NameObject,NumberObject
            for name in ('blank_page','wrong_catalog_type','direct_pages','unknown_key'):
                writer=PdfWriter(); writer.add_blank_page(width=100,height=100)
                if name=='wrong_catalog_type': writer.root_object[NameObject('/Type')]=NameObject('/BenignWrongType')
                if name=='direct_pages': writer.root_object[NameObject('/Pages')]=writer.root_object['/Pages']
                if name=='unknown_key': writer.root_object[NameObject('/ArlingtonBenignCanary')]=NumberObject(7)
                stream=BytesIO(); writer.write(stream)
                path=run.artifacts/(name+'.pdf'); path.write_bytes(stream.getvalue())
                bundle=extract_pdf(path,boundary=run.artifacts,limits=limits,arlington_lock=args.lock,repository_root=root)
                write_json(run.artifacts/(name+'.json'),bundle)
                analysis=next((r['details'] for r in bundle['evidence_store']['records'] if r['kind']=='arlington_analysis'),{})
                checks=[r['details'] for r in bundle['evidence_store']['records'] if r['kind']=='arlington_rule_check']
                def found(model,key,category,result):
                    return any(c['model_table']==model and c.get('key')==key and c['category']==category and c['outcome']==result for c in checks)
                assertions={'model_available':analysis.get('model',{}).get('status')=='available',
                    'locked_model_used':analysis.get('model',{}).get('commit')==catalog.provenance['commit'],
                    'rule_pass_finished':analysis.get('complete') is True,
                    'requested_limits_match':bundle['coverage_report']['provenance']['requested_limits']==asdict(limits),
                    'size_rule_pass':found('FileTrailer','Size','possible_values','pass'),
                    'unsupported_context_explicit':any(c['outcome']=='indeterminate' for c in checks),
                    'worker_cleaned':bundle['coverage_report']['worker']['worker_cleanup_complete'] is True,
                    'whole_pdf_not_claimed':bundle['coverage_report']['whole_document_complete'] is False}
                if name=='wrong_catalog_type': assertions['wrong_type_detected']=found('Catalog','Type','possible_values','fail')
                if name=='direct_pages': assertions['required_indirect_detected']=found('Catalog','Pages','indirect','fail')
                if name=='unknown_key': assertions['unknown_key_preserved']=any(c['category']=='unknown_key' for c in checks)
                row={'fixture':name,'assertions':assertions,'checks':len(checks),
                     'outcomes':dict(Counter(c['outcome'] for c in checks)),
                     'analysis_status':analysis.get('status'),'analysis_complete':analysis.get('complete')}
                verification['fixture_results'].append(row)
                write_json(run.artifacts/(name+'_verification.json'),row)
                if not all(assertions.values()): raise ValueError('Arlington synthetic verification failed: '+name)
        # Reference hashes are public dependency data; all PDF evidence is synthetic
        # and stays private in ignored runtime storage.
        write_json(run.report/'arlington_verification.json',verification)
        run.state.update(status='completed',tsv_count=catalog.provenance['tsv_count'],
            arlington_commit=catalog.provenance['commit'],fixtures=len(verification['fixture_results']),
            notes='Locked public Arlington model verified; only generated benign fixtures, no real PDFs/Test. Metrics N/A; no classifier evaluated.')
    print(json.dumps(run.state,indent=2,allow_nan=False))


if __name__=='__main__':
    main()
