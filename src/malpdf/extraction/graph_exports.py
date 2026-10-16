"""Directed multigraph wire data and optional tensor indices; no PDF operations."""

from copy import deepcopy

from malpdf.extraction.contracts import validate_bundle
from malpdf.extraction.tabular import digest


def node_link_data(bundle,*,bundle_index=0,export_id=None):
    """NetworkX node-link shape, with explicit 'edges' and unmodified records."""
    validate_bundle(bundle)
    if type(bundle_index) is not int or not 0<=bundle_index<2**63:
        raise ValueError('export_bundle_index')
    if export_id is not None and (not isinstance(export_id,str) or not 0<len(export_id)<=128):
        raise ValueError('export_run_id')
    nodes=bundle['evidence_store']['records'];edges=bundle['evidence_store']['edges']
    return {'directed':True,'multigraph':True,
        'graph':{'schema_version':'pdf-evidence-graph-v1','export_id':export_id,'bundle_index':bundle_index,
            'bundle_id':f'bundle_{bundle_index:06d}','bundle_sha256':digest(bundle),
            'sample_sha256':bundle['sample_sha256'],'extraction_profile':bundle['extraction_profile'],
            'observation_status':bundle['status'],'whole_document_complete':bundle['coverage_report']['whole_document_complete']},
        'nodes':[{'id':node['evidence_id'],'index':i,'record':deepcopy(node)} for i,node in enumerate(nodes)],
        'edges':[{'source':edge['source'],'target':edge['target'],'key':edge['id'],'index':i,'record':deepcopy(edge)}
                 for i,edge in enumerate(edges)]}


def graph_tensors(bundle,*,bundle_index=0,export_id=None):
    """PyG/DGL-compatible COO plus explicit isolates, ordering and identities.

    No features/labels are inferred, categorical values encoded, or graphs
    coalesced. PyG and DGL themselves are not dependencies or invoked here.
    """
    import torch
    graph=node_link_data(bundle,bundle_index=bundle_index,export_id=export_id)
    nodes={node['id']:i for i,node in enumerate(graph['nodes'])}
    edges=graph['edges']
    index=torch.tensor([[nodes[e['source']] for e in edges],[nodes[e['target']] for e in edges]],dtype=torch.int64)
    return {'edge_index':index.reshape(2,-1),'num_nodes':len(nodes),
        'node_ids':[n['id'] for n in graph['nodes']],'edge_ids':[e['key'] for e in edges],
        'node_records':[n['record'] for n in graph['nodes']],'edge_records':[e['record'] for e in edges],
        'graph':graph['graph']}
