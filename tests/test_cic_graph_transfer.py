import torch

from scripts.lab.run_cic_vapd_graph_transfer import initialize_full


def test_transfer_initializes_only_graph_encoder():
    control = initialize_full(38, None)
    pretrained = {name: torch.full_like(value, 0.75)
                  for name, value in control.graph_encoder.state_dict().items()}

    transferred = initialize_full(38, pretrained)

    for name, value in transferred.state_dict().items():
        expected = pretrained[name.removeprefix("graph_encoder.")] if name.startswith("graph_encoder.") else control.state_dict()[name]
        assert torch.equal(value, expected), name
