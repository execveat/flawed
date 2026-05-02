from tools.cfg_idom_benchmark import synthetic_cfg


def test_synthetic_cfg_benchmark_shapes_have_expected_edges() -> None:
    linear_blocks, linear_edges = synthetic_cfg(5, shape="linear")
    diamond_blocks, diamond_edges = synthetic_cfg(5, shape="diamonds")

    assert len(linear_blocks) == 5
    assert [(edge.source_id, edge.target_id) for edge in linear_edges] == [
        (0, 1),
        (1, 2),
        (2, 3),
        (3, 4),
    ]
    assert len(diamond_blocks) == 5
    assert {(edge.source_id, edge.target_id) for edge in diamond_edges} == {
        (0, 1),
        (0, 2),
        (1, 3),
        (2, 3),
        (3, 4),
    }
