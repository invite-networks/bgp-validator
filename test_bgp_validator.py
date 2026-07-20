def test_module_imports() -> None:
    import bgp_validator

    assert hasattr(bgp_validator, "app")
