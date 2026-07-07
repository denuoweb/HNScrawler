from hns_topology.ns_handoff import nameserver_hns_root, normalize_nameserver


def test_normalize_nameserver_strips_case_and_trailing_root_dot():
    assert normalize_nameserver("NS1.SkyInclude.") == "ns1.skyinclude"
    assert normalize_nameserver(" ns2.SKYINCLUDE.. ") == "ns2.skyinclude"


def test_nameserver_hns_root_uses_rightmost_label():
    assert nameserver_hns_root("ns1.skyinclude.") == "skyinclude"
    assert nameserver_hns_root("ns1.external.example.") == "example"
    assert nameserver_hns_root("") == ""
