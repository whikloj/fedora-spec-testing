#!/bin/env python3

import requests
import pytest
import re

#baseurl = "http://127.0.0.1:8080/rest"
#username = "fedoraAdmin"
#password = "fedoraAdmin"

PAYLOAD_HEADERS = ['Content-Length', 'Content-Range', 'Trailer', 'Transfer-Encoding'] # Via RFC 7231 3.3


def pytest.apytest_addopts(parser):
    parser.addoption("--baseurl", dest="baseurl", action="store", help="Root URL of Fedora instance")
    parser.addoption("--username", dest="username", action="store", help="Username if required")
    parser.addoption("--password", dest="password", action="store", help="Password if required")


@pytest.fixture(scope='module')
def baseurl(request):
    return request.config.getoption("--baseurl", "http://127.0.0.1:8080/rest")


@pytest.fixture(scope='module')
def username(request):
    return request.config.getoption("--username", None)


@pytest.fixture(scope='module')
def password(request):
    return request.config.getoption("--password", None)


def pytest_collection_modifyitems(config, items):
    baseurl = config.getoption("--baseurl", "http://127.0.0.1:8080/rest")
    username = config.getoption("--username", None)
    password = config.getoption("--password", None)
    if 'DELETE' not in requests.head(baseurl, auth=(username, password)).headers['Allow']:
        support_delete = pytest.mark.skip(reason='3.7 DELETE: (OPTIONAL) Delete method not supported')
        for item in items:
            if "support_delete" not in item.keywords:
                item.add_marker(support_delete)


@pytest.fixture(scope='module')
def nodes(baseurl, username, password):
    """Ensures ROOT is accessible and nodes are deleted after testing"""
    # Ensure ROOT is accessible.
    r = requests.get(baseurl, auth=(username, password))

    if r.status_code == 403:
        print("\nReceived a 403 on Fedora base url, you might need to define --username and --password\n")
        quit()

    assert r.status_code == 200, 'Fedora root not found. Is Fedora running at the ROOT url?'

    nodes = set()
    yield nodes

    for node in nodes:
        requests.delete(node)
        requests.delete(node + '/fcr:tombstone')


@pytest.fixture(scope='module')
def files():
    """Provides a file for LDP-NR tests"""
    with open('./image.jpg', 'rb') as image:
        yield {'file': image}


# POST
def test_create_ldpc(nodes):
    body = "".join(["@prefix ldp: <http://www.w3.org/ns/ldp#> .",
                    "@prefix dcterms: <http://purl.org/dc/terms/> .",
                    "<> a ldp:Container, ldp:BasicContainer;",
                    "dcterms:title 'Container class Container' ;",
                    "dcterms:description 'This is a test container for the Fedora API Test Suite.' ."])
    headers = {"Content-Type" : "text/turtle", "Link": "<http://www.w3.org/ns/ldp#BasicContainer>; rel=\"type\"",
               "Slug": "Container-3.1.1-A"}

    r = requests.post(baseurl, body, None, headers=headers, auth=(username, password))

    assert r.status_code == 201, '3.1.1 POST: Error creating an LDPC'


def test_create_ldp_rs(nodes):
    # Can create an LDP-RS with POST
    r = requests.post(baseurl, auth=(username, password))
    assert r.status_code == 201, '3.3 POST: Error creating an LDP-RS'
    nodes.add(r.headers['Location'])

    # Defaults are advertised in the constraints
    constraints_match = re.search('<(\S+)>; ?rel="http://www.w3.org/ns/ldp#constrainedBy"', r.headers['Link'])
    assert constraints_match is not None, '3.3 POST: Constraints link missing when creating an LDP-RS'
    # group(1) is the captured group (\S+)
    constraints = requests.get(constraints_match.group(1))
    assert 'interaction model' in constraints.text and 'default' in constraints.text, '3.3 POST: Default interaction model may be missing from constraints'

def test_create_ldp_nr(nodes, files):
    # Can create an LDP-NR with POST
    r = requests.post(baseurl, files=files)
    assert r.status_code == 201, '3.3 POST: Error creating an LDP-NR'
    nodes.add(r.headers['Location'])

    # Defaults are advertised in the constraints
    constraints_match = re.search('<(\S+)>; ?rel="http://www.w3.org/ns/ldp#constrainedBy"', r.headers['Link'])
    assert constraints_match is not None, '3.3 POST: Constraints link missing when creating an LDP-NR'
    # group(1) is the captured group (\S+)
    constraints = requests.get(constraints_match.group(1))
    assert 'interaction model' in constraints.text and 'default' in constraints.text, '3.3 POST: Default interaction model may be missing from constraints'

def test_describe_ldp_nr(nodes, files):
    # Can create an LDP-NR with POST
    r = requests.post(baseurl, files=files)
    assert r.status_code == 201, '3.3 POST: Error creating an LDP-NR'
    nodes.add(r.headers['Location'])

    # Creating an LDP-NR returns the LDP-RS that describes it
    describes_match = re.search('<(\S+)>; ?rel="describedby"', r.headers['Link'])
    assert describes_match is not None, '3.3 POST: Link to LDP-RS describing new LDP-NR missing'
    # group(1) is the captured group (\S+)
    describes = requests.get(describes_match.group(1))
    assert describes.status_code == 200, '3.3 POST: LDP-RS describing new LDP-NR was linked, but not created'
    assert re.search('<'+r.headers['Location']+'>; ?rel="describes"', describes.headers['Link']) is not None, '3.5 GET: LDP-RS does not link to the LDP-NR it describes'
    # TODO: Assert it has type ldp#RDFSource

def test_bad_digest(nodes, files):
    # LDP-NR with bad digest value returns 409
    r = requests.post(baseurl, files=files, headers={'digest': 'md5=deadbeef'})
    assert r.status_code == 409, '3.3.1 POST: Creating LDP-NR with bad digest value should return 409'
    if r.status_code == 201:
        nodes.add(r.headers['Location'])

def test_bad_algo(nodes, files):
    # LDP-NR with bad digest algorithm returns 400
    # TODO: How to query for accepted algorithms?
    r = requests.post(baseurl, files=files, headers={'digest': 'md1=fakealgo'})
    assert r.status_code == 400, '3.3.1 POST: Creating LDP-NR with bad digest algorithm should return 400'
    if r.status_code == 201:
        nodes.add(r.headers['Location'])

# GET
def test_representation(nodes):
    # Setup: Create LDP-RS
    r = requests.post(baseurl)
    r.raise_for_status
    ldp_rs = r.headers['Location']
    nodes.add(ldp_rs)

    # LDP-RS responds to the Prefer header
    # TODO: How to query for Prefer header values?
    # TODO: Preference-Applied header always returned.
    r = requests.get(ldp_rs, headers={'Prefer': 'return=representation'})
    assert r.headers['Preference-Applied'] == 'return=representation', '3.5.2 GET: Preference-Applied header missing from response'
    r = requests.get(ldp_rs, headers={'Prefer': 'return=minimal'})
    assert r.headers['Preference-Applied'] == 'return=minimal', '3.5.2 GET: Preference-Applied header missing from response'

def test_contained_desc(nodes):
    # Setup: Create LDP-RSs
    r = requests.post(baseurl)
    r.raise_for_status
    parent = r.headers['Location']
    nodes.add(parent)
    r = requests.post(parent)
    r.raise_for_status
    child = r.headers['Location']
    nodes.add(child)

    # LDP-RS returns contained descriptions when asked
    includes = 'include="http://w3.org/ns/oa#PreferContainedDescriptions"'
    r = requests.get(parent, headers={'Prefer': 'return=representation; ' + includes})
    assert re.search('ldp:contains\s*<' + child +'>', r.text) is not None
    assert re.search('fedora:hasParent\s*<' + parent + '>', r.text) is not None, '3.5.1 GET: (MAY) Contained descriptions missing from response'

def test_inbound_refs(nodes):
    # Setup: Create LDP-RSs
    r = requests.post(baseurl)
    r.raise_for_status
    parent = r.headers['Location']
    nodes.add(parent)
    r = requests.post(parent)
    r.raise_for_status
    child = r.headers['Location']
    nodes.add(child)

    # LDP-RS returns inbound references when asked
    includes = 'include="http://fedora.info/definitions/fcrepo#PreferInboundReferences"'
    r = requests.get(child, headers={'Prefer': 'return=representation; ' + includes})
    assert r.status_code == 200
    # TODO: how to test inbound refs?
    assert 0, '3.5.1 GET: (SHOULD) Inbound references missing from response'

def test_want_digest_header(nodes, files):
    # Setup: Create LDP-NR
    r = requests.post(baseurl, files=files)
    r.raise_for_status
    ldp_nr = r.headers['Location']
    nodes.add(ldp_nr)

    # LDP-NR responds to the Want-Digest header.
    r = requests.get(ldp_nr, headers={'Want-Digest': 'md5'})
    assert r.status_code == 200
    assert r.headers['Digest'].startswith('md5='), '3.5.3 GET: Want-Digest header ignored or incorrect response returned'
    r = requests.get(ldp_nr, headers={'Want-Digest': 'sha1'})
    assert r.status_code == 200
    assert r.headers['Digest'].startswith('sha1='), '3.5.3 GET: Want-Digest header ignored or incorrect response returned'

# HEAD
def test_empty_ldp_rs(nodes):
    # Setup
    r = requests.post(baseurl)
    r.raise_for_status
    ldp_rs = r.headers['Location']
    nodes.add(ldp_rs)

    # Head request has no body
    head = requests.head(ldp_rs)
    assert head.status_code == 200
    assert head.text == '', '3.6 HEAD: Unexpected response body for HEAD request'

def test_no_payload_headers(nodes):
    # Setup
    r = requests.post(baseurl)
    r.raise_for_status
    ldp_rs = r.headers['Location']
    nodes.add(ldp_rs)

    # Head request has no body
    head = requests.head(ldp_rs)
    for payload_header in PAYLOAD_HEADERS:
        assert payload_header not in head.headers.keys(), '3.6 HEAD: (MAY) Payload header "' + payload_header + '" not ommitted'

def test_same_headers(nodes):
    # Setup
    r = requests.post(baseurl)
    r.raise_for_status
    ldp_rs = r.headers['Location']
    nodes.add(ldp_rs)

    head = requests.head(ldp_rs)
    get = requests.get(ldp_rs)
    # Collect the headers from the HEAD request, without the payload headers.
    head_keys = {key for key in head.headers.keys()}.difference(PAYLOAD_HEADERS)
    # Collect the headers from the GET request, without the payload headers.
    get_keys = {key for key in get.headers.keys()}.difference(PAYLOAD_HEADERS)
    assert head_keys == get_keys, '3.6 HEAD: (SHOULD) Headers for a HEAD request should match the headers for a GET request'

def test_empty_ldp_nr(nodes, files):
    # Setup
    r = requests.post(baseurl, files=files)
    r.raise_for_status
    ldp_nr = r.headers['Location']
    nodes.add(ldp_nr)

    head = requests.head(ldp_nr)
    assert head.status_code == 200
    assert head.text == '', '3.6 HEAD: Unexpected response body for HEAD request'

def test_head_digest(nodes, files):
    # Setup
    r = requests.post(baseurl, files=files)
    r.raise_for_status
    ldp_nr = r.headers['Location']
    nodes.add(ldp_nr)

    # First without Want-Digest
    head = requests.head(ldp_nr)
    get = requests.get(ldp_nr)
    assert ('Digest' in head.headers.keys()) == ('Digest' in get.headers.keys()), '3.6 HEAD: Presence of Digest header must be the same in HEAD and GET requests'

    # Now with Want-Digest
    head = requests.head(ldp_nr, headers={'Want-Digest': 'md5'})
    get = requests.get(ldp_nr, headers={'Want-Digest': 'md5'})
    assert ('Digest' in head.headers.keys()) == ('Digest' in get.headers.keys()), '3.6 HEAD: Presence of Digest header must be the same in HEAD and GET requests'

# PUT

# PATCH

"""
 DELETE
"""
@pytest.mark.support_delete
def test_depth_zero(nodes):
    # Setup
    r = requests.post(baseurl)
    r.raise_for_status
    parent = r.headers['Location']
    nodes.add(parent)
    r = requests.post(parent)
    r.raise_for_status
    child = r.headers['Location']
    nodes.add(child)

    # Support deletion with depth of zero
    # TODO: How to query for supported or default Depth values?
    r = requests.delete(parent, headers={'Depth': '0'})
    assert r.status_code == 204, '3.7.1 DELETE: Depth: 0 not supported'
    r = requests.get(parent)
    assert r.status_code == 410
    r = requests.get(child)
    assert r.status_code == 200, '3.7.1 DELETE: Depth:0 should delete the resource only'


@pytest.mark.support_delete
def test_depth_infinity(nodes):
    # Setup
    r = requests.post(baseurl)
    r.raise_for_status
    parent = r.headers['Location']
    nodes.add(parent)
    r = requests.post(parent)
    r.raise_for_status
    child = r.headers['Location']
    nodes.add(child)
    r = requests.post(child)
    r.raise_for_status
    grandchild = r.headers['Location']
    nodes.add(grandchild)

    # Support deletion with depth of infinity
    r = requests.delete(parent, headers={'Depth': 'infinity'})
    assert r.status_code == 204, '3.7.1 DELETE: Depth: infinity not supported'
    r = requests.get(parent)
    assert r.status_code == 410
    r = requests.get(grandchild)
    assert r.status_code == 410


@pytest.mark.support_delete
def test_unsupported_depth(nodes):
    # Setup
    r = requests.post(baseurl)
    r.raise_for_status
    ldp_rs = r.headers['Location']
    nodes.add(ldp_rs)

    # Bad Depth value returns 400
    r = requests.delete(ldp_rs, headers={'Depth': 'forfty'})
    assert r.status_code == 400, '3.7.1 DELETE: Using an unsupported Depth value should return 440'
