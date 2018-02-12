#!/bin/env python3

import requests
import re
import argparse
import unittest
import sys


def support_delete(f):
    """ Decorator to allow optional DELETE tests to be skipped """
    def wrapper(s):
        if 'DELETE' not in requests.head(s.baseurl,
                                         auth=(s.username, s.password)).headers['Allow']:
            print('3.7 DELETE: (OPTIONAL) Delete method not supported')
            return
        f(s)
    return wrapper


class FedoraApiSpecTest(unittest.TestCase):
    baseurl = None
    username = None
    password = None
    self = None
    nodes = []
    # Via RFC 7231 3.3
    PAYLOAD_HEADERS = ['Content-Length', 'Content-Range', 'Trailer', 'Transfer-Encoding']

    JSONLD_MIMETYPE = "application/ld+json"
    SPARQL_UPDATE_MIMETYPE = "application/sparql-update"

    def setUp(self):
        self.not_authorized()

    def not_authorized(self):
        """ Ensure we can even access the repository """
        r = requests.head(self.baseurl, auth=(self.username, self.password))
        if str(r.status_code)[0:2] == '40':
            mesg = "Received a {} status code accessing {}, you may need to provide/check credentials".format(
                r.status_code, self.baseurl)
            print(mesg)
            raise RuntimeError(mesg)

    @staticmethod
    def makeRegistrar(self):
        """ Makes a list of all functions with the decorator """
        registry = {}

        def registrar(func):
            registry[func.__name__] = func
            # normally a decorator returns a wrapped function, but here we return func unmodified, after registering it
            return func
        registrar.all = registry
        return registrar

    def do_post(self, parent=None, headers={}, body=None, files=None):
        if parent is None:
            parent = self.baseurl
        return requests.post(parent, body, None, files=files, headers=headers, auth=(self.username, self.password))

    def do_get(self, url, headers={}):
        return requests.get(url, headers=headers, auth=(self.username, self.password))

    def do_head(self, url, headers={}):
        return requests.head(url, headers=headers, auth=(self.username, self.password))

    def do_patch(self, url, body, headers={}):
        return requests.patch(url, body, headers=headers, auth=(self.username, self.password))

    def do_delete(self, url, headers={}):
        return requests.delete(url, headers=headers, auth=(self.username, self.password))

    def tearDown(self):
        """ Delete any resources created """
        for node in self.nodes:
            r = requests.delete(node, auth=(self.username, self.password))
            if r.status_code == 410 or r.status_code == 204:
                requests.delete(node + '/fcr:tombstone', auth=(self.username, self.password))
        self.nodes.clear()

    """ TESTS """

    def test_create_ldpc(self):
        body = "".join(["@prefix ldp: <http://www.w3.org/ns/ldp#> .",
                        "@prefix dcterms: <http://purl.org/dc/terms/> .",
                        "<> a ldp:Container, ldp:BasicContainer;",
                        "dcterms:title 'Container class Container' ;",
                        "dcterms:description 'This is a test container for the Fedora API Test Suite.' ."])
        headers = {"Content-Type" : "text/turtle", "Link": "<http://www.w3.org/ns/ldp#BasicContainer>; rel=\"type\"",
                   "Slug": "Container-3.1.1-A"}

        r = self.do_post(headers=headers, body=body)
        self.assertEqual(r.status_code, 201, '3.1.1 POST: Error creating an LDPC')
        self.nodes.append(r.headers["Location"])

    def test_distinguish_containment(self):
        body = "".join(["@prefix ldp: <http://www.w3.org/ns/ldp#> .",
                        "<> a ldp:Container, ldp:BasicContainer ." ])
        headers = {"Content-Type": "text/turtle", "Link": "<http://www.w3.org/ns/ldp#BasicContainer>; rel=\"type\""}
        r = self.do_post(headers=headers)
        self.assertEqual(r.status_code, 201)
        basic = r.headers["Location"]
        self.nodes.append(basic)

        headers = {"Content-type": "text/turtle", "Link": "<http://www.w3.org/ns/ldp#IndirectContainer>; rel=\"type\""}
        body = "".join(["<> a <http://www.w3.org/ns/ldp#IndirectContainer>; ",
                       "<http://www.w3.org/ns/ldp#membershipResource> <" + basic + ">; ",
                       "<http://www.w3.org/ns/ldp#hasMemberRelation> <http://www.w3.org/ns/ldp#contains>; ",
                       "<http://www.w3.org/ns/ldp#insertedContentRelation> <http://www.openarchives.org/ore/terms/proxyFor> ."])
        r = self.do_post(parent=basic, body=body, headers=headers)
        if r.status_code == 201:
            indirect = r.headers["Location"]
            self.nodes.append(indirect)

            headers = {"Content-type": "text/turtle"}
            body = "<> <http://www.openarchives.org/ore/terms/proxyFor> <" + self.baseurl + "> ."
            r = self.do_post(parent=indirect, body=body, headers=headers)
            self.nodes.append(r.headers["Location"])

            headers = {"Prefer": "return=representation; omit=\"http://www.w3.org/ns/ldp#PreferContainment\""}
            r = self.do_get(basic, headers=headers)
            # TODO: ensure only ldp:contains /rest is present
            headers = {"Prefer": "return=representation; omit=\"http://www.w3.org/ns/ldp#PreferMembership\""}
            r = self.do_get(basic, headers=headers)
            # TODO: ensure only ldp:contains /rest/basic/indirect is present
            # This is based on suggestions from https://gist.github.com/escowles/e6d09cab84d2c8d8e9042f3f8bcc4f0d
        else:
            self.assertEqual(r.status_code, 409,
                             "3.1.1 If an impl can't distinguish between membership and containment triples, it must " +
                             "fail with 409 to use ldp:contains for membership")

    def test_create_ldp_rs(self):
        # Can create an LDP-RS with POST
        r = self.do_post()
        self.assertEqual(r.status_code, 201, '3.3 POST: Error creating an LDP-RS')
        self.nodes.append(r.headers['Location'])

        # Defaults are advertised in the constraints
        constraints_match = re.search('<(\S+)>; ?rel="http://www.w3.org/ns/ldp#constrainedBy"', r.headers['Link'])
        self.assertIsNotNone(constraints_match, '3.3 POST: Constraints link missing when creating an LDP-RS')
        # group(1) is the captured group (\S+)
        constraints = self.do_get(constraints_match.group(1))
        self.assertTrue('interaction model' in constraints.text and 'default' in constraints.text,
                        '3.3 POST: Default interaction model may be missing from constraints')

    def test_create_ldpnr_with_constraint(self):
        ldpnr_type = "http://www.w3.org/ns/ldp#NonRDFSource; rel=\"type\""
        headers = {"Link": ldpnr_type, "Content-type": "text/turtle"}
        body = "<> a <http://www.w3.org/ns/ldp#Resource> ."

        r = self.do_post(body=body, headers=headers)
        if r.status_code == 201:
            ldpnr = r.headers["Location"]
            self.nodes.append(ldpnr)
            #headers["Accept"] = self.JSONLD_MIMETYPE
            r = self.do_get(ldpnr, headers=headers)
            self.assertTrue(ldpnr_type in r.headers["Link"], '3.1.2 - Did not see type of resource as NonRDFSource')


    def test_create_ldp_nr(self):
        # Can create an LDP-NR with POST
        with open('./image.jpg', 'rb') as image:
            files = {'files' : ('image.jpg', image)}
            r = requests.post(self.baseurl, files=files, auth=(self.username, self.password))
        self.assertEqual(r.status_code, 201, '3.3 POST: Error creating an LDP-NR')
        self.nodes.append(r.headers['Location'])

        # Defaults are advertised in the constraints
        constraints_match = re.search('<(\S+)>; ?rel="http://www.w3.org/ns/ldp#constrainedBy"', r.headers['Link'])
        self.assertIsNotNone(constraints_match, '3.3 POST: Constraints link missing when creating an LDP-NR')
        # group(1) is the captured group (\S+)
        constraints = self.do_get(constraints_match.group(1))
        self.assertTrue('interaction model' in constraints.text and 'default' in constraints.text,
                        '3.3 POST: Default interaction model may be missing from constraints')

    def test_describe_ldp_nr(self):
        # Can create an LDP-NR with POST
        with open('./image.jpg', 'rb') as image:
            files = {'files' : ('image.jpg', image)}
            r = self.do_post(files=files)
        self.assertEqual(r.status_code, 201, '3.3 POST: Error creating an LDP-NR')
        self.nodes.append(r.headers['Location'])

        # Creating an LDP-NR returns the LDP-RS that describes it
        describes_match = re.search('<(\S+)>; ?rel="describedby"', r.headers['Link'])
        self.assertIsNotNone(describes_match, '3.3 POST: Link to LDP-RS describing new LDP-NR missing')
        # group(1) is the captured group (\S+)
        describes = self.do_get(describes_match.group(1))
        self.assertEqual(describes.status_code, 200,
                         '3.3 POST: LDP-RS describing new LDP-NR was linked, but not created')
        self.assertTrue(re.search('<'+r.headers['Location']+'>; ?rel="describes"',
                                  describes.headers['Link']) is not None,
                        '3.5 GET: LDP-RS does not link to the LDP-NR it describes')
        # TODO: Assert it has type ldp#RDFSource

    def test_bad_digest(self):
        with open('./image.jpg', 'rb') as image:
            files = {'files' : ('image.jpg', image)}
        # LDP-NR with bad digest value returns 409
            r = self.do_post(files=files, headers={'digest': 'md5=deadbeef'})
        self.assertEqual(r.status_code, 409, '3.3.1 POST: Creating LDP-NR with bad digest value should return 409')
        if r.status_code == 201:
            self.nodes.append(r.headers['Location'])

    def test_bad_algo(self):
        # LDP-NR with bad digest algorithm returns 400
        with open('./image.jpg', 'rb') as image:
            files = {'files' : ('image.jpg', image)}
        # TODO: How to query for accepted algorithms?
            r = self.do_post(files=files, headers={'digest': 'md1=fakealgo'})
        self.assertEqual(r.status_code, 400, '3.3.1 POST: Creating LDP-NR with bad digest algorithm should return 400')
        if r.status_code == 201:
            self.nodes.append(r.headers['Location'])

    def test_representation(self):
        # Setup: Create LDP-RS
        r = self.do_post()
        self.assertEqual(r.status_code, 201)
        ldp_rs = r.headers['Location']
        self.nodes.append(ldp_rs)

        # LDP-RS responds to the Prefer header
        # TODO: How to query for Prefer header values?
        # TODO: Preference-Applied header always returned.
        r = self.do_get(ldp_rs, headers={'Prefer': 'return=representation'})
        self.assertEqual(r.headers['Preference-Applied'], 'return=representation',
                         '3.5.2 GET: Preference-Applied header missing from response')
        r = self.do_get(ldp_rs, headers={'Prefer': 'return=minimal'})
        self.assertEqual(r.headers['Preference-Applied'] == 'return=minimal',
                         '3.5.2 GET: Preference-Applied header missing from response')

    def test_contained_desc(self):
        # Setup: Create LDP-RSs
        r = self.do_post()
        self.assertEqual(r.status_code, 201)
        parent = r.headers['Location']
        self.nodes.append(parent)
        r = self.do_post(parent)
        self.assertEqual(r.status_code, 201)
        child = r.headers['Location']
        self.nodes.append(child)

        # LDP-RS returns contained descriptions when asked
        return_representation = 'return=representation; include="http://w3.org/ns/oa#PreferContainedDescriptions"'
        r = self.do_get(parent, headers={'Prefer': return_representation})
        self.assertEqual(r.headers["Preference-Applied"], return_representation, "3.2.2 - Missing Preference-Applied header when " +
                         "Prefer header is used for GET")
        self.assertIsNotNone(re.search('ldp:contains\s*<' + child +'>', r.text))
        if not re.search('fedora:hasParent\s*<' + parent + '>', r.text):
            print('3.5.1 GET: (MAY) Contained descriptions missing from response')

    def test_inbound_refs(self):
        # Setup: Create LDP-RSs
        r = self.do_post()
        self.assertEqual(r.status_code, 201)
        parent = r.headers['Location']
        self.nodes.append(parent)
        r = self.do_post(parent)
        self.assertEqual(r.status_code, 201)
        child = r.headers['Location']
        self.nodes.append(child)

        # LDP-RS returns inbound references when asked
        includes = 'include="http://fedora.info/definitions/fcrepo#PreferInboundReferences"'
        r = self.do_get(child, headers={'Prefer': 'return=representation; ' + includes})
        self.assertEqual(r.status_code, 200)
        # TODO: how to test inbound refs?
        # '3.5.1 GET: (SHOULD) Inbound references missing from response'

    def test_want_digest_header(self):
        # Setup: Create LDP-NR
        with open('./image.jpg', 'rb') as image:
            files = {'files' : ('image.jpg', image)}
            r = self.do_post(files=files)
        self.assertEqual(r.status_code, 201)
        ldp_nr = r.headers['Location']
        self.nodes.append(ldp_nr)

        # LDP-NR responds to the Want-Digest header.
        r = self.do_get(ldp_nr, headers={'Want-Digest': 'md5'})
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.headers['Digest'].startswith('md5='),
                        '3.5.3 GET: Want-Digest header ignored or incorrect response returned')
        r = self.do_get(ldp_nr, headers={'Want-Digest': 'sha'})
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.headers['Digest'].startswith('sha='),
                        '3.5.3 GET: Want-Digest header ignored or incorrect response returned')

    # HEAD
    def test_empty_ldp_rs(self):
        # Setup
        r = requests.post(self.baseurl, auth=(self.username, self.password))
        self.assertEqual(r.status_code, 201)
        ldp_rs = r.headers['Location']
        self.nodes.append(ldp_rs)

        # Head request has no body
        head = requests.head(ldp_rs, auth=(self.username, self.password))
        self.assertEqual(head.status_code, 200)
        self.assertTrue(head.text == '', '3.6 HEAD: Unexpected response body for HEAD request')

    def test_no_payload_headers(self):
        # Setup
        r = self.do_post()
        self.assertEqual(r.status_code, 201)
        ldp_rs = r.headers['Location']
        self.nodes.append(ldp_rs)

        # Head request has no body
        head = self.do_head(ldp_rs)
        for payload_header in self.PAYLOAD_HEADERS:
            self.assertNotIn(payload_header, head.headers.keys(),
                             '3.6 HEAD: (MAY) Payload header "' + payload_header + '" not omitted')

    def test_same_headers(self):
        # Setup
        r = self.do_post()
        self.assertEqual(r.status_code, 201)
        ldp_rs = r.headers['Location']
        self.nodes.append(ldp_rs)

        head = self.do_head(ldp_rs)
        get = self.do_get(ldp_rs)
        # Collect the headers from the HEAD request, without the payload headers.
        head_keys = {key for key in head.headers.keys()}.difference(self.PAYLOAD_HEADERS)
        # Collect the headers from the GET request, without the payload headers.
        get_keys = {key for key in get.headers.keys()}.difference(self.PAYLOAD_HEADERS)
        self.assertEqual(head_keys, get_keys,
                         '3.6 HEAD: (SHOULD) Headers for a HEAD request should match the headers for a GET request')

    def test_empty_ldp_nr(self):
        # Setup
        with open('./image.jpg', 'rb') as image:
            files = {'files' : ('image.jpg', image)}
            r = self.do_post(files=files)
        self.assertEqual(r.status_code, 201)
        ldp_nr = r.headers['Location']
        self.nodes.append(ldp_nr)

        head = self.do_head(ldp_nr)
        self.assertEqual(head.status_code, 200)
        self.assertTrue(head.text == '', '3.6 HEAD: Unexpected response body for HEAD request')

    def test_head_digest(self):
        # Setup
        with open('./image.jpg', 'rb') as image:
            files = {'files' : ('image.jpg', image)}
            r = self.do_post(files=files)
        self.assertEqual(r.status_code, 201)
        ldp_nr = r.headers['Location']
        self.nodes.append(ldp_nr)

        # First without Want-Digest
        head = self.do_head(ldp_nr)
        get = self.do_get(ldp_nr)
        self.assertEqual('Digest' in head.headers.keys(), 'Digest' in get.headers.keys(),
                         '3.6 HEAD: Presence of Digest header must be the same in HEAD and GET requests')

        # Now with Want-Digest
        head = self.do_head(ldp_nr, headers={'Want-Digest': 'md5'})
        get = self.do_get(ldp_nr, headers={'Want-Digest': 'md5'})
        self.assertEqual('Digest' in head.headers.keys(), 'Digest' in get.headers.keys(),
                         '3.6 HEAD: Presence of Digest header must be the same in HEAD and GET requests')

    # PUT

    # PATCH
    def test_patch_sparql_update(self):
        r = self.do_post()
        self.assertEqual(r.status_code, 201)
        ldprs = r.headers["Location"]
        self.nodes.append(ldprs)

        patch = "INSERT { <> <http://purl.org/dc/elements/1.1/title> \"The title\" . } WHERE {}"
        headers = {"Content-type": self.SPARQL_UPDATE_MIMETYPE}
        r = self.do_patch(ldprs, patch, headers=headers)
        self.assertEqual(r.status_code, 204, '3.7 Any LDP-RS MUST support PATCH with Sparql11-update')

    def test_patch_interaction_model(self):
        r = self.do_post()
        self.assertEqual(r.status_code, 201)
        ldprs = r.headers["Location"]
        self.nodes.append(ldprs)

        patch = "DELETE { <> <http://www.w3.org/1999/02/22-rdf-syntax-ns#> <http://www.w3.org/ns/ldp#RDFSource> .}" \
                " INSERT { <> a <http://www.w3.org/ns/ldp#NonRDFSource> . } WHERE {}"
        headers = {"Content-type": self.SPARQL_UPDATE_MIMETYPE}
        r = self.do_patch(ldprs, patch, headers=headers)
        self.assertEqual(r.status_code, 409, '3.7.2 - Interaction model change not rejected with 409.')

    """
     DELETE
    """
    @support_delete
    def test_delete_depth(self):
        # Setup
        r = self.do_post()
        self.assertEqual(r.status_code, 201)
        parent = r.headers['Location']
        self.nodes.append(parent)
        r = self.do_post(parent=parent)
        self.assertEqual(r.status_code, 201)
        child = r.headers['Location']
        self.nodes.append(child)
        r = self.do_post(parent=child)
        self.assertEqual(r.status_code, 201)
        grandchild = r.headers['Location']
        self.nodes.append(grandchild)

        r = requests.options(parent, auth=(self.username, self.password))
        if r.status_code == 200 and "DELETE" in r.headers["Allow"].split(","):
            # Recursive delete is allowed.
            # Support deletion with depth of infinity
            r = self.do_delete(parent, headers={'Depth': 'infinity'})
            self.assertEqual(r.status_code, 204, '3.7.1 DELETE: Depth: infinity not supported')
            r = self.do_get(parent)
            self.assertEqual(r.status_code, 410)
            r = self.do_get(grandchild)
            self.assertEqual(r.status_code, 410)
        else:

            r = requests.options(grandchild, auth=(self.username, self.password))
            if r.status_code == 200 and "DELETE" in r.headers["Allow"].split(","):
                r = self.do_delete(parent, headers={'Depth': '0'})
                self.assertEqual(r.status_code, 204, '3.7.1 DELETE: Depth: 0 not supported')

    @support_delete
    def test_unsupported_depth(self):
        # Setup
        r = self.do_post()
        self.assertEqual(r.status_code, 201)
        ldp_rs = r.headers['Location']
        self.nodes.append(ldp_rs)

        # Bad Depth value returns 400
        r = self.do_delete(ldp_rs, headers={'Depth': 'forfty'})
        self.assertEqual(r.status_code, 400, '3.7.1 DELETE: Using an unsupported Depth value should return 400')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Test a repository against the Fedora API specification')
    parser.add_argument('--baseurl', dest='baseurl', action='store', default='http://localhost:8080/rest',
                        help='Base URL for the repository')
    parser.add_argument("--username", dest="username", action="store", default="", help="Username if required")
    parser.add_argument("--password", dest="password", action="store", default="", help="Password if required")
    parsed_args = parser.parse_args()
    # This is bad practice but allows us to modify the "unit tests"
    FedoraApiSpecTest.baseurl = parsed_args.baseurl
    FedoraApiSpecTest.username = parsed_args.username
    FedoraApiSpecTest.password = parsed_args.password
    removals = []
    for arg in sys.argv:
        if arg.startswith('--baseurl') or arg.startswith('--username') or arg.startswith('--password'):
            removals.append(arg)
    for arg in removals:
        sys.argv.remove(arg)

    unittest.main()