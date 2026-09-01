import unittest

from ariadne.server import CORPUS_HASH, _target_from_req, do_plan, do_recon


GRAPH = {
    "name": "contract-test",
    "goal": ["read_file", "/root/proof.txt"],
    "facts": [
        ["rce_as", "www-data"],
        ["file", "/root/proof.txt"],
        ["can_read", "root", "/root/proof.txt"],
    ],
    "negatives": [["can_read", "www-data", "/root/proof.txt"]],
}


class ServerContractTests(unittest.TestCase):
    def test_registered_target_cannot_be_a_path(self):
        with self.assertRaisesRegex(ValueError, "not a path"):
            _target_from_req({"target": "/etc/passwd"})

    def test_inline_graph_is_schema_checked(self):
        bad = dict(GRAPH, facts=[["invented_predicate", "x"]])
        with self.assertRaisesRegex(ValueError, "invalid fact"):
            _target_from_req({"graph": bad})

    def test_plan_and_recon_include_stable_corpus_hash(self):
        self.assertEqual(do_plan({"graph": GRAPH, "top": 1})["corpus_hash"], CORPUS_HASH)
        self.assertEqual(do_recon({"graph": GRAPH, "steps": 1})["corpus_hash"], CORPUS_HASH)

    def test_bounds_are_enforced(self):
        with self.assertRaisesRegex(ValueError, "top"):
            do_plan({"graph": GRAPH, "top": 1000})
        with self.assertRaisesRegex(ValueError, "steps"):
            do_recon({"graph": GRAPH, "steps": 0})


if __name__ == "__main__":
    unittest.main()
