import unittest

from run_htb import _surface_to_mapjson


class PortsToMapJsonTest(unittest.TestCase):
    def test_mixed_services_and_web_products(self):
        facts = [
            "ports=21,22,25,53,80,110,143,8080",
            "web80=Apache/2.4.41:Inlanefreight",
            "web8080=Apache/2.4.41:Support Center",
            "ftp=anonymous:readable:flag.txt",
        ]
        result = _surface_to_mapjson(facts, {}, "10.10.10.10")
        ports = {row["port"]: row for row in result["hosts"][0]["ports"]}
        self.assertEqual("http", ports[80]["name"])
        self.assertEqual("http", ports[8080]["name"])
        self.assertEqual("ftp", ports[21]["name"])
        self.assertEqual("ssh", ports[22]["name"])
        self.assertEqual("smtp", ports[25]["name"])
        self.assertEqual("dns", ports[53]["name"])
        self.assertEqual("Apache/2.4.41:Inlanefreight", ports[80]["product"])

    def test_web_fact_alone_creates_the_port(self):
        # a web80= fact implies port 80 exists — the surface builder creates it
        result = _surface_to_mapjson(["web80=Apache"], {}, "10.10.10.10")
        ports = {row["port"]: row for row in result["hosts"][0]["ports"]}
        self.assertEqual("http", ports[80]["name"])
        self.assertEqual("Apache", ports[80]["product"])

    def test_no_surface_data_returns_none(self):
        self.assertIsNone(_surface_to_mapjson(["ftp=anonymous:readable:flag.txt"], {}, "10.10.10.10"))


if __name__ == "__main__":
    unittest.main()
