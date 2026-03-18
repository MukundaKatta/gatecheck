"""Tests for Gatecheck."""
from src.core import Gatecheck
def test_init(): assert Gatecheck().get_stats()["ops"] == 0
def test_op(): c = Gatecheck(); c.detect(x=1); assert c.get_stats()["ops"] == 1
def test_multi(): c = Gatecheck(); [c.detect() for _ in range(5)]; assert c.get_stats()["ops"] == 5
def test_reset(): c = Gatecheck(); c.detect(); c.reset(); assert c.get_stats()["ops"] == 0
def test_service_name(): c = Gatecheck(); r = c.detect(); assert r["service"] == "gatecheck"
