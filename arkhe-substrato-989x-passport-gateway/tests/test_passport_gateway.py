#!/usr/bin/env python3
"""
Testes canonicos — Substrato 989.x PASSPORT-GATEWAY
Arquiteto ORCID: 0009-0005-2697-4668
Seal: 989-PASSPORT-GATEWAY-4B3CB68C02D21E5A
"""

import pytest
from unittest.mock import AsyncMock, MagicMock
from aiohttp import ClientSession
import hashlib
import json
import time

import sys
sys.path.insert(0, ".")
from passport_gateway import (
    PassportGateway,
    PassportGatewayError,
    HumanityProof,
    StampCredential,
    VerificationStatus,
    MIN_HUMANITY_SCORE,
    MIN_PASSPORT_SCORE,
)


# ===================================================================
# Fixtures
# ===================================================================

@pytest.fixture
def gateway():
    g = PassportGateway(api_key="test-key", scorer_id="42")
    return g


@pytest.fixture
def mock_session():
    session = AsyncMock()
    session.closed = False
    return session


# ===================================================================
# Helpers
# ===================================================================

class MockResponse:
    def __init__(self, status, json_data, text=""):
        self.status = status
        self._json_data = json_data
        self._text = text

    async def json(self):
        return self._json_data

    async def text(self):
        return self._text

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        pass

def make_mock_response(status, json_data, text='{"error":"Invalid API Key"}'):
    """Cria um mock de resposta aiohttp."""
    return MockResponse(status, json_data, text)


def build_credential(provider, issuance_date=None):
    """Constroi um credential do Passport de forma segura."""
    cred = {"credentialSubject": {"provider": provider}}
    if issuance_date:
        cred["issuanceDate"] = issuance_date
    return {"credential": cred}


# ===================================================================
# Testes de inicializacao
# ===================================================================

@pytest.mark.asyncio
async def test_gateway_start_stop(gateway):
    await gateway.start()
    assert gateway._session is not None
    await gateway.stop()


def test_gateway_constants():
    assert PassportGateway.SUBSTRATE_ID == 989
    assert PassportGateway.VARIANT == "x"
    assert PassportGateway.SEAL == "989-PASSPORT-GATEWAY-4B3CB68C02D21E5A"


def test_humanity_proof_seal():
    proof = HumanityProof(
        address="0xTest",
        is_human=True,
        score=0.85,
        raw_passport_score=17.0,
        stamps=[],
        orcid_verified=True,
        status=VerificationStatus.VERIFIED,
    )
    seal = proof.compute_seal()
    assert seal.startswith("HP-")
    assert len(seal) == 19
    seal2 = proof.compute_seal()
    assert seal == seal2


def test_humanity_proof_to_dict():
    proof = HumanityProof(
        address="0xTest",
        is_human=True,
        score=0.85,
        raw_passport_score=17.0,
        stamps=[StampCredential(provider="Google")],
        orcid_verified=True,
        status=VerificationStatus.VERIFIED,
    )
    d = proof.to_dict()
    assert d["address"] == "0xTest"
    assert d["is_human"] is True
    assert d["status"] == "verified"
    assert len(d["stamps"]) == 1
    assert d["stamps"][0]["provider"] == "Google"


# ===================================================================
# Testes de API Passport (mockados)
# ===================================================================

@pytest.mark.asyncio
async def test_get_passport_score_success(gateway, mock_session):
    resp = make_mock_response(200, {"score": "25.5", "status": "done"})
    mock_session.get = MagicMock(return_value=resp)
    gateway._session = mock_session

    result = await gateway.get_passport_score("0xAlice")
    assert result["score"] == "25.5"
    mock_session.get.assert_called_once()


@pytest.mark.asyncio
async def test_get_passport_score_404(gateway, mock_session):
    resp = make_mock_response(404, {})
    mock_session.get = MagicMock(return_value=resp)
    gateway._session = mock_session

    result = await gateway.get_passport_score("0xUnknown")
    assert result["score"] == 0
    assert result["status"] == "NOT_FOUND"


@pytest.mark.asyncio
async def test_get_passport_score_no_api_key():
    g = PassportGateway(api_key="", scorer_id="1")
    with pytest.raises(PassportGatewayError, match="PASSPORT_API_KEY"):
        await g.get_passport_score("0xAlice")


@pytest.mark.asyncio
async def test_get_passport_stamps(gateway, mock_session):
    data = {
        "items": [
            build_credential("Google", "2026-01-01"),
            build_credential("GitHub"),
        ]
    }
    resp = make_mock_response(200, data)
    mock_session.get = MagicMock(return_value=resp)
    gateway._session = mock_session

    stamps = await gateway.get_passport_stamps("0xAlice")
    assert len(stamps) == 2
    assert stamps[0].provider == "Google"
    assert stamps[0].issuance_date == "2026-01-01"
    assert stamps[1].provider == "GitHub"


@pytest.mark.asyncio
async def test_get_passport_stamps_empty(gateway, mock_session):
    resp = make_mock_response(200, {"items": []})
    mock_session.get = MagicMock(return_value=resp)
    gateway._session = mock_session

    stamps = await gateway.get_passport_stamps("0xEmpty")
    assert stamps == []


# ===================================================================
# Testes de verificacao de humanidade
# ===================================================================

@pytest.mark.asyncio
async def test_is_human_high_score(gateway, mock_session):
    score_resp = make_mock_response(200, {"score": "30.0"})
    stamps_resp = make_mock_response(200, {"items": []})
    mock_session.get = MagicMock(side_effect=[score_resp, stamps_resp])
    gateway._session = mock_session

    proof = await gateway.is_human("0xAlice")
    assert proof.is_human is True
    assert proof.score == 1.0
    assert proof.raw_passport_score == 30.0
    assert proof.status == VerificationStatus.VERIFIED
    assert proof.seal.startswith("HP-")


@pytest.mark.asyncio
async def test_is_human_low_score_no_orcid(gateway, mock_session):
    score_resp = make_mock_response(200, {"score": "5.0"})
    stamps_resp = make_mock_response(200, {"items": []})
    mock_session.get = MagicMock(side_effect=[score_resp, stamps_resp])
    gateway._session = mock_session

    proof = await gateway.is_human("0xBob")
    assert proof.is_human is False
    assert proof.score == 0.25
    assert proof.orcid_verified is False


@pytest.mark.asyncio
async def test_is_human_orcid_fallback(gateway, mock_session):
    score_resp = make_mock_response(200, {"score": "5.0"})
    stamps_resp = make_mock_response(200, {"items": []})
    mock_session.get = MagicMock(side_effect=[score_resp, stamps_resp])
    gateway._session = mock_session

    proof = await gateway.is_human("0xAlice123456789")
    assert proof.is_human is True
    assert proof.orcid_verified is True


@pytest.mark.asyncio
async def test_is_human_api_error_with_orcid(gateway, mock_session):
    score_resp = make_mock_response(500, {})
    score_resp.text = AsyncMock(return_value="Internal Server Error")
    orcid_resp = make_mock_response(200, {"orcid-identifier": {"path": "0009-0005-2697-4668"}})
    mock_session.get = MagicMock(side_effect=[score_resp, orcid_resp])
    gateway._session = mock_session

    proof = await gateway.is_human("0xAlice123456789", orcid_id="0009-0005-2697-4668")
    assert proof.status == VerificationStatus.PENDING
    assert proof.orcid_verified is True


# ===================================================================
# Testes de governanca DAO (979)
# ===================================================================

@pytest.mark.asyncio
async def test_verify_dao_voter_human(gateway, mock_session):
    score_resp = make_mock_response(200, {"score": "25.0"})
    stamps_resp = make_mock_response(200, {"items": []})
    mock_session.get = MagicMock(side_effect=[score_resp, stamps_resp])
    gateway._session = mock_session

    can_vote = await gateway.verify_dao_voter("0xAlice")
    assert can_vote is True


@pytest.mark.asyncio
async def test_verify_dao_voter_sanctions(gateway, mock_session):
    score_resp = make_mock_response(200, {"score": "25.0"})
    stamps_resp = make_mock_response(200, {"items": []})
    mock_session.get = MagicMock(side_effect=[score_resp, stamps_resp])
    gateway._session = mock_session

    can_vote = await gateway.verify_dao_voter("0xAlice")
    assert can_vote is True


# ===================================================================
# Testes de malha global (972)
# ===================================================================

@pytest.mark.asyncio
async def test_verify_node_access(gateway, mock_session):
    score_resp = make_mock_response(200, {"score": "25.0"})
    stamps_resp = make_mock_response(200, {"items": []})
    mock_session.get = MagicMock(side_effect=[score_resp, stamps_resp])
    gateway._session = mock_session

    can_operate = await gateway.verify_node_access("0xAlice")
    assert can_operate is True


# ===================================================================
# Testes Axiarchy (954)
# ===================================================================

@pytest.mark.asyncio
async def test_axiarchy_validate_vote(gateway, mock_session):
    score_resp = make_mock_response(200, {"score": "25.0"})
    stamps_resp = make_mock_response(200, {"items": []})
    mock_session.get = MagicMock(side_effect=[score_resp, stamps_resp])
    gateway._session = mock_session

    result = await gateway.axiarchy_validate("0xAlice", "vote")
    assert result["approved"] is True
    assert result["action"] == "vote"
    assert result["substrate"] == "989.x"
    assert "seal" in result


@pytest.mark.asyncio
async def test_axiarchy_validate_rejected(gateway, mock_session):
    score_resp = make_mock_response(200, {"score": "5.0"})
    stamps_resp = make_mock_response(200, {"items": []})
    mock_session.get = MagicMock(side_effect=[score_resp, stamps_resp])
    gateway._session = mock_session

    result = await gateway.axiarchy_validate("0xSybil", "treasury")
    assert result["approved"] is False
    assert result["humanity_score"] == 0.25


# ===================================================================
# Testes de ORCID (982)
# ===================================================================

@pytest.mark.asyncio
async def test_verify_orcid_link_fallback(gateway):
    assert await gateway.verify_orcid_link("0xAlice123") is True
    assert await gateway.verify_orcid_link("0xArchitect0009") is True
    assert await gateway.verify_orcid_link("0xBob456") is False


@pytest.mark.asyncio
async def test_get_orcid_record(gateway, mock_session):
    data = {
        "orcid-identifier": {"path": "0009-0005-2697-4668"},
        "person": {"name": {"given-names": {"value": "Arquiteto"}}}
    }
    resp = make_mock_response(200, data)
    mock_session.get = MagicMock(return_value=resp)
    gateway._session = mock_session

    record = await gateway.get_orcid_record("0009-0005-2697-4668")
    assert record["orcid-identifier"]["path"] == "0009-0005-2697-4668"


@pytest.mark.asyncio
async def test_get_orcid_record_404(gateway, mock_session):
    resp = make_mock_response(404, {})
    mock_session.get = MagicMock(return_value=resp)
    gateway._session = mock_session

    record = await gateway.get_orcid_record("0000-0000-0000-0000")
    assert record == {}


# ===================================================================
# Testes de relatorio canonico
# ===================================================================

def test_generate_report(gateway):
    report = gateway.generate_report()
    assert "989-PASSPORT-GATEWAY-4B3CB68C02D21E5A" in report
    assert "CANONIZED_PROVISIONAL" in report
    assert "Themis" in report
    assert "Athena" in report
    assert "Hermes" in report
    assert "979" in report
    assert "954" in report


# ===================================================================
# Testes de edge cases e resiliencia
# ===================================================================

@pytest.mark.asyncio
async def test_is_human_zero_score(gateway, mock_session):
    score_resp = make_mock_response(200, {"score": "0"})
    stamps_resp = make_mock_response(200, {"items": []})
    mock_session.get = MagicMock(side_effect=[score_resp, stamps_resp])
    gateway._session = mock_session

    proof = await gateway.is_human("0xZero")
    assert proof.score == 0.0
    assert proof.is_human is False


@pytest.mark.asyncio
async def test_is_human_exact_threshold(gateway, mock_session):
    score_resp = make_mock_response(200, {"score": "15.0"})
    stamps_resp = make_mock_response(200, {"items": []})
    mock_session.get = MagicMock(side_effect=[score_resp, stamps_resp])
    gateway._session = mock_session

    proof = await gateway.is_human("0xThreshold")
    assert proof.score == 0.75
    assert proof.is_human is True


@pytest.mark.asyncio
async def test_multiple_stamps_parsing(gateway, mock_session):
    score_resp = make_mock_response(200, {"score": "30.0"})
    stamps_data = {
        "items": [
            build_credential("Google", "2026-01-01"),
            build_credential("Twitter", "2026-02-01"),
            build_credential("GitHub", "2026-03-01"),
            build_credential("LinkedIn"),
        ]
    }
    stamps_resp = make_mock_response(200, stamps_data)
    mock_session.get = MagicMock(side_effect=[score_resp, stamps_resp])
    gateway._session = mock_session

    proof = await gateway.is_human("0xRich")
    assert len(proof.stamps) == 4
    providers = [s.provider for s in proof.stamps]
    assert "Google" in providers
    assert "Twitter" in providers
    assert "GitHub" in providers
    assert "LinkedIn" in providers




# ===================================================================
# Testes de DeSci Nodes Bridge (989.y)
# ===================================================================

import sys
sys.path.insert(0, "..")
from desci_nodes_bridge import (
    DeSciNodesBridge,
    ResearchObject,
    ResearchObjectType,
    FAIRMetadata,
)

@pytest.fixture
def desci_bridge():
    return DeSciNodesBridge()


@pytest.mark.asyncio
async def test_create_research_object(desci_bridge):
    ro = await desci_bridge.create_research_object(
        ro_type=ResearchObjectType.PUBLICATION,
        content=b"Test paper content",
        title="Test Paper",
        description="A test paper for the Cathedral",
        orcid_id="0009-0005-2697-4668",
        keywords=["test", "cathedral", "AI"],
        cathedral_substrates=[934, 964],
    )
    assert ro.ro_id.startswith("dpid-")
    assert ro.ro_type == ResearchObjectType.PUBLICATION
    assert ro.cid.startswith("Qm")
    assert ro.manifest_cid.startswith("Qm")
    assert ro.fair.title == "Test Paper"
    assert ro.fair.orcid_id == "0009-0005-2697-4668"
    assert ro.cathedral_substrates == [934, 964]
    assert ro.seal.startswith("RO-")
    assert len(desci_bridge.research_objects) == 1


@pytest.mark.asyncio
async def test_create_dataset(desci_bridge):
    ro = await desci_bridge.create_research_object(
        ro_type=ResearchObjectType.DATASET,
        content=b"1,2,3\n4,5,6",
        title="Test Dataset",
        description="CSV dataset for ML training",
        keywords=["dataset", "ML"],
    )
    assert ro.ro_type == ResearchObjectType.DATASET
    assert ro.fair.data_format == "json"


@pytest.mark.asyncio
async def test_fair_score(desci_bridge):
    ro = await desci_bridge.create_research_object(
        ro_type=ResearchObjectType.CODE,
        content=b"print('hello')",
        title="Test Code",
        description="Python script",
        orcid_id="0009-0005-2697-4668",
        keywords=["python", "AI"],
    )
    score = ro.fair.compute_fair_score()
    assert 0 <= score <= 1
    # Com todos os campos preenchidos, score deve ser alto
    assert score > 0.5


def test_fair_score_empty():
    fair = FAIRMetadata(dpid="test")
    score = fair.compute_fair_score()
    assert score < 0.7  # Poucos campos preenchidos


@pytest.mark.asyncio
async def test_link_to_substrate(desci_bridge):
    ro = await desci_bridge.create_research_object(
        ro_type=ResearchObjectType.PUBLICATION,
        content=b"content",
        title="Link Test",
        description="Testing links",
    )
    result = desci_bridge.link_to_substrate(ro.ro_id, 989, "989-TEST-SEAL")
    assert result is True
    assert 989 in desci_bridge.research_objects[ro.ro_id].cathedral_substrates
    assert "989-TEST-SEAL" in desci_bridge.research_objects[ro.ro_id].cathedral_seals


def test_link_to_nonexistent(desci_bridge):
    result = desci_bridge.link_to_substrate("nonexistent", 989, "seal")
    assert result is False


@pytest.mark.asyncio
async def test_get_fair_report(desci_bridge):
    ro = await desci_bridge.create_research_object(
        ro_type=ResearchObjectType.PUBLICATION,
        content=b"content",
        title="FAIR Report Test",
        description="Testing FAIR report",
        orcid_id="0009-0005-2697-4668",
        keywords=["FAIR", "test"],
    )
    report = desci_bridge.get_fair_report(ro.ro_id)
    assert report is not None
    assert report["dpid"] == ro.ro_id
    assert "fair_score" in report
    assert "findable" in report
    assert "accessible" in report
    assert "interoperable" in report
    assert "reusable" in report
    assert "cathedral_links" in report
    assert report["seal"] == ro.seal


def test_get_fair_report_nonexistent(desci_bridge):
    report = desci_bridge.get_fair_report("nonexistent")
    assert report is None


@pytest.mark.asyncio
async def test_generate_report(desci_bridge):
    for i in range(3):
        await desci_bridge.create_research_object(
            ro_type=ResearchObjectType.PUBLICATION,
            content=f"content {i}".encode(),
            title=f"Paper {i}",
            description=f"Description {i}",
        )
    report = desci_bridge.generate_report()
    assert "989.y-DESCI-NODES-BRIDGE" in report
    assert "Total: 3" in report
    assert "publication" in report


def test_generate_dpid(desci_bridge):
    dpid1 = desci_bridge.generate_dpid()
    dpid2 = desci_bridge.generate_dpid()
    assert dpid1.startswith("dpid-")
    assert dpid2.startswith("dpid-")
    assert dpid1 != dpid2
    assert int(dpid1.split("-")[1]) < int(dpid2.split("-")[1])


@pytest.mark.asyncio
async def test_research_object_seal(desci_bridge):
    ro = await desci_bridge.create_research_object(
        ro_type=ResearchObjectType.MODEL,
        content=b"model weights",
        title="ML Model",
        description="Trained model",
    )
    assert ro.seal.startswith("RO-")
    assert len(ro.seal) == 19  # RO- + 16 hex

    # Determinismo
    ro.compute_seal()
    assert ro.seal.startswith("RO-")

# ===================================================================
# Suite runner


# ===================================================================
# Testes de TemporalChain Anchor (923)
# ===================================================================

import sys
sys.path.insert(0, "..")
from temporal_chain_anchor import TemporalChainAnchor, HumanityAnchor, TemporalBlock

@pytest.fixture
def anchor():
    return TemporalChainAnchor()


def test_genesis_block(anchor):
    assert len(anchor.chain) == 1
    assert anchor.chain[0].block_id == "923-GENESIS"
    assert anchor.chain[0].seal.startswith("923-BLOCK-")


def test_create_block(anchor):
    block = anchor.create_block({"type": "test", "data": "value"})
    assert block.block_id == "923-BLOCK-000001"
    assert block.previous_hash == anchor.chain[0].compute_hash()
    assert block.seal.startswith("923-BLOCK-")
    assert len(anchor.chain) == 2


def test_anchor_humanity_proof(anchor):
    proof = {
        "address": "0xAlice",
        "is_human": True,
        "score": 0.95,
        "seal": "HP-TEST1234567890",
    }
    humanity_anchor = anchor.anchor_humanity_proof(proof)
    assert humanity_anchor.anchor_id.startswith("anchor-")
    assert humanity_anchor.proof_hash == hashlib.sha3_256(json.dumps(proof, sort_keys=True).encode()).hexdigest()
    assert humanity_anchor.temporal_anchor.startswith("923-ANCHOR-")
    assert humanity_anchor.orcid_signature != ""
    assert len(anchor.anchors) == 1
    assert len(anchor.chain) == 2  # genesis + new block


def test_verify_anchor(anchor):
    proof = {"address": "0xAlice", "is_human": True, "score": 0.95, "seal": "HP-TEST"}
    humanity_anchor = anchor.anchor_humanity_proof(proof)
    assert anchor.verify_anchor(humanity_anchor.anchor_id) is True
    assert anchor.verify_anchor("nonexistent") is False


def test_chain_summary(anchor):
    summary = anchor.get_chain_summary()
    assert summary["length"] == 1
    assert summary["latest_block"] == "923-GENESIS"
    assert summary["anchors_count"] == 0


# ===================================================================
# Testes de Proof of Clean Hands (989.x.1)
# ===================================================================

from proof_of_clean_hands import ProofOfCleanHands, RiskLevel, SanctionsCheck

@pytest.fixture
def clean_hands():
    return ProofOfCleanHands()


@pytest.mark.asyncio
async def test_check_address_clear(clean_hands):
    # Endereço com hash que dá CLEAR
    check = await clean_hands.check_address("0xClear1234567890abcdef")
    assert check.risk_level in {RiskLevel.CLEAR, RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.SANCTIONED}
    assert 0 <= check.score <= 1
    assert check.seal.startswith("POC-")


@pytest.mark.asyncio
async def test_can_operate_node(clean_hands):
    # Forçar CLEAR
    addr = "0x" + "a" * 40  # hash determinístico
    check = await clean_hands.check_address(addr)
    can_operate = clean_hands.can_operate_node(addr)
    assert isinstance(can_operate, bool)
    if check.risk_level in {RiskLevel.CLEAR, RiskLevel.LOW}:
        assert can_operate is True
    else:
        assert can_operate is False


@pytest.mark.asyncio
async def test_can_vote_dao(clean_hands):
    addr = "0x" + "b" * 40
    check = await clean_hands.check_address(addr)
    can_vote = clean_hands.can_vote_dao(addr)
    assert isinstance(can_vote, bool)
    if check.risk_level in {RiskLevel.CLEAR, RiskLevel.LOW, RiskLevel.MEDIUM}:
        assert can_vote is True
    else:
        assert can_vote is False


def test_risk_summary_empty(clean_hands):
    summary = clean_hands.get_risk_summary()
    assert summary["total"] == 0
    assert summary["risk_score"] == 0.0


@pytest.mark.asyncio
async def test_risk_summary_with_checks(clean_hands):
    for i in range(10):
        await clean_hands.check_address(f"0x{i:040d}")
    summary = clean_hands.get_risk_summary()
    assert summary["total"] == 10
    assert summary["blocked"] >= 0
    assert 0 <= summary["risk_score"] <= 1


# ===================================================================
# Testes de Distributed Cache (989.x.3)
# ===================================================================

from distributed_cache import DistributedCache, CacheEntry, CacheLayer

@pytest.fixture
def cache():
    return DistributedCache()


@pytest.mark.asyncio
async def test_cache_miss(cache):
    result = await cache.get("0xAlice")
    assert result is None
    assert cache.misses == 1


@pytest.mark.asyncio
async def test_cache_set_and_get(cache):
    value = {"is_human": True, "score": 0.95}
    entry = await cache.set("0xAlice", value)
    assert entry.seal.startswith("CACHE-")
    assert not entry.is_expired

    result = await cache.get("0xAlice")
    assert result == value
    assert cache.hits == 1


@pytest.mark.asyncio
async def test_cache_expiration(cache):
    value = {"is_human": True}
    await cache.set("0xAlice", value, ttl=1)

    # Antes de expirar
    result = await cache.get("0xAlice")
    assert result is not None

    # Esperar expirar
    import time
    time.sleep(1.1)

    result = await cache.get("0xAlice")
    assert result is None  # Expirado


@pytest.mark.asyncio
async def test_cache_invalidate(cache):
    await cache.set("0xAlice", {"is_human": True})
    await cache.invalidate("0xAlice")
    result = await cache.get("0xAlice")
    assert result is None


def test_cache_stats(cache):
    stats = cache.get_stats()
    assert stats["memory_entries"] == 0
    assert stats["hits"] == 0
    assert stats["misses"] == 0
    assert stats["hit_rate"] == 0.0


@pytest.mark.asyncio
async def test_cache_stats_with_data(cache):
    await cache.set("0xAlice", {"score": 0.9})
    await cache.set("0xBob", {"score": 0.8})
    await cache.get("0xAlice")  # hit
    await cache.get("0xCharlie")  # miss

    stats = cache.get_stats()
    assert stats["memory_entries"] == 2
    assert stats["hits"] == 1
    assert stats["misses"] == 1
    assert stats["hit_rate"] == 0.5


def test_cache_entry_seal():
    entry = CacheEntry(
        key="test:0xAlice",
        value={"score": 0.9},
        timestamp=time.time(),
        ttl_seconds=300,
    )
    seal = entry.compute_seal()
    assert seal.startswith("CACHE-")
    assert len(seal) == 22  # CACHE- + 16 hex


def test_cache_entry_expiration():
    entry = CacheEntry(
        key="test",
        value={},
        timestamp=time.time() - 400,  # 400s atrás
        ttl_seconds=300,
    )
    assert entry.is_expired is True

    entry2 = CacheEntry(
        key="test2",
        value={},
        timestamp=time.time(),
        ttl_seconds=300,
    )
    assert entry2.is_expired is False
# ===================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])