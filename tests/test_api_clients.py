import pytest
from fastapi import Depends, Request
from fastapi.testclient import TestClient

from app import container
from app.api.dependencies import get_authenticated_principal
from app.core.constants import ApiKey, Collection, ErrorCode, Limits
from app.core.database import get_mongodb
from app.core.exceptions import Unauthorized
from app.domain.admin.api_keys import hash_api_key
from app.models.admin.api_clients import Principal
from tests.conftest import ADMIN

URL = "/v1/tsg/api-clients"


def _mint_api_client_via_api(client: TestClient, name: str) -> dict:
    response = client.post(URL, json={"name": name}, headers={**ADMIN, "X-User-Id": "admin-1"})
    assert response.status_code == 201, response.text
    return response.json()


def test_mint_shows_the_secret_once_and_stores_only_its_hash(client: TestClient) -> None:
    minted = _mint_api_client_via_api(client, "frontend-a")
    assert minted["api_key"].startswith(ApiKey.PREFIX)
    assert minted["key_prefix"] == minted["api_key"][:8]
    stored = get_mongodb()[Collection.API_CLIENTS].find_one({"_id": minted["client_id"]})
    assert stored["key_hash"] == hash_api_key(minted["api_key"])
    assert minted["api_key"] not in str(stored)
    listed = client.get(URL, headers=ADMIN).json()["items"]
    assert all("api_key" not in item and "key_hash" not in item for item in listed)


def test_mint_response_is_never_cached(client: TestClient) -> None:
    response = client.post(URL, json={"name": "frontend-b"}, headers=ADMIN)
    assert response.headers["cache-control"] == "no-store"


@pytest.mark.parametrize("headers", [{}, {"X-Admin-Key": "wrong"}])
def test_admin_key_is_required(client: TestClient, headers: dict) -> None:
    response = client.get(URL, headers=headers)
    assert response.status_code == 401
    assert response.json()["code"] == ErrorCode.UNAUTHORIZED


def test_two_active_clients_cannot_share_a_name(client: TestClient) -> None:
    _mint_api_client_via_api(client, "frontend-c")
    response = client.post(URL, json={"name": "frontend-c"}, headers=ADMIN)
    assert response.status_code == 409
    assert response.json()["code"] == ErrorCode.CONFLICT


def test_revoke_stops_the_key_and_is_idempotent(client: TestClient) -> None:
    minted = _mint_api_client_via_api(client, "frontend-d")
    service = container.get_admin_service()
    assert service.get_api_client_id(minted["api_key"]) == minted["client_id"]
    first = client.post(f"{URL}/{minted['client_id']}/revoke", headers=ADMIN)
    second = client.post(f"{URL}/{minted['client_id']}/revoke", headers=ADMIN)
    assert first.status_code == second.status_code == 200
    assert first.json()["active"] is False
    assert service.get_api_client_id(minted["api_key"]) is None


def test_revoking_an_unknown_client_is_404(client: TestClient) -> None:
    assert client.post(f"{URL}/does-not-exist/revoke", headers=ADMIN).status_code == 404


def test_principal_needs_a_valid_key_and_all_identity_headers(client: TestClient) -> None:
    minted = _mint_api_client_via_api(client, "frontend-e")
    service, request = container.get_admin_service(), Request({"type": "http", "headers": []})
    with pytest.raises(Unauthorized):
        get_authenticated_principal(
            request, service, api_key=minted["api_key"], user_id="u1", entity_id=86, tenant_id="   "
        )
    with pytest.raises(Unauthorized):
        get_authenticated_principal(
            request, service, api_key=f"{ApiKey.PREFIX}wrong", user_id="u1", entity_id=86, tenant_id="DESC"
        )
    principal = get_authenticated_principal(
        request, service, api_key=minted["api_key"], user_id=" u1 ", entity_id=86, tenant_id="DESC"
    )
    assert principal == Principal(minted["client_id"], "u1", 86, "DESC")
    assert request.state.client_id == minted["client_id"]  # for the request's access line


def test_a_name_of_only_spaces_is_refused(client: TestClient) -> None:
    assert client.post(URL, json={"name": "   "}, headers=ADMIN).status_code == 422


def test_wrong_keys_are_never_cached() -> None:
    """The cause of unbounded growth: every distinct wrong key used to be remembered for a minute."""
    service, repository = container.get_admin_service(), container.get_api_client_repository()
    cached_before = len(repository._verified)
    for attempt in range(50):
        assert service.get_api_client_id(f"{ApiKey.PREFIX}guess_{attempt}") is None
    assert len(repository._verified) == cached_before


def test_a_key_that_cannot_be_one_tsg_minted_costs_no_database_read(monkeypatch: pytest.MonkeyPatch) -> None:
    """Before: every request with any junk X-API-Key made a MongoDB read (and held a thread while MongoDB
    was slow). Only a key with TSG's prefix and length is looked up."""
    service = container.get_admin_service()
    reads: list[dict] = []
    monkeypatch.setattr(container.get_api_client_repository(), "get", lambda *_, **where: reads.append(where))
    minted_length = len(ApiKey.PREFIX) + 43  # the prefix and secrets.token_urlsafe(32)
    for junk in ("", "secret", f"{ApiKey.PREFIX}short", "x" * minted_length, ApiKey.PREFIX + "a" * 44):
        assert service.get_api_client_id(junk) is None
    assert reads == []
    service.get_api_client_id(ApiKey.PREFIX + "a" * 43)  # a minted key's shape: looked up
    assert len(reads) == 1


@pytest.mark.parametrize("entity_id", ["abc", "-1", "0", str(Limits.MAX_SQL_INT + 1)])
def test_an_entity_id_that_is_not_a_positive_number_is_refused(client: TestClient, entity_id: str) -> None:
    def who_am_i(principal: Principal = Depends(get_authenticated_principal)) -> dict:  # noqa: B008
        return {"entity_id": principal.entity_id}

    client.app.add_api_route("/test-only/who-am-i", who_am_i)  # type: ignore[attr-defined]
    response = client.get("/test-only/who-am-i", headers={"X-Entity-Id": entity_id})
    assert response.status_code == 422


def test_an_oversized_user_header_is_refused_before_it_is_stored(client: TestClient) -> None:
    """Before: any length of X-User-Id went into created_by, the audit record and the log line."""
    too_long = "u" * (Limits.MAX_IDENTITY_CHARS + 1)
    response = client.post(URL, json={"name": "oversized-user"}, headers={**ADMIN, "X-User-Id": too_long})
    assert response.status_code == 422
    assert get_mongodb()[Collection.API_CLIENTS].find_one({"name": "oversized-user"}) is None
