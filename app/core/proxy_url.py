"""The type of the CII_PROXY_URL setting: an http(s):// address, or blank."""

from typing import Annotated

from pydantic import AfterValidator, SecretStr

from app.core.constants import ErrorMessage


def _refuse_a_proxy_url_without_scheme(value: SecretStr) -> SecretStr:
    """A proxy address without http:// or https:// is read as a host name: every outside call would fail later
    with no word of why, so start-up stops with the reason instead (every environment)."""
    proxy = value.get_secret_value()
    if proxy and not proxy.startswith(("http://", "https://")):
        raise ValueError(ErrorMessage.PROXY_URL_WITHOUT_SCHEME)
    return value


#: CII_PROXY_URL, the company proxy of the outside calls. Not true/false: an http(s):// address = every
#: outside call goes through it (the intel feeds; the AI calls too when CII_AI_BYPASS_PROXY is false);
#: blank = the machine's or pod's HTTP(S)_PROXY, else Windows' own setting. Named _URL, never _PROXY:
#: Python reads any *_PROXY variable as a proxy. Secret: it can carry a password.
ProxyUrl = Annotated[SecretStr, AfterValidator(_refuse_a_proxy_url_without_scheme)]
