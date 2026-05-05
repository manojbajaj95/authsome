"""Auth session routes and browser input pages."""

from __future__ import annotations

import html
from datetime import timedelta
from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from authsome.auth import AuthService
from authsome.auth.input_provider import InputField, MockInputProvider
from authsome.auth.models.connection import ProviderClientRecord
from authsome.auth.models.enums import FlowType
from authsome.auth.sessions import AuthSession, AuthSessionStatus, AuthSessionStore
from authsome.server.routes._deps import get_auth_service, get_auth_sessions
from authsome.server.schemas import (
    AuthSessionResponse,
    DeviceCodeAction,
    NoneAction,
    OpenUrlAction,
    ResumeAuthSessionRequest,
    StartAuthSessionRequest,
)
from authsome.utils import utc_now

router = APIRouter(prefix="/auth", tags=["auth"])

LOCAL_BASE_URL = "http://127.0.0.1:7998"
OAUTH_CALLBACK_URL = f"{LOCAL_BASE_URL}/auth/callback/oauth"


@router.post("/sessions", response_model=AuthSessionResponse)
def start_session(
    body: StartAuthSessionRequest,
    auth: AuthService = Depends(get_auth_service),
    sessions: AuthSessionStore = Depends(get_auth_sessions),
) -> AuthSessionResponse:
    definition = auth.get_provider(body.provider)
    flow = FlowType(body.flow) if body.flow else definition.flow
    session = sessions.create(
        provider=body.provider,
        profile=auth.identity,
        connection_name=body.connection,
        flow_type=flow.value,
    )
    session.payload["force"] = body.force
    if body.scopes is not None:
        session.payload["requested_scopes"] = body.scopes
    if body.base_url is not None:
        session.payload["base_url"] = body.base_url

    if not body.force:
        try:
            existing = auth.get_connection(body.provider, body.connection)
            if auth._connection_is_valid(existing) and auth._requested_context_matches(
                existing,
                scopes=body.scopes,
                base_url=body.base_url,
            ):
                session.state = AuthSessionStatus.COMPLETED
                session.status_message = "Already connected"
                return _session_response(session)
        except Exception:
            pass

    fields = _required_input_fields(auth, session, flow)
    if fields:
        session.state = AuthSessionStatus.WAITING_FOR_USER
        session.payload["input_fields"] = [_field_to_payload(field) for field in fields]
        return _session_response(session)

    _begin_oauth_or_device(auth, sessions, session)
    return _session_response(session)


@router.get("/sessions/{session_id}", response_model=AuthSessionResponse)
def get_session(
    session_id: str,
    sessions: AuthSessionStore = Depends(get_auth_sessions),
) -> AuthSessionResponse:
    return _session_response(sessions.get(session_id))


@router.post("/sessions/{session_id}/resume", response_model=AuthSessionResponse)
def resume_session(
    session_id: str,
    body: ResumeAuthSessionRequest,
    auth: AuthService = Depends(get_auth_service),
    sessions: AuthSessionStore = Depends(get_auth_sessions),
) -> AuthSessionResponse:
    session = sessions.get(session_id)
    try:
        record = auth.resume_login_flow(session, body.data)
        if record is None:
            session.state = AuthSessionStatus.WAITING_FOR_USER
        else:
            session.state = AuthSessionStatus.COMPLETED
            session.status_message = "Login successful"
    except Exception as exc:
        session.state = AuthSessionStatus.FAILED
        session.error_message = str(exc)
        raise
    return _session_response(session)


@router.get("/callback/oauth", response_class=HTMLResponse)
def oauth_callback(
    request: Request,
    auth: AuthService = Depends(get_auth_service),
    sessions: AuthSessionStore = Depends(get_auth_sessions),
) -> HTMLResponse:
    state = request.query_params.get("state")
    if not state:
        return HTMLResponse(_message_page("Authentication failed", "Missing OAuth state."), status_code=400)
    try:
        session = sessions.get_by_oauth_state(state)
    except KeyError:
        return HTMLResponse(
            _message_page("Authentication session expired", "Please run authsome login again."),
            status_code=400,
        )
    callback_data = dict(request.query_params)
    try:
        auth.resume_login_flow(session, callback_data)
        session.state = AuthSessionStatus.COMPLETED
        session.status_message = "Login successful"
    except Exception as exc:
        session.state = AuthSessionStatus.FAILED
        session.error_message = str(exc)
        return HTMLResponse(_message_page("Authentication failed", str(exc)), status_code=400)
    return HTMLResponse(_message_page("Authentication successful", "You can close this window."))


@router.get("/sessions/{session_id}/input", response_class=HTMLResponse)
def input_page(
    session_id: str,
    auth: AuthService = Depends(get_auth_service),
    sessions: AuthSessionStore = Depends(get_auth_sessions),
) -> HTMLResponse:
    try:
        session = sessions.get(session_id)
    except KeyError:
        return HTMLResponse(
            _message_page("Authentication session expired", "Please run authsome login again."),
            status_code=404,
        )
    definition = auth.get_provider(session.provider)
    fields = session.payload.get("input_fields", [])
    return HTMLResponse(_input_page(session, definition.display_name, definition.docs, fields))


@router.post("/sessions/{session_id}/input")
async def submit_input(
    session_id: str,
    request: Request,
    auth: AuthService = Depends(get_auth_service),
    sessions: AuthSessionStore = Depends(get_auth_sessions),
):
    session = sessions.get(session_id)
    form = await request.form()
    inputs = {key: str(value) for key, value in form.items()}

    flow = FlowType(session.flow_type)
    if flow == FlowType.API_KEY:
        auth.login(
            session.provider,
            session.connection_name,
            force=bool(session.payload.get("force", False)),
            input_provider=MockInputProvider(inputs),
        )
        session.state = AuthSessionStatus.COMPLETED
        session.status_message = "Login successful"
        return HTMLResponse(_message_page("Authentication successful", "You can close this window."))

    _save_oauth_setup_inputs(auth, session, inputs)
    _begin_oauth_or_device(auth, sessions, session)
    auth_url = session.payload.get("auth_url")
    if auth_url:
        return RedirectResponse(str(auth_url), status_code=303)
    return HTMLResponse(_message_page("Authentication started", "Return to your terminal to continue."))


def _required_input_fields(auth: AuthService, session: AuthSession, flow: FlowType) -> list[InputField]:
    definition = auth.get_provider(session.provider)
    client_record = auth._get_provider_client_credentials(session.provider)
    fields: list[InputField] = []

    if flow == FlowType.API_KEY:
        api_key_field = InputField(name="api_key", label="API Key", secret=True)
        if definition.api_key and definition.api_key.key_pattern:
            api_key_field.pattern = definition.api_key.key_pattern
            api_key_field.pattern_hint = definition.api_key.key_pattern_hint
        return [api_key_field]

    if definition.oauth and definition.oauth.base_url and not (client_record and client_record.base_url):
        fields.append(InputField(name="base_url", label="Base URL", secret=False, default=definition.oauth.base_url))
        fields.append(
            InputField(name="host_url", label="API Host URL", secret=False, default=definition.host_url or "")
        )

    if flow == FlowType.PKCE and not (client_record and client_record.client_id):
        fields.append(InputField(name="client_id", label="Client ID", secret=False))
        fields.append(InputField(name="client_secret", label="Client Secret", secret=True, default=""))
    elif flow == FlowType.DEVICE_CODE and not (client_record and client_record.client_id):
        fields.append(InputField(name="client_id", label="Client ID", secret=False, default=""))
        fields.append(InputField(name="client_secret", label="Client Secret", secret=True, default=""))

    requested_scopes = session.payload.get("requested_scopes")
    persisted_scopes = client_record.scopes if client_record else None
    needs_scope_input = (
        flow in (FlowType.PKCE, FlowType.DEVICE_CODE, FlowType.DCR_PKCE)
        and requested_scopes is None
        and persisted_scopes is None
    )
    if needs_scope_input:
        default_scopes = ",".join(definition.oauth.scopes) if definition.oauth and definition.oauth.scopes else ""
        fields.append(InputField(name="scopes", label="Scopes", secret=False, default=default_scopes))

    return fields


def _save_oauth_setup_inputs(auth: AuthService, session: AuthSession, inputs: dict[str, str]) -> None:
    record = auth._get_provider_client_credentials(session.provider)
    if record is None:
        record = ProviderClientRecord(profile=auth.identity, provider=session.provider)
    if inputs.get("base_url"):
        record.base_url = inputs["base_url"]
        session.payload["base_url"] = inputs["base_url"]
    if inputs.get("host_url"):
        record.host_url = inputs["host_url"]
    if inputs.get("client_id"):
        record.client_id = inputs["client_id"]
    if inputs.get("client_secret"):
        record.client_secret = inputs["client_secret"]
    if "scopes" in inputs:
        scopes_input = inputs["scopes"].strip()
        record.scopes = [scope.strip() for scope in scopes_input.split(",") if scope.strip()] if scopes_input else []
    auth._save_provider_client_credentials(record)


def _begin_oauth_or_device(auth: AuthService, sessions: AuthSessionStore, session: AuthSession) -> None:
    scopes = session.payload.get("requested_scopes")
    flow = FlowType(session.flow_type)
    if flow in (FlowType.PKCE, FlowType.DCR_PKCE):
        session.payload["callback_url_override"] = OAUTH_CALLBACK_URL
    auth.begin_login_flow(
        session=session,
        scopes=scopes,
        flow_override=flow,
        force=bool(session.payload.get("force", False)),
        base_url=session.payload.get("base_url"),
    )
    if flow == FlowType.DEVICE_CODE and "expires_in" in session.payload:
        try:
            session.expires_at = utc_now() + timedelta(seconds=int(session.payload["expires_in"]))
        except ValueError:
            pass
    sessions.index_oauth_state(session)


def _session_response(session: AuthSession) -> AuthSessionResponse:
    action: OpenUrlAction | DeviceCodeAction | NoneAction = NoneAction()
    input_fields = session.payload.get("input_fields")
    if input_fields and session.state != AuthSessionStatus.COMPLETED:
        action = OpenUrlAction(type="open_url", url=f"{LOCAL_BASE_URL}/auth/sessions/{session.session_id}/input")
    elif session.payload.get("auth_url"):
        action = OpenUrlAction(type="open_url", url=str(session.payload["auth_url"]))
    elif session.payload.get("verification_uri") and session.payload.get("user_code"):
        action = DeviceCodeAction(
            type="device_code",
            verification_uri=str(session.payload["verification_uri"]),
            verification_uri_complete=session.payload.get("verification_uri_complete"),
            user_code=str(session.payload["user_code"]),
            interval=int(session.payload.get("internal_interval", 5)),
        )
    return AuthSessionResponse(
        id=session.session_id,
        provider=session.provider,
        connection=session.connection_name,
        status=str(session.state),
        message=session.status_message,
        error=session.error_message,
        created_at=session.created_at,
        expires_at=session.expires_at,
        next_action=action,
    )


def _field_to_payload(field: InputField) -> dict[str, Any]:
    return field.model_dump(mode="json", exclude_none=True)


def _input_page(session: AuthSession, display_name: str, docs_url: str | None, fields: list[dict[str, Any]]) -> str:
    required_rows = []
    optional_rows = []
    for field in fields:
        row = _field_row(field)
        if field.get("default") is None:
            required_rows.append(row)
        else:
            optional_rows.append(row)
    docs = (
        f'<p><a href="{html.escape(docs_url)}" target="_blank" rel="noreferrer">Provider documentation</a></p>'
        if docs_url
        else ""
    )
    optional = ""
    if optional_rows:
        optional = f"<details><summary>Advanced options</summary>{''.join(optional_rows)}</details>"
    return f"""<!doctype html>
<html>
  <head><meta charset="utf-8"><title>Authsome - {html.escape(display_name)}</title></head>
  <body>
    <main>
      <h1>{html.escape(display_name)}</h1>
      {docs}
      <form method="post" action="/auth/sessions/{html.escape(session.session_id)}/input">
        {''.join(required_rows)}
        {optional}
        <button type="submit">Continue</button>
      </form>
    </main>
  </body>
</html>"""


def _field_row(field: dict[str, Any]) -> str:
    name = html.escape(str(field["name"]))
    label = html.escape(str(field["label"]))
    input_type = "password" if field.get("secret", True) else "text"
    value = html.escape(str(field.get("default") or ""))
    required = " required" if field.get("default") is None else ""
    pattern = f' pattern="{html.escape(str(field["pattern"]))}"' if field.get("pattern") else ""
    hint = f"<small>{html.escape(str(field['pattern_hint']))}</small>" if field.get("pattern_hint") else ""
    return (
        f"<label>{label}<br>"
        f'<input type="{input_type}" name="{name}" value="{value}"{required}{pattern}>'
        f"</label>{hint}<br><br>"
    )


def _message_page(title: str, message: str) -> str:
    return f"""<!doctype html>
<html>
  <head><meta charset="utf-8"><title>{html.escape(title)}</title></head>
  <body><main><h1>{html.escape(title)}</h1><p>{html.escape(message)}</p></main></body>
</html>"""
