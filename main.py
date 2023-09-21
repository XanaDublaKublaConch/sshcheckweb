from typing import Annotated
from fastapi import FastAPI, Request, Form
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import JSONResponse
from paramiko.ssh_exception import SSHException
from yaml import safe_load
from sshcheck import CheckedServer
from sshcheck.exceptions import InvalidTargetException


app = FastAPI()
templates = Jinja2Templates(directory='templates')

# Load the policy
with open('policy.yml', 'r') as policy_file:
    ssh_policy = safe_load(policy_file)


@app.get('/', tags=['get', 'form'])
async def root(request: Request):
    message = "Enter an IP to check."
    return templates.TemplateResponse(
        'form.html',
        context={
            'request': request,
            'port': 22,
            'message': message
        }
    )


@app.get('/host/{host}', response_class=JSONResponse, tags=['json', 'get'])
def get_json_result(host: str, port: int = 22):
    try:
        svr = CheckedServer(hostname=host, port=port, policy=ssh_policy)
    except InvalidTargetException as e:
        response = {'error': e}
        return response
    try:
        svr.check_ssh()
    except SSHException as e:
        response = {'error': e}
        return response

    return {
        'hostname': svr.hostname,
        'ip_address': svr.ip_address,
        'port': svr.port,
        'server_host_key_type': svr.host_key_type,
        'server_host_key_status': svr.host_key_status.name.lower(),
        'kex': svr.kex,
        'hka': svr.hka,
        'ciphers': svr.ciphers,
        'mac': svr.mac,
        'compress': svr.compress,
        'lang_list': svr.lang_list,
    }


@app.post('/', tags=['post', 'form'])
async def form_post(request: Request, host: Annotated[str, Form()], port: Annotated[int, Form()]):
    try:
        svr = CheckedServer(hostname=host, port=port, policy=ssh_policy)
    except InvalidTargetException as e:
        return templates.TemplateResponse(
            'form.html',
            context={
                'host': host,
                'port': port,
                'request': request,
                'message': e
            }
        )
    try:
        svr.check_ssh()
    except SSHException as e:
        return templates.TemplateResponse(
            'form.html',
            context={
                'host': host,
                'port': port,
                'request': request,
                'message': e
            }
        )
    return templates.TemplateResponse(
        'form.html',
        context={
            'host': host,
            'port': port,
            'request': request,
            'svr': svr
        }
    )

app.mount('/', StaticFiles(directory="static"), name="static")
