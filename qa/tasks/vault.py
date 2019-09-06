"""
Deploy and configure Vault for Teuthology
"""

import argparse
import contextlib
import logging

import httplib
import json
import urlparse

from teuthology import misc as teuthology
from teuthology import contextutil
from teuthology.orchestra import run
from teuthology.exceptions import ConfigError


log = logging.getLogger(__name__)


@contextlib.contextmanager
def download(ctx, config):
    """
    Download Vault Release from Hashicopr website.
    Remove downloaded file upon exit.
    """
    assert isinstance(config, dict)
    log.info('Downloading vault...')
    testdir = teuthology.get_testdir(ctx)

    for (client, cconf) in config.items():
        vault_version = cconf.get('version', '1.2.2')

        ctx.cluster.only(client).run(
            args=['mkdir', '-p', '{tdir}/vault'.format(tdir=testdir)])

        cmd = [
            'curl', '-L',
            'https://releases.hashicorp.com/vault/{version}/vault_{version}_linux_amd64.zip'.format(version=vault_version), '-o',
            '{tdir}/vault_{version}.zip'.format(tdir=testdir, version=vault_version)
        ]
        ctx.cluster.only(client).run(args=cmd)

        log.info('Extracting vault...')
        cmd = ['unzip', '{tdir}/vault_{version}.zip'.format(tdir=testdir, version=vault_version), '-d','./vault']
        ctx.cluster.only(client).run(args=cmd)

    try:
        yield
    finally:
        log.info('Removing vault...')
        testdir = teuthology.get_testdir(ctx)
        for client in config:
            ctx.cluster.only(client).run(
                args=[
                    'rm',
                    '-rf',
                    '{tdir}/vault'.format(tdir=testdir),
                    ],
                )


def get_vault_dir(ctx):
    return '{tdir}/vault'.format(tdir=teuthology.get_testdir(ctx))


@contextlib.contextmanager
def run_vault(ctx, config):
    assert isinstance(config, dict)
    log.info('Running vault...')

    for (client, cconf) in config.items():
        (remote,) = ctx.cluster.only(client).remotes.iterkeys()
        cluster_name, _, client_id = teuthology.split_role(client)

        v_params = [
            '-dev',
            '-dev-listen-address={}'.format(cconf.get("listen_address", "localhost:8200")),
            '-dev-no-store-token',
            '-dev-root-token-id={}'.format(cconf.get('root_token', 'root'))
        ]

        cmd = 'cd ' + "{}/vault/".format(get_vault_dir(ctx)) + ' && ' + "./vault server {} &".format(" ".join(v_params))

        ctx.daemons.add_daemon(
            remote, 'vault', client_id,
            cluster=cluster_name,
            args=['bash', '-c', cmd],
            logger=log.getChild(client),
            stdin=run.PIPE,
            cwd=get_vault_dir(ctx),
            wait=False,
            check_status=False,
        )

    try:
        yield
    finally:
        log.info('Stopping Vault instance')
        ctx.daemons.get_daemon('vault', client_id,
                               cluster_name).stop()


@contextlib.contextmanager
def setup_vault(ctx, config):
    """
    Mount simple kv Secret Engine
    """
    data = {
        "type": "kv",
        "options": {
            "version": "1"
        }
    }

    (cclient, cconfig) = config.items()[0]

    log.info('Mount kv secret engine')

    send_req(cconfig, '/v1/sys/mounts/kv', json.dumps(data))

    try:
        yield
    finally:
        pass


def send_req(cconfig, path, body, method='POST'):
    base_url = cconfig.get('listen_address', 'localhost:8200')
    if not base_url.startswith('http'):
        # making sure urlparse can parse the url
        base_url = "http://{}".format(base_url)
    parsed_url = urlparse(base_url)
    host, port = parsed_url.hostname, parsed_url.port
    req = httplib.HTTPConnection(host, port, timeout=30)
    headers = {'X-Vault-Token': cconfig.get('root_token', 'atoken')}
    req.request(method, path, headers=headers, body=body)
    resp = req.getresponse()
    if not (resp.status >= 200 and
            resp.status < 300):
        raise Exception("Error Contacting Vault Server")
    return resp


@contextlib.contextmanager
def create_secrets(ctx, config):
    (cclient, cconfig) = config.items()[0]
    secrets = cconfig.get('secrets')
    if secrets is None:
        raise ConfigError("No secrets specified, please specify some.")

    for secret in secrets:
        try:
            data = {
                "key": secret['secret']
            }
        except KeyError:
            raise ConfigError('vault.secrets must have "secret" field')
    try:
        path = secret['path']
    except KeyError:
        raise ConfigError('vault.secrets must have "path" field')

    send_req(cconfig, '/v1/{}'.format(path), json.dumps(data))

    log.info("secrets created")
    try:
        yield
    except:
        pass


@contextlib.contextmanager
def task(ctx, config):
    """
    Deploy and configure Vault

    Example of configuration:

    tasks:
      - local_cluster:
          cluster_path: /home/andrea/ceph-1/build
      - local_rgw:
      - tox: [ client.0 ]
      - vault:
          client.0:
            version: 1.2.2
            root_token: test_root_token
            listen_address: localhost:8200
            secrets:
              - path: kv/teuthology/test-1
                secret: a2V5MS5GcWVxKzhzTGNLaGtzQkg5NGVpb1FKcFpGb2c=
    """
    assert config is None or isinstance(config, list)
    all_clients = ['client.{id}'.format(id=id_)
                   for id_ in teuthology.all_roles_of_type(ctx.cluster, 'client')]
    if config is None:
        config = all_clients
    if isinstance(config, list):
        config = dict.fromkeys(config)

    overrides = ctx.config.get('overrides', {})
    # merge each client section, not the top level.
    for client in config.iterkeys():
        if not config[client]:
            config[client] = {}
        teuthology.deep_merge(config[client], overrides.get('vault', {}))

    log.debug('Vault config is %s', config)

    ctx.vault = argparse.Namespace()

    with contextutil.nested(
        lambda: download(ctx=ctx, config=config),
        lambda: run_vault(ctx=ctx, config=config),
        lambda: setup_vault(ctx=ctx, config=config),
        lambda: create_secrets(ctx=ctx, config=config)
        ):
        yield



