#!/usr/bin/env python3
import argparse
import datetime as dt
import difflib
import shutil
from pathlib import Path

BASE = Path(__file__).resolve().parents[2]
DIR = BASE / 'ubuntu-26.04'
BOOT = DIR / 'awx/bootstrap/install-awx.sh'
BOOTREADME = DIR / 'awx/bootstrap/README.md'
README = DIR / 'README.md'
TEST = DIR / 'tests/test_monohost.py'
GRAFANA = DIR / 'templates/grafana/docker-compose.yml.j2'
GROUPVARS = DIR / 'playbooks/group_vars/all.yml'
SAMPLE = DIR / 'examples/variables_host_central.yml.example'
GITIGNORE = BASE / '.gitignore'

OLD_FLAGS = "INSTALL_K3S_EXEC='server --disable traefik --disable servicelb --write-kubeconfig-mode 0600 --secrets-encryption'"
NEW_FLAGS = "INSTALL_K3S_EXEC='server --write-kubeconfig-mode 0600 --secrets-encryption'"


def repl_exact(content, old, new, name):
    if old in content:
        if content.count(old) != 1:
            raise ValueError(f'{name}: patrón ambiguo')
        return content.replace(old, new)
    if new in content:
        return content
    raise ValueError(f'{name}: contenido diferente de la versión auditada; operación cancelada')


def main():
    p = argparse.ArgumentParser()
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument('--check', action='store_true')
    g.add_argument('--apply', action='store_true')
    a = p.parse_args()
    if not all(f.exists() for f in (BOOT, BOOTREADME, README, TEST, GRAFANA, SAMPLE, GITIGNORE)):
        raise SystemExit('Faltan archivos de referencia: comprueba que el ZIP se descomprimió en la raíz del repositorio.')
    updates = {}
    boot = BOOT.read_text(encoding='utf-8')
    updates[BOOT] = repl_exact(boot, OLD_FLAGS, NEW_FLAGS, BOOT.name)
    b = BOOTREADME.read_text(encoding='utf-8')
    b = repl_exact(b,
        'K3s lleva `--disable traefik --disable servicelb --write-kubeconfig-mode 0600 --secrets-encryption`.',
        'En una instalación limpia, K3s mantiene Traefik y ServiceLB integrados, junto con `--write-kubeconfig-mode 0600 --secrets-encryption`. La VM existente conserva su configuración hasta que se migre expresamente.',
        BOOTREADME.name)
    updates[BOOTREADME] = b
    t = TEST.read_text(encoding='utf-8')
    t = repl_exact(t,
        "config = yaml.safe_load((ROOT/'playbooks/group_vars/all.yml').read_text())",
        "assert not (ROOT/'playbooks/group_vars/all.yml').exists()\n    config = yaml.safe_load((ROOT/'examples/variables_host_central.yml.example').read_text())",
        TEST.name)
    updates[TEST] = t
    graf = GRAFANA.read_text(encoding='utf-8')
    lines = graf.splitlines(keepends=True)
    target = [x for x in lines if 'GF_SERVER_ROOT_URL:' in x and 'var_obs_domain' in x]
    if len(target) > 1:
        raise ValueError('Grafana: hay más de una entrada HTTPS inyectada; cancelar')
    if target:
        graf = graf.replace(target[0], '')
    updates[GRAFANA] = graf
    readme = README.read_text(encoding='utf-8')
    readme = repl_exact(readme,
        '**Prueba pendiente:** se han hecho comprobaciones estáticas locales. No hay validación de instalación real en Ubuntu 26.04, ni prueba de versiones AWX/Helm/Wazuh, ni backups y restauración. **No autorizar la entrada en producción hasta completar esas pruebas.**',
        '**Pruebas:** el bootstrap AWX 24.6.1 sobre K3s se reinstaló y arrancó en un laboratorio Ubuntu 26.04 el 18/11/2026, con mitigación específica AppArmor. La instalación limpia con Traefik integrado y los demás Jobs todavía no se ha probado. No autorizar producción hasta validar esa configuración, los servicios, backups y restauración.',
        README.name)
    updates[README] = readme
    gitignore = GITIGNORE.read_text(encoding='utf-8-sig')
    ign_lines = ('/ubuntu-26.04/playbooks/group_vars/all.yml', '/ubuntu-26.04-anterior/', '/ubuntu-26.04/acceso-https/')
    for line in ign_lines:
        if line not in gitignore.splitlines():
            gitignore += '\n' + line
    updates[GITIGNORE] = gitignore + ('\n' if not gitignore.endswith('\n') else '')
    if GROUPVARS.exists():
        raw = GROUPVARS.read_text(encoding='utf-8')
        import re
        names = set(re.findall(r'^([A-Za-z][A-Za-z0-9_]*)\s*:', raw, re.M))
        allowed = set(re.findall(r'^([A-Za-z][A-Za-z0-9_]*)\s*:', SAMPLE.read_text(encoding='utf-8'), re.M)) | {'var_obs_domain'}
        if not names or names - allowed:
            raise ValueError(f'group_vars contiene claves no previstas: {sorted(names - allowed)}. No se borra.')
    changed = [str(f.relative_to(BASE)) for f, content in updates.items() if content != f.read_text(encoding='utf-8-sig' if f == GITIGNORE else 'utf-8')]
    if GROUPVARS.exists():
        changed.append(str(GROUPVARS.relative_to(BASE)) + ' (deja de cargarse; copia local)')
    print('Cambios previstos:' if a.check else 'Cambios aplicados:')
    for c in changed:
        print('  ' + c)
    if not changed:
        print('  ninguno, ya está alineado')
    if a.check:
        return
    backup = Path.home() / 'Downloads' / ('deployment-kits-respaldo-alineacion-' + dt.datetime.now().strftime('%Y%m%d-%H%M%S'))
    backup.mkdir(parents=True, exist_ok=False)
    for f in updates:
        if f.exists():
            dest = backup / f.relative_to(BASE)
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(f, dest)
    if GROUPVARS.exists():
        dest = backup / GROUPVARS.relative_to(BASE)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(GROUPVARS, dest)
    for f, s in updates.items():
        if s != f.read_text(encoding='utf-8-sig' if f == GITIGNORE else 'utf-8'):
            f.write_text(s, encoding='utf-8')
    if GROUPVARS.exists():
        GROUPVARS.unlink()
    print('Respaldo local:', backup)
    print('Importante: no se ha modificado K3s en Ubuntu ni se ha instalado Traefik todavía.')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError) as exc:
        raise SystemExit(f'ERROR: {exc}')
