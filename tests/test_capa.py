#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import argparse

# (opcional) shim para colorama em ambientes onde falta just_fix_windows_console
try:
    import colorama  # type: ignore
    if not hasattr(colorama, "just_fix_windows_console"):
        def _dummy(*a, **kw): return None
        colorama.just_fix_windows_console = _dummy  # type: ignore[attr-defined]
except Exception:
    pass

import capa.main  # flare-capa

def main():
    p = argparse.ArgumentParser(
        description="Execute flare-capa via biblioteca (sem subprocess) e imprima a saída completa."
    )
    p.add_argument("-f", "--file", required=True, help="Arquivo a ser escaneado")
    p.add_argument("-r", "--rules", help="Diretório de regras capa (.yml)")
    p.add_argument("-s", "--sigs", help="Diretório de signatures capa (opcional)")
    p.add_argument("-b", "--backend", help="Backend (auto, vivisect, pefile, ...)")
    p.add_argument("--os", dest="os_hint", help="Hint do SO (auto/windows/linux/macos)")
    # tudo após `--` é repassado direto ao capa (ex.: -v, -vv, --no-default-rules, etc.)
    p.add_argument("passthrough", nargs=argparse.REMAINDER,
                   help="Argumentos extras enviados diretamente ao capa (use `--` antes deles)")
    args = p.parse_args()

    target = os.path.abspath(args.file)
    if not os.path.isfile(target):
        print(f"error: file not found: {target}", file=sys.stderr)
        sys.exit(1)

    # Monta argv exatamente como o CLI receberia (sem filtrar nem interpretar)
    argv = []

    # regras/signatures se fornecidas
    if args.rules:
        argv += ["-r", args.rules]
    if args.sigs:
        argv += ["-s", args.sigs]

    # backend e OS hint se fornecidos
    if args.backend:
        argv += ["-b", args.backend]
    if args.os_hint:
        argv += ["--os", args.os_hint]

    # arquivo alvo
    argv += [target]

    # repasse de flags extras após `--`
    if args.passthrough:
        if args.passthrough[0] == "--":
            argv += args.passthrough[1:]
        else:
            argv += args.passthrough

    # Chama o capa pelo entrypoint da LIB (imprime no stdout/stderr por conta própria)
    try:
        rc = capa.main.main(argv)
        sys.exit(rc if isinstance(rc, int) else 0)
    except SystemExit as e:
        # algumas versões dão SystemExit; preserve o código de saída
        sys.exit(e.code if isinstance(e.code, int) else 0)
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(2)

if __name__ == "__main__":
    main()