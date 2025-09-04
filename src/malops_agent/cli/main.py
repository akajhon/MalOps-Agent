
import argparse, json
from ..agent.parallel_graph import run_parallel

def main():
    p=argparse.ArgumentParser(description="MalOps Agent CLI (Parallel Pipeline)")
    p.add_argument("--file", required=True, help="Caminho do arquivo")
    p.add_argument("--hint", default=None, help="Dica/Contexto opcional")
    p.add_argument("--model", default="gpt-4o-mini", help="Modelo LLM")
    args=p.parse_args()
    res = run_parallel(args.file, hint=args.hint, model=args.model)
    print(json.dumps(res, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()
