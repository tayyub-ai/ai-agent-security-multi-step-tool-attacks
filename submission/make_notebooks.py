import json, sys
attack=open("attack.py").read()
def build(mode, path):
    src=attack.replace('MODE = "public"', f'MODE = "{mode}"')
    cell1=("# === Cell 1: write attack.py ("+mode+" slot) ===\n"
           "attack_src = r'''"+src+"'''\n"
           "with open('/kaggle/working/attack.py','w') as f: f.write(attack_src)\n"
           "print('attack.py ("+mode+") written:', len(attack_src))\n")
    cell2=("import os\n"
           "if not os.getenv('KAGGLE_IS_COMPETITION_RERUN'):\n"
           "    os.environ['AICOMP_MODEL_NAMES'] = 'deterministic'\n\n"
           "from kaggle_evaluation.jed_attack_134815.jed_attack_inference_server import JEDAttackInferenceServer\n"
           "JEDAttackInferenceServer().run()\n")
    nb={"cells":[
      {"cell_type":"markdown","metadata":{},"source":[f"# AI Agent Security — v7 diverse portfolio ({mode} slot)\n"]},
      {"cell_type":"code","execution_count":None,"metadata":{},"outputs":[],"source":cell1.splitlines(keepends=True)},
      {"cell_type":"code","execution_count":None,"metadata":{},"outputs":[],"source":cell2.splitlines(keepends=True)}],
      "metadata":{"kernelspec":{"display_name":"Python 3","language":"python","name":"python3"},"language_info":{"name":"python","version":"3.11"}},
      "nbformat":4,"nbformat_minor":5}
    json.dump(nb,open(path,"w"),indent=1); print("wrote",path)
build("public","aisec_slot1_public.ipynb")
build("private","aisec_slot2_private.ipynb")
