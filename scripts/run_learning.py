#!/usr/bin/env python3
import os
import sys
import json
import time
import uuid
import shutil
import psutil
from datetime import datetime
from typing import Optional, Dict, Any, List
from dotenv import load_dotenv

from pydantic import BaseModel, Field
from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.text import Text

# Ensure application modules can be discovered from scripts directory
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.graph.orchestrator import soc_graph
from app.core.state import IncidentState

# Optional cloud storage client
try:
    from supabase import create_client, Client
    SUPABASE_AVAILABLE = True
except ImportError:
    SUPABASE_AVAILABLE = False

load_dotenv()

# ==========================================
# 1. CONSTANTS & PATHS
# ==========================================

DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data"))
CURRICULUM_FILE = os.path.join(DATA_DIR, "curriculum.json")
DPO_FILE = os.path.join(DATA_DIR, "dpo_dataset", "preferences.jsonl")
RUNS_DIR = os.path.join(DATA_DIR, "training_runs")

BACKUP_INTERVAL_SECONDS = 3600  # Trigger Supabase backup every 60 minutes
THROTTLE_CPU_PERCENT = 85.0
THROTTLE_RAM_PERCENT = 90.0
THROTTLE_TEMP_C = 80.0
COOLING_CYCLE_SECONDS = 30

console = Console()

# ==========================================
# 2. FILE SYSTEM & CLOUD STORAGE SYNC
# ==========================================

def setup_directories() -> None:
    os.makedirs(os.path.dirname(DPO_FILE), exist_ok=True)
    os.makedirs(RUNS_DIR, exist_ok=True)

def load_curriculum() -> List[Dict[str, str]]:
    if not os.path.exists(CURRICULUM_FILE):
        console.log(f"[bold red][!] Critical Error: Curriculum file not found at {CURRICULUM_FILE}[/bold red]")
        sys.exit(1)
    try:
        with open(CURRICULUM_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            if not isinstance(data, list):
                raise ValueError("Curriculum must be a JSON array of objects.")
            return data
    except Exception as e:
        console.log(f"[bold red][!] Failed to parse curriculum JSON: {e}[/bold red]")
        sys.exit(1)

def backup_to_supabase() -> None:
    if not SUPABASE_AVAILABLE:
        return
    supabase_url = os.environ.get("SUPABASE_URL")
    supabase_key = os.environ.get("SUPABASE_SERVICE_KEY")
    if not supabase_url or not supabase_key:
        return

    try:
        supabase: Client = create_client(supabase_url, supabase_key)
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        zip_filename = f"zephyr_logs_{timestamp}"
        archive_path = os.path.join(DATA_DIR, zip_filename)

        shutil.make_archive(archive_path, 'zip', DATA_DIR)
        full_zip_path = f"{archive_path}.zip"

        with open(full_zip_path, "rb") as f:
            supabase.storage.from_("training_logs").upload(
                path=f"{zip_filename}.zip",
                file=f,
                file_options={"content-type": "application/zip"}
            )
        if os.path.exists(full_zip_path):
            os.remove(full_zip_path)
    except Exception as e:
        console.log(f"[bold yellow][!] Autonomous cloud backup skipped: {str(e)}[/bold yellow]")

# ==========================================
# 3. TELEMETRY SERIALIZATION & HARVESTING
# ==========================================

def clean_state_for_json(raw_state: Dict[str, Any]) -> Dict[str, Any]:
    serialized = {}
    for key, value in raw_state.items():
        if key == "messages" and isinstance(value, list):
            serialized[key] = [
                {"type": getattr(msg, "type", "message"), "content": getattr(msg, "content", str(msg))}
                for msg in value
            ]
        elif isinstance(value, (str, int, float, bool, list, dict)) or value is None:
            serialized[key] = value
        else:
            serialized[key] = str(value)
    return serialized

def log_dpo_preference(final_state: Dict[str, Any]) -> None:
    prompt_str = (
        f"Alert Signature: {final_state.get('alert_signature', '')}\n"
        f"Source IP: {final_state.get('source_ip', '')}\n"
        f"Target IP: {final_state.get('target_ip', '')}\n"
        f"Assessment Outcome: {final_state.get('assessment_outcome', '')}"
    )
    rejected_str = (
        f"Action: BLOCK_SOURCE\n"
        f"Target: {final_state.get('source_ip', '')}\n"
        f"Failure Context: {final_state.get('reviewer_feedback', 'Failed blast-radius simulation')}"
    )
    chosen_str = (
        f"Action: {final_state.get('proposed_action', 'ISOLATE_ASSET')}\n"
        f"Target: {final_state.get('proposed_target', '')}\n"
        f"Evolved Rule: {final_state.get('learned_rule', '')}\n"
        f"Justification: {final_state.get('action_justification', '')}"
    )
    dpo_entry = {
        "prompt": prompt_str,
        "rejected": rejected_str,
        "chosen": chosen_str,
        "metadata": {
            "incident_id": final_state.get("incident_id"),
            "timestamp": datetime.utcnow().isoformat(),
            "simulated_blast_radius": final_state.get("simulated_blast_radius", "")
        }
    }
    with open(DPO_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(dpo_entry) + "\n")

def save_run_telemetry(incident_id: str, raw_state: Dict[str, Any]) -> None:
    incident_folder = os.path.join(RUNS_DIR, incident_id)
    os.makedirs(incident_folder, exist_ok=True)
    telemetry_file = os.path.join(incident_folder, "telemetry.json")

    cleaned_data = clean_state_for_json(raw_state)
    with open(telemetry_file, "w", encoding="utf-8") as f:
        json.dump(cleaned_data, f, indent=4)

# ==========================================
# 4. HARDWARE MONITORING & COOLING
# ==========================================

def get_system_temp() -> float:
    try:
        temps = psutil.sensors_temperatures()
        if not temps:
            return 0.0
        core_readings = [entry.current for entry in list(temps.values())[0]]
        return sum(core_readings) / len(core_readings) if core_readings else 0.0
    except (AttributeError, KeyError, IndexError):
        return 0.0

def check_hardware_limits(run_idx: int) -> bool:
    cpu_usage = psutil.cpu_percent(interval=0.2)
    ram_usage = psutil.virtual_memory().percent
    temp_c = get_system_temp()

    is_overheated = temp_c > THROTTLE_TEMP_C and temp_c != 0.0
    is_overloaded = cpu_usage > THROTTLE_CPU_PERCENT or ram_usage > THROTTLE_RAM_PERCENT

    if is_overheated or is_overloaded:
        console.log(f"[bold red][!] RUN {run_idx}: THROTTLE ACTIVATED.[/bold red] CPU: {cpu_usage}% | RAM: {ram_usage}% | Temp: {temp_c}°C")
        time.sleep(COOLING_CYCLE_SECONDS)
        return True
    return False

# ==========================================
# 5. DASHBOARD INTERFACE
# ==========================================

def generate_dashboard(run_history: List[Dict[str, Any]], dpo_total: int, status_line: str, total_runs: int) -> Layout:
    layout = Layout()
    layout.split_column(Layout(name="header", size=3), Layout(name="body"), Layout(name="footer", size=3))

    cpu_usage = psutil.cpu_percent()
    ram_usage = psutil.virtual_memory().percent
    temp_c = get_system_temp()
    
    header_str = f"ZEPHYR GYM | CPU: {cpu_usage}% | RAM: {ram_usage}% | TEMP: {temp_c}°C | DPO RECORDS: {dpo_total} | COMPLETED: {len(run_history)}/{total_runs}"
    layout["header"].update(Panel(Text(header_str, style="bold green"), title="COMPUTE TELEMETRY"))

    table = Table(show_header=True, header_style="bold cyan", expand=True)
    table.add_column("Incident ID", width=16)
    table.add_column("Alert Signature", ratio=3)
    table.add_column("Reviewer Gate", width=14)
    table.add_column("RART Mutated", width=14)
    table.add_column("Action Committed", ratio=2)

    for item in run_history[-12:]:
        rev_style = "bold green" if item["reviewer"] == "APPROVE" else "bold red"
        rart_style = "[bold yellow]TRUE[/bold yellow]" if item["rart"] else "[dim]FALSE[/dim]"
        table.add_row(item["id"], item["signature"][:38], f"[{rev_style}]{item['reviewer']}[/]", rart_style, item["action"])

    layout["body"].update(Panel(table, title="CURRICULUM MCTS ROLLOUT PIPELINE"))
    layout["footer"].update(Panel(f"[bold magenta]{status_line}[/bold magenta]", title="ACTIVE STATE"))
    return layout

# ==========================================
# 6. MAIN GYM EXECUTION ENGINE
# ==========================================

def main() -> None:
    setup_directories()
    console.clear()
    
    curriculum = load_curriculum()
    total_runs = len(curriculum)
    run_history: List[Dict[str, Any]] = []
    dpo_count = 0
    last_backup_timestamp = time.time()

    with Live(generate_dashboard([], 0, "Initializing Curriculum Engine...", total_runs), refresh_per_second=4, screen=True) as live:
        for idx, scenario in enumerate(curriculum, start=1):
            incident_id = scenario.get("incident_id", f"INC-GYM-{uuid.uuid4().hex[:6].upper()}")
            signature = scenario.get("alert_signature", "UNKNOWN_ALERT")
            
            if check_hardware_limits(idx):
                live.update(generate_dashboard(run_history, dpo_count, f"RUN {idx}: Cooling pause engaged...", total_runs))
                time.sleep(COOLING_CYCLE_SECONDS)

            live.update(generate_dashboard(run_history, dpo_count, f"RUN {idx}: Ingesting {incident_id}...", total_runs))

            initial_state = IncidentState(
                incident_id=incident_id,
                alert_signature=signature,
                source_ip=scenario.get("source_ip", "0.0.0.0"),
                target_ip=scenario.get("target_ip", "0.0.0.0")
            )

            try:
                raw_output = soc_graph.invoke(initial_state)
                final_state = raw_output if isinstance(raw_output, dict) else raw_output.model_dump()

                save_run_telemetry(incident_id, final_state)

                learned_rule = final_state.get("learned_rule")
                rart_active = bool(learned_rule and str(learned_rule).strip() != "")

                if rart_active:
                    log_dpo_preference(final_state)
                    dpo_count += 1

                run_history.append({
                    "id": incident_id,
                    "signature": signature,
                    "reviewer": final_state.get("reviewer_decision", "UNKNOWN"),
                    "rart": rart_active,
                    "action": f"{final_state.get('proposed_action', 'NONE')} -> {final_state.get('proposed_target', '')}"
                })

            except Exception as ex:
                run_history.append({
                    "id": incident_id,
                    "signature": signature,
                    "reviewer": "ERROR",
                    "rart": False,
                    "action": f"FAILED: {str(ex)[:20]}"
                })

            current_timestamp = time.time()
            if current_timestamp - last_backup_timestamp > BACKUP_INTERVAL_SECONDS:
                live.update(generate_dashboard(run_history, dpo_count, "Uploading intermediary backup to Supabase...", total_runs))
                backup_to_supabase()
                last_backup_timestamp = time.time()

            live.update(generate_dashboard(run_history, dpo_count, f"RUN {idx} COMPLETED.", total_runs))
            time.sleep(0.2)

    console.print(f"\n[bold green]Curriculum exhausted. {total_runs} runs executed.[/bold green]")
    console.print(f"[bold cyan]Total DPO preference entries logged: {dpo_count}[/bold cyan]")
    console.print("[bold yellow]Uploading final state snapshot to Supabase 'training_logs'...[/bold yellow]")
    backup_to_supabase()
    console.print("[bold green]System offline and ready for evaluation.[/bold green]")

if __name__ == "__main__":
    main()